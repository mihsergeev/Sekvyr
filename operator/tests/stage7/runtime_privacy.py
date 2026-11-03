"""Counts-only scan of retained logs, CR status and Events in six owned namespaces.

The reviewed bounded private-material collector is shared with stage6. This
does not claim coverage of deleted Pods or already rotated historical logs.
"""

import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

from fixture import ROLES, canonical

_path = Path(__file__).resolve().parents[1] / "stage6" / "log_privacy.py"
_spec = importlib.util.spec_from_file_location("sekvyr_stage7_privacy_primitives", _path)
_base = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(_path.parent))
try:
    _spec.loader.exec_module(_base)
finally:
    sys.path.remove(str(_path.parent))
require = _base.require


def _events(cluster, namespace):
    """Bound the kubectl stdout pipe before buffering an EventList."""
    process = subprocess.Popen([str(cluster.kubectl), "--kubeconfig", str(cluster.config),
        "get", "events", "-n", namespace, "-o", "json", "--chunk-size=100", "--request-timeout=20s"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    raw, deadline = bytearray(), time.monotonic() + 25
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ)
            while len(raw) < _base.MAX_LOG:
                remaining = deadline - time.monotonic()
                require(remaining > 0)
                if not selected.select(min(remaining, 1)):
                    continue
                chunk = os.read(process.stdout.fileno(), min(65536, _base.MAX_LOG - len(raw)))
                if not chunk:
                    require(process.wait(timeout=3) == 0)
                    break
                raw.extend(chunk)
        return bytes(raw)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close()


def scan(coordinator, known_memory_secrets=()):
    result = {"logStreams": 0, "statusObjects": 0, "eventObjects": 0, "knownPatterns": 0,
        "secretCount": 0, "canaryCount": 0, "confirmedLeaks": 0, "truncatedStreams": 0,
        "incompleteStreams": 0, "complete": False, "production": False}
    try:
        inventory = _base.collect(coordinator)
        # The signer rollover uses new-key.pem, in addition to legacy *.key
        # and node.pem material already covered by the shared collector.
        pem_bytes = 0
        for path in coordinator.private.rglob("*.pem"):
            if path.name == "node.pem":
                continue
            raw = _base.read_private(path, coordinator.private.resolve())
            pem_bytes += len(raw)
            require(pem_bytes <= _base.MAX_FILE)
            inventory.private(raw)
        require(isinstance(known_memory_secrets, (tuple, list)) and len(known_memory_secrets) <= 128)
        for value in known_memory_secrets:
            require(isinstance(value, (str, bytes)) and 16 <= len(value) <= 16384)
            inventory.add(value)
        result.update(knownPatterns=len(inventory.patterns), secretCount=len(inventory.secrets), canaryCount=len(inventory.canaries))
        namespaces = coordinator.cluster.fixture["namespaces"]
        require(set(namespaces) == set(ROLES) and len(ROLES) == 6 and len(set(namespaces.values())) == 6)
        pins = coordinator.cluster.namespace_pins()
        require(set(pins) == set(namespaces.values()) and all(isinstance(uid, str) and uid for uid in pins.values()))
        for namespace in sorted(pins):
            _base.namespace_guard(coordinator, pins, namespace)
            listed = json.loads(coordinator.cluster.kube("get", "pods", "-n", namespace, "-o", "json").stdout)["items"]
            require(isinstance(listed, list) and len(listed) <= 1024)
            for pod in listed:
                name, uid = pod["metadata"]["name"], pod["metadata"]["uid"]
                require(pod["metadata"].get("namespace") == namespace and name and uid)
                try:
                    available = _base.containers(pod)
                except Exception:
                    result["incompleteStreams"] += 1
                    continue
                for container, previous, status in available:
                    try:
                        _base.namespace_guard(coordinator, pins, namespace)
                        before = _base.pod_get(coordinator, namespace, name, uid)
                        require((container, previous, status) in _base.containers(before))
                        args = ["logs", name, "-n", namespace, "-c", container, "--limit-bytes=" + str(_base.MAX_LOG)]
                        if previous:
                            args.append("--previous")
                        raw = coordinator.cluster.kube(*args).stdout.encode("utf-8")
                        result["logStreams"] += 1
                        if len(raw) >= _base.MAX_LOG:
                            result["truncatedStreams"] += 1
                        elif inventory.matches(raw):
                            result["confirmedLeaks"] += 1
                        after = _base.pod_get(coordinator, namespace, name, uid)
                        require((container, previous, status) in _base.containers(after))
                        _base.namespace_guard(coordinator, pins, namespace)
                    except Exception:
                        result["incompleteStreams"] += 1
            try:
                events_raw = _events(coordinator.cluster, namespace)
                if len(events_raw) >= _base.MAX_LOG:
                    result["truncatedStreams"] += 1
                else:
                    events = json.loads(events_raw)["items"]
                    require(isinstance(events, list) and len(events) <= 4096)
                    for event in events:
                        require(event.get("kind") == "Event" and event["metadata"].get("namespace") == namespace and event["metadata"].get("uid"))
                        result["eventObjects"] += 1
                        if inventory.matches(canonical(event)):
                            result["confirmedLeaks"] += 1
                _base.namespace_guard(coordinator, pins, namespace)
            except Exception:
                result["incompleteStreams"] += 1
        records = [json.loads(path.read_bytes()) for path in coordinator.cluster.pins.glob("*.json")]
        records = [pin for pin in records if pin.get("kind") in ("SekvyrStore", "SekvyrSecret")]
        require(len(records) >= 2 and len({(pin["namespace"], pin["kind"], pin["name"]) for pin in records}) == len(records))
        for pin in records:
            try:
                namespace = pin["namespace"]
                require(namespace in pins)
                _base.namespace_guard(coordinator, pins, namespace)
                value = json.loads(coordinator.cluster.kube("get", pin["kind"], pin["name"], "-n", namespace, "-o", "json").stdout)
                require(value.get("kind") == pin["kind"] and value["metadata"].get("namespace") == namespace and value["metadata"].get("uid") == pin["uid"])
                raw = canonical(value.get("status", {}))
                result["statusObjects"] += 1
                if len(raw) >= _base.MAX_LOG:
                    result["truncatedStreams"] += 1
                elif inventory.matches(raw):
                    result["confirmedLeaks"] += 1
                _base.namespace_guard(coordinator, pins, namespace)
            except Exception:
                result["incompleteStreams"] += 1
        result["complete"] = not result["incompleteStreams"] and not result["truncatedStreams"]
    except Exception:
        result["incompleteStreams"] += 1
    return result
