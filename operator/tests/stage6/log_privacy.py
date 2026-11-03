"""Bounded in-memory privacy scan of this disposable fixture only.

No raw log, status, secret, match, path or exception is printed or persisted.
Incomplete inventories, changed Pod/container identities and truncated streams
prevent a complete result; they are never treated as a clean scan.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from application import TARGET
from fixture import ROLES, canonical


MAX_LOG = 2 << 20
MAX_FILE = 16 << 20
MAX_PRIVATE_FILES = 8192
MAX_PRIVATE_BYTES = 128 << 20
MIN_CANARY = 16
PRIVATE_ANCHOR = re.compile(rb"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")
PRIVATE_BLOCK = re.compile(rb"-----BEGIN ([A-Z ]*PRIVATE KEY)-----\r?\n.*?-----END \1-----", re.DOTALL)
JWT = re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,2048}\.[A-Za-z0-9_-]{16,8192}\.[A-Za-z0-9_-]{16,2048}(?![A-Za-z0-9_-])")
CREDENTIAL_FIELDS = {"access_key", "secret_key", "password", "root_key", "access_token", "kubernetes_token",
    "SEKVYR_ADMIN_PASSWORD", "SEKVYR_JWT_SECRET", "SEKVYR_DB_URL"}


def require(condition):
    if not condition:
        raise RuntimeError("Trial privacy scan incomplete")


def unbase64(value):
    require(isinstance(value, (str, bytes)))
    raw = value.encode("ascii") if isinstance(value, str) else value
    require(len(raw) <= MAX_FILE)
    return base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)


class Inventory:
    def __init__(self):
        self.patterns, self.secrets, self.canaries = set(), set(), set()
        self.private_keys, self.read_keys = 0, 0

    def __repr__(self):
        return "<private trial scan patterns [redacted]>"

    def add(self, raw, canary=False):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        require(isinstance(raw, bytes) and len(raw) <= MAX_FILE)
        if len(raw) < MIN_CANARY:
            return
        (self.canaries if canary else self.secrets).add(hashlib.sha256(raw).digest())
        variants = {raw, raw.hex().encode(), base64.b64encode(raw), base64.b64encode(raw).rstrip(b"="),
            base64.urlsafe_b64encode(raw), base64.urlsafe_b64encode(raw).rstrip(b"=")}
        try:
            value = raw.decode("utf-8")
            variants.add(json.dumps(value, ensure_ascii=True)[1:-1].encode())
            variants.add(quote(value, safe="").encode())
        except UnicodeError:
            pass
        self.patterns.update(value for value in variants if len(value) >= MIN_CANARY)
        require(len(self.patterns) <= 100000 and sum(map(len, self.patterns)) <= 32 << 20)

    def private(self, raw):
        blocks = list(PRIVATE_BLOCK.finditer(raw))
        if not blocks:
            # Raw legacy node material is allowed only for exactly 32 bytes.
            if len(raw.strip()) == 32:
                self.add(raw.strip())
            elif b"PUBLIC KEY" not in raw and b"CERTIFICATE" not in raw:
                try:
                    decoded = unbase64(raw.strip())
                except (ValueError, UnicodeError):
                    return
                if len(decoded) == 32:
                    self.add(decoded)
            return
        for match in blocks:
            block = match.group()
            self.add(block)
            # A PEM suffix may contain only its public point. Never classify
            # individual base64 lines as secrets: public certificates could
            # legitimately contain the same point. The full DER stays private.
            body = b"".join(line.strip() for line in block.splitlines() if not line.startswith(b"-----"))
            if b"OPENSSH PRIVATE KEY" not in block:
                self.add(unbase64(body))
            try:
                key = serialization.load_ssh_private_key(block, password=None) if b"OPENSSH PRIVATE KEY" in block else serialization.load_pem_private_key(block, password=None)
            except (ValueError, TypeError):
                raise RuntimeError("Trial privacy scan incomplete") from None
            self.private_keys += 1
            if isinstance(key, ed25519.Ed25519PrivateKey):
                self.add(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                self.add(key.private_numbers().private_value.to_bytes((key.curve.key_size + 7) // 8, "big"))
            self.add(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def walk(self, value, depth=0):
        require(depth <= 64)
        if isinstance(value, list):
            require(len(value) <= 100000)
            for item in value:
                self.walk(item, depth + 1)
        elif isinstance(value, dict):
            require(len(value) <= 100000)
            for key, item in value.items():
                if isinstance(item, str):
                    if key in CREDENTIAL_FIELDS:
                        self.add(item)
                    elif key == "read_key":
                        self.add(item)
                        decoded = unbase64(item)
                        require(len(decoded) == 32)
                        self.add(decoded)
                        self.read_keys += 1
                    elif key in ("generation", "demo_value", "demo"):
                        self.add(item, canary=True)
                    elif key == "value" and ((value.get("name") in ("GENERATION", "DEMO_VALUE"))
                        or ("generation" in value and "envelope" in value and "hash" in value)):
                        self.add(item, canary=True)
                    elif key in ("GENERATION", "DEMO_VALUE"):
                        self.add(unbase64(item), canary=True)
                    elif key.endswith(".key") or key == "node.pem" or key == "client-key-data":
                        try:
                            self.private(unbase64(item))
                        except (ValueError, UnicodeError):
                            require(False)
                self.walk(item, depth + 1)

    def matches(self, raw):
        require(isinstance(raw, bytes) and len(raw) < MAX_LOG)
        if PRIVATE_ANCHOR.search(raw) or any(pattern in raw for pattern in self.patterns):
            return True
        for match in JWT.finditer(raw):
            try:
                header, payload, _ = match.group().split(b".")
                parsed = json.loads(unbase64(header))
                claims = json.loads(unbase64(payload))
                if isinstance(parsed, dict) and isinstance(parsed.get("alg"), str) and isinstance(claims, dict):
                    return True
            except (ValueError, UnicodeError, RuntimeError):
                continue
        return False


def read_private(path, root):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root))
    require(path.stat().st_size <= MAX_FILE)
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE)
    return raw


def collect(coordinator):
    private = coordinator.private
    require(private.is_dir() and not private.is_symlink())
    root = private.resolve()
    task = coordinator.task.resolve()
    require(root.parent == task)
    inventory = Inventory()
    count, size = 0, 0
    found = set()
    for directory, directories, names in os.walk(private, followlinks=False):
        require(all(not (Path(directory) / name).is_symlink() for name in directories))
        for name in names:
            path = Path(directory) / name
            require(not path.is_symlink())
            count += 1
            require(count <= MAX_PRIVATE_FILES)
            if not (name.endswith(".json") or name.endswith(".key") or name == "node.pem"
                or (path.parent == private and name in ("database-password", "fetch-token"))):
                continue
            raw = read_private(path, root)
            size += len(raw)
            require(size <= MAX_PRIVATE_BYTES)
            if path.parent == private:
                found.add(name)
            if name.endswith(".json"):
                inventory.walk(json.loads(raw))
            elif name.endswith(".key") or name == "node.pem":
                inventory.private(raw)
            else:
                inventory.add(raw.strip())
    require({"storage-credentials.json", "database-password", "fetch-token", "panel-access.json", "panel-vault-key.json"} <= found)
    kubeconfig = coordinator.cluster.config
    require(kubeconfig.parent.resolve() == task and kubeconfig.name == "kubeconfig")
    raw = read_private(kubeconfig, task)
    import yaml
    config = yaml.safe_load(raw)
    users = config.get("users", [])
    require(isinstance(users, list) and 0 < len(users) <= 128)
    embedded = 0
    for user in users:
        key = user.get("user", {}).get("client-key-data")
        if key:
            decoded = unbase64(key)
            require(PRIVATE_ANCHOR.search(decoded) is not None)
            inventory.private(decoded)
            embedded += 1
    require(embedded > 0 and inventory.private_keys > 0 and inventory.read_keys > 0)
    target = coordinator.app.get("Secret", TARGET)
    for name in ("GENERATION", "DEMO_VALUE"):
        inventory.add(unbase64(target["data"][name]), canary=True)
    inventory.add("public-trial-initial", canary=True)
    return inventory


def namespace_guard(coordinator, pins, namespace):
    value = json.loads(coordinator.cluster.kube("get", "namespace", namespace, "-o", "json").stdout)
    require(value.get("metadata", {}).get("name") == namespace and value["metadata"].get("uid") == pins[namespace]
        and not value["metadata"].get("deletionTimestamp"))


def pod_get(coordinator, namespace, name, uid):
    value = json.loads(coordinator.cluster.kube("get", "pod", name, "-n", namespace, "-o", "json").stdout)
    require(value.get("kind") == "Pod" and value.get("metadata", {}).get("namespace") == namespace
        and value["metadata"].get("name") == name and value["metadata"].get("uid") == uid)
    return value


def containers(pod):
    result = []
    for spec, status in (("containers", "containerStatuses"), ("initContainers", "initContainerStatuses"),
                         ("ephemeralContainers", "ephemeralContainerStatuses")):
        selected = pod.get("spec", {}).get(spec, [])
        statuses = pod.get("status", {}).get(status, [])
        for container in selected:
            name = container.get("name")
            matches = [item for item in statuses if item.get("name") == name]
            require(isinstance(name, str) and name and len(matches) == 1)
            value = matches[0]
            require(type(value.get("restartCount")) is int and value["restartCount"] >= 0 and value.get("containerID"))
            result.append((name, False, value))
            if value["restartCount"] > 0:
                require(value.get("lastState", {}).get("terminated", {}).get("containerID"))
                result.append((name, True, value))
    require(len({(name, previous) for name, previous, _ in result}) == len(result))
    return result


def scan(coordinator):
    result = {"logStreams": 0, "statusObjects": 0, "knownPatterns": 0, "secretCount": 0, "canaryCount": 0,
        "confirmedLeaks": 0, "truncatedStreams": 0, "incompleteStreams": 0, "complete": False, "production": False}
    try:
        inventory = collect(coordinator)
        result.update(knownPatterns=len(inventory.patterns), secretCount=len(inventory.secrets), canaryCount=len(inventory.canaries))
        namespaces = coordinator.cluster.fixture["namespaces"]
        require(set(namespaces) == set(ROLES) and len(set(namespaces.values())) == 7)
        pins = coordinator.cluster.namespace_pins()
        require(set(pins) == set(namespaces.values()) and all(isinstance(uid, str) and uid for uid in pins.values()))
        for namespace in sorted(pins):
            namespace_guard(coordinator, pins, namespace)
            values = json.loads(coordinator.cluster.kube("get", "pods", "-n", namespace, "-o", "json").stdout)["items"]
            require(isinstance(values, list) and len(values) <= 1024)
            for listed in values:
                name, uid = listed["metadata"]["name"], listed["metadata"]["uid"]
                require(listed["metadata"].get("namespace") == namespace and isinstance(name, str) and name and isinstance(uid, str) and uid)
                try:
                    available = containers(listed)
                except Exception:
                    result["incompleteStreams"] += 1
                    continue
                for container, previous, status in available:
                    try:
                        namespace_guard(coordinator, pins, namespace)
                        before = pod_get(coordinator, namespace, name, uid)
                        require((container, previous, status) in containers(before))
                        args = ["logs", name, "-n", namespace, "-c", container, "--limit-bytes=" + str(MAX_LOG)]
                        if previous:
                            args.append("--previous")
                        response = coordinator.cluster.kube(*args)
                        raw = response.stdout.encode("utf-8")
                        result["logStreams"] += 1
                        if len(raw) >= MAX_LOG:
                            result["truncatedStreams"] += 1
                        elif inventory.matches(raw):
                            result["confirmedLeaks"] += 1
                        after = pod_get(coordinator, namespace, name, uid)
                        require((container, previous, status) in containers(after))
                        namespace_guard(coordinator, pins, namespace)
                    except Exception:
                        result["incompleteStreams"] += 1
            namespace_guard(coordinator, pins, namespace)
        records = [json.loads(path.read_bytes()) for path in coordinator.cluster.pins.glob("*.json")]
        records = [pin for pin in records if pin.get("kind") in ("SekvyrStore", "SekvyrSecret")]
        require(len({(pin["namespace"], pin["kind"], pin["name"]) for pin in records}) == len(records) and len(records) >= 2)
        for pin in records:
            try:
                namespace = pin["namespace"]
                require(namespace in pins)
                namespace_guard(coordinator, pins, namespace)
                value = json.loads(coordinator.cluster.kube("get", pin["kind"], pin["name"], "-n", namespace, "-o", "json").stdout)
                require(value.get("kind") == pin["kind"] and value["metadata"].get("namespace") == namespace
                    and value["metadata"].get("uid") == pin["uid"])
                raw = canonical(value.get("status", {}))
                result["statusObjects"] += 1
                if len(raw) >= MAX_LOG:
                    result["truncatedStreams"] += 1
                elif inventory.matches(raw):
                    result["confirmedLeaks"] += 1
                namespace_guard(coordinator, pins, namespace)
            except Exception:
                result["incompleteStreams"] += 1
        result["complete"] = not result["incompleteStreams"] and not result["truncatedStreams"]
    except Exception:
        result["incompleteStreams"] += 1
    return result
