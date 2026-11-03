"""Read-only reconstruction from explicitly selected durable Helm captures.

No install/upgrade/create/patch, latest-by-time discovery or live-name adoption.
Every live identity must already have a post-create UID and its persisted
absence preflight. Older retained configurations require explicit captures.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

from app_modes import require
from helm_lifecycle import HelmLifecycle, canonical, identity


def _read(path, maximum=4 << 20):
    require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
        and path.stat().st_size <= maximum, "Exact safe Helm receipt file required")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, ValueError):
        raise RuntimeError("Persisted Helm receipt unreadable") from None
    require(raw == canonical(value), "Helm receipt is not the exact canonical saved input")
    return value


def _receipt(cluster, release, namespace, namespace_uid, digest):
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "Exact Helm preflight hash required")
    path = cluster.task / "private" / "helm-preflights" / (digest + ".json")
    value = _read(path)
    require(hashlib.sha256(canonical(value)).hexdigest() == digest and value.get("format") == "sekvyr-stage7-helm-preflight-v1"
        and value.get("action") in ("install", "upgrade") and value.get("release") == release
        and value.get("namespace") == namespace and value.get("namespaceUID") == namespace_uid
        and isinstance(value.get("external"), list) and isinstance(value.get("absent"), list), "Helm preflight identity mismatch")
    return value


def _capture(cluster, release, namespace, namespace_uid, directory, supplied):
    path = Path(supplied).absolute()
    match = re.fullmatch(r"captured-([0-9a-f]{64})\.json", path.name)
    require(path.parent == directory and match is not None, "Caller must select an exact capture in this release directory")
    records = _read(path)
    require(isinstance(records, list) and 1 <= len(records) <= 40 and all(isinstance(item, dict)
        and set(item) == {"manifest", "uid", "data"} and isinstance(item["uid"], str) and item["uid"] for item in records), "Helm capture shape invalid")
    keys = [identity(item["manifest"]) for item in records]
    require(len(keys) == len(set(keys)), "Duplicate identities in selected Helm capture")
    receipt = _receipt(cluster, release, namespace, namespace_uid, match[1])
    require(hashlib.sha256(canonical([item["manifest"] for item in records])).hexdigest() == receipt.get("renderHash"),
        "Helm capture is partial or differs from its reviewed render")
    return records, receipt


def restore_captured(cluster, helm, chart, release, namespace, expected_values, capture_path, older_capture_paths=()):
    require(namespace in cluster.namespaces and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,52}", release), "Explicit owned namespace and release required")
    require(isinstance(expected_values, dict) and isinstance(older_capture_paths, (tuple, list)), "Explicit expected values and older capture paths required")
    directory = cluster.task / "private" / ("helm-lifecycle-" + release)
    require(directory.is_dir() and directory.resolve() == directory and not directory.is_symlink(), "Existing exact release context required")
    namespace_uid = cluster.namespace_pins()[namespace]
    selected, receipt = _capture(cluster, release, namespace, namespace_uid, directory, capture_path)
    require(expected_values.get("installation", {}).get("namespace") == namespace, "Restored Helm values namespace differs")
    values_path = directory / ("values-" + hashlib.sha256(canonical(expected_values)).hexdigest() + ".json")
    require(_read(values_path) == expected_values, "Expected values must already exist as an exact saved input")
    paths = [Path(value).absolute() for value in older_capture_paths]
    require(len(paths) == len(set(paths)) and Path(capture_path).absolute() not in paths, "Older captures must be explicit and distinct")
    older = [_capture(cluster, release, namespace, namespace_uid, directory, value) for value in paths]
    external = receipt["external"]
    require(all(isinstance(pin, dict) and set(pin) == {"kind", "name", "uid"} and isinstance(pin["uid"], str) and pin["uid"] for pin in external)
        and len({(pin["kind"], pin["name"]) for pin in external}) == len(external), "External Helm capture pins invalid")
    external_set = {canonical(value) for value in external}
    require(all({canonical(value) for value in previous["external"]}.issubset(external_set) for records, previous in older),
        "Restoration cannot drop historical external UID pins")
    helper = HelmLifecycle(cluster, helm, chart, release, namespace, external)
    require(helper.owned.namespace_uid == namespace_uid, "Namespace UID changed during Helm restoration")
    rendered, actual_values_path = helper.render(expected_values)
    require(actual_values_path == values_path and [value["manifest"] for value in selected] == rendered
        and hashlib.sha256(canonical(rendered)).hexdigest() == receipt["renderHash"], "Current chart/values differ from the exact selected capture")

    related_pins = {}
    for path in cluster.pins.glob("*.json"):
        # Only creation receipts of this release can authorize a managed UID.
        pin = _read(path, 1 << 20)
        if pin.get("provenance") != "helm-post-create-read" or pin.get("namespace") not in (namespace, ""):
            continue
        initial_hash = pin.get("preflightHash", "")
        require(re.fullmatch(r"[0-9a-f]{64}", initial_hash) is not None, "Creation preflight hash is not a fixed receipt identity")
        initial = _read(cluster.task / "private" / "helm-preflights" / (initial_hash + ".json"))
        if initial.get("release") != release or initial.get("namespace") != namespace:
            continue
        initial = _receipt(cluster, release, namespace, namespace_uid, pin["preflightHash"])
        key = pin["apiVersion"], pin["kind"], pin["namespace"], pin["name"]
        matches = [entry for entry in initial["absent"] if (entry.get("apiVersion"), entry.get("kind"), entry.get("namespace"), entry.get("name")) == key]
        require(key not in related_pins and len(matches) == 1 and matches[0].get("manifestHash") == pin.get("manifestHash"), "Managed UID lacks one exact creation absence receipt")
        related_pins[key] = pin

    managed, retained = {}, {}
    for item in selected:
        manifest, uid = item["manifest"], item["uid"]
        key = identity(manifest)
        require(key in related_pins and related_pins[key]["uid"] == uid, "Selected resource is not the creation-pinned Helm object")
        require(manifest.get("data") == item["data"], "Captured resource data differs from its manifest")
        current = helper._get(manifest)
        helper._owned(current, uid)
        helper._matches(current, manifest)
        managed[key] = copy.deepcopy(item)
    for records, previous in older:
        for item in records:
            manifest, uid = item["manifest"], item["uid"]
            key = identity(manifest)
            require(key in related_pins and related_pins[key]["uid"] == uid, "Historical capture UID has no creation provenance")
            if key in managed:
                require(managed[key]["uid"] == uid, "Historical managed UID was replaced")
                continue
            require(manifest["kind"] == "ConfigMap" and manifest.get("immutable") is True
                and manifest["metadata"].get("annotations", {}).get("helm.sh/resource-policy") == "keep"
                and manifest.get("data") == item["data"], "Only explicitly kept immutable configuration may be retained")
            require(hashlib.sha256(canonical(manifest)).hexdigest() == related_pins[key]["manifestHash"], "Retained configuration differs from its creation review")
            if key in retained:
                require(retained[key] == item, "Conflicting historical configuration capture")
                continue
            current = helper._get(manifest)
            helper._owned(current, uid)
            helper._matches(current, manifest)
            require(current.get("immutable") is True and current.get("data") == item["data"], "Retained configuration was altered")
            retained[key] = copy.deepcopy(item)
    require(set(related_pins) == set(managed) | set(retained), "Known Helm creation UID lacks an explicitly selected current/retained capture")
    helper.owned.guard()
    helper._external_guard()
    # Publish reconstructed in-memory ownership only after every read-only guard.
    helper.managed, helper.retained = managed, retained
    return helper
