"""Additive Stage 8 entry; six-namespace resource/UID algorithms unchanged."""

import json
from pathlib import Path
from types import FunctionType, SimpleNamespace
import importlib.util

from app_modes import require
from .profiles import reviewed
from .capability import Capability
import remote_kind_capability as cap

# Explicit file import avoids shadowing the identically named Stage 7 module.
_source = Path(__file__).resolve().parents[1] / "stage7" / "infrastructure.py"
_spec = importlib.util.spec_from_file_location("sekvyr_stage7_fixed_infrastructure", _source)
legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(legacy)

def _prepare_template(task, expected_version):
    task = safe_task(task)
    if (task / "private" / "stage7-infrastructure-created.json").exists():
        raise RuntimeError("Infrastructure was already created; use exact owned continuation")
    cluster = BudgetCluster(task)
    if expected_version not in EXPECTED_VERSIONS or json.loads(cluster.kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"] != expected_version:
        raise RuntimeError("Exact approved stage7 Kubernetes version mismatch")
    fixture = TrialFixture(task)
    protocol = ProtocolAuthority(task)
    cluster.fixture = json.loads((task / "private" / "fixture.json").read_bytes())
    for name in cluster.namespaces:
        if cluster.kube("get", "namespace", name, "--ignore-not-found", "-o", "name").stdout.strip():
            raise RuntimeError("Fresh namespace reservation already exists")
    storage = json.loads(cluster.kube("get", "storageclasses", "-o", "json").stdout)["items"]
    selected = [v for v in storage if v["metadata"].get("annotations", {}).get("storageclass.kubernetes.io/is-default-class") == "true"]
    nodes = json.loads(cluster.kube("get", "nodes", "-o", "json").stdout)["items"]
    if len(selected) != 1 or len(nodes) != 1:
        raise RuntimeError("Explicit single-node/default-storage trial required")
    storage_class, node_name = selected[0]["metadata"]["name"], nodes[0]["metadata"]["name"]
    for role, namespace in fixture.namespaces.items():
        value = object_resource("Namespace", namespace)
        value["metadata"]["labels"] = {"secrets.sekvyr.ru/trial": "stage7", "secrets.sekvyr.ru/trial-domain": role}
        cluster.create(value)
        cluster.create(object_resource("ResourceQuota", "trial-memory-budget", namespace,
            {"hard": {"limits.memory": str(BUDGETS[role]) + "Mi", "pods": "24"}}))
        cluster.create(object_resource("LimitRange", "trial-container-defaults", namespace, {"limits": [{
            "type": "Container", "default": {"memory": "64Mi" if role in ("apps", "isolation") else "128Mi", "cpu": "1000m"},
            "defaultRequest": {"memory": "16Mi", "cpu": "10m"}, "max": {"memory": "512Mi"}}]}))
    # The shared generator's legacy topology has an unused fencer namespace.
    # Explicitly map it to the installation NS and deduplicate identical rules.
    mapped = dict(fixture.namespaces, fencer=fixture.namespaces["apps"])
    policies = {}
    for value in network_policies(mapped):
        key = (value["kind"], value["metadata"]["namespace"], value["metadata"]["name"])
        if key in policies and policies[key] != value:
            raise RuntimeError("Conflicting mapped trial policy")
        policies[key] = value
    for value in policies.values():
        cluster.create(value)
    namespace = fixture.namespaces["storage"]
    cluster.create(secret(namespace, "storage-tls", {name: (task / "private" / name).read_bytes() for name in ("storage.crt", "storage.key")}))
    cluster.create(secret(namespace, "storage-identities", {"s3-identities.json": (task / "private" / "s3-identities.json").read_bytes()}))
    for value in storage_manifests(fixture.namespaces, storage_class, node_name):
        cluster.create(value)
    database.prepare(cluster, storage_class, node_name)
    parameters = {"storage_class": storage_class, "node_name": node_name,
        "expected_kubernetes": expected_version, "namespaceCount": 6, "production": False}
    write_private(task / "infrastructure-parameters.json", canonical(parameters))
    result = {"namespaceCount": 6, "createdPVCs": 2, "aggregatePodMemoryQuotaMiB": sum(BUDGETS.values()),
        "networkPolicyResourcesInstalled": True, "packetIsolationVerified": False,
        "operatorInstalled": False, "panelInstalled": False, "production": False}
    write_private(task / "private" / "stage7-infrastructure-created.json", canonical(result))
    return result

def prepare(task, *, profile):
    selected, _ = reviewed(profile)
    task = legacy.safe_task(task)
    _, fixture = cap.read(task / "private" / "fixture.json")
    owner = Capability(SimpleNamespace(task=task, fixture=fixture), profile=selected.name)
    owner.guard()
    operation = FunctionType(_prepare_template.__code__,
        dict(legacy.prepare.__globals__, EXPECTED_VERSIONS=(selected.version,)))
    result = operation(task, selected.version)
    return {**result, "sourceStage": 8, "profile": selected.name}

def ready(task, *, profile):
    selected, _ = reviewed(profile)
    task = legacy.safe_task(task)
    _, fixture = cap.read(task / "private" / "fixture.json")
    owner = Capability(SimpleNamespace(task=task, fixture=fixture), profile=selected.name)
    owner.guard()
    # Use the exact scoped client; capability has already verified creator identity.
    cluster = legacy.BudgetCluster(task)
    require(json.loads(cluster.kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"] == selected.version,
        "Exact Stage 8 Kubernetes version required")
    return {**legacy.ready(task), "sourceStage": 8, "profile": selected.name}
