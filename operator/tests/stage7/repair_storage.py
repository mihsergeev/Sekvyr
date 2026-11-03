"""Explicit local trial weed memory experiment, preserving storage identity."""

import copy
import json
from datetime import datetime, timezone

from app_modes import OwnedNamespace, require, wait
from fixture import canonical, write_private


def run(coordinator, accepted_current):
    c = coordinator
    require(c.task.parent.as_posix() == "/var/tmp", "Storage experiment is local owned kind only")
    root = c.private / "storage-memory-experiment.json"
    require(not root.exists(), "Storage experiment cannot silently reset a previous attempt")
    own = OwnedNamespace(c.cluster, c.namespaces["storage"])
    old = own.get("Deployment", "storage")
    require(old["spec"].get("replicas") == 1, "Storage experiment requires original replica count")
    containers = old["spec"]["template"]["spec"]["containers"]
    require(len(containers) == 3 and {item["name"] for item in containers} == {"storage", "s3-1", "s3-2"}
        and all(item["resources"]["limits"]["memory"] == "128Mi" for item in containers), "Storage experiment input limits differ")
    quota = own.get("ResourceQuota", "trial-memory-budget")
    require(quota["spec"]["hard"]["limits.memory"] == "512Mi", "Storage experiment quota differs")
    volumes = [volume["persistentVolumeClaim"]["claimName"] for volume in old["spec"]["template"]["spec"]["volumes"] if "persistentVolumeClaim" in volume]
    require(len(volumes) == 1, "Storage experiment needs one pinned persistent volume")
    pvc = own.get("PersistentVolumeClaim", volumes[0])
    current = accepted_current
    require(current["scope"] == c.protocol.scope and current["genesis_hash"] == c.protocol.genesis_hash
        and int(current["snapshot"]["sequence"]) > 0, "Storage experiment needs the exact already observed canonical checkpoint")
    plan = {"deploymentUID": old["metadata"]["uid"], "pvcUID": pvc["metadata"]["uid"], "oldSpec": old["spec"],
        "snapshot": current["snapshot"], "genesisHash": current["genesis_hash"], "memoryChanged": {"storage": ["128Mi", "256Mi"]}}
    write_private(root, canonical(plan))
    own.patch("Deployment", "storage", [{"op": "test", "path": "/spec", "value": old["spec"]}, {"op": "replace", "path": "/spec/replicas", "value": 0}])
    def stopped():
        value = own.get("Deployment", "storage")
        pods = json.loads(c.cluster.kube("get", "pods", "-n", own.namespace, "-o", "json").stdout)["items"]
        return value["spec"]["replicas"] == 0 and not pods
    wait(stopped)
    zero = own.get("Deployment", "storage")
    expected = copy.deepcopy(old["spec"])
    expected["replicas"] = 0
    require(zero["spec"] == expected and own.get("PersistentVolumeClaim", volumes[0])["metadata"]["uid"] == plan["pvcUID"], "Storage experiment changed identity or another field")
    desired = copy.deepcopy(old["spec"])
    for item in desired["template"]["spec"]["containers"]:
        if item["name"] == "storage":
            item["resources"]["limits"]["memory"] = "256Mi"
    own.patch("Deployment", "storage", [{"op": "test", "path": "/spec", "value": expected}, {"op": "replace", "path": "/spec", "value": desired}])
    def ready():
        value = own.get("Deployment", "storage")
        return value["spec"] == desired and value.get("status", {}).get("observedGeneration") == value["metadata"]["generation"] and value.get("status", {}).get("readyReplicas") == 1 and value.get("status", {}).get("updatedReplicas") == 1
    wait(ready, timeout=180)
    require(own.get("PersistentVolumeClaim", volumes[0])["metadata"]["uid"] == plan["pvcUID"], "Storage PVC was replaced")
    return {"storageDeploymentUIDPreserved": True, "pvcUIDPreserved": True, "onlyWeedMemoryLimitChanged": True,
        "storageQuotaMiB": 512, "oomCauseProven": False, "storageReset": False}


def verify(coordinator):
    from forward import Forward
    from gateway_probe import clients, framed
    from protocol import record_hash
    c = coordinator
    latest = (c.private / "storage-memory-512-experiment.json").exists()
    plan = json.loads((c.private / ("storage-memory-512-experiment.json" if latest else "storage-memory-experiment.json")).read_bytes())
    entries = [{"record": c.protocol.genesis_record, "registration": c.protocol.registration}, *c.protocol.fault_logs.values()]
    with Forward(c.cluster, c.namespaces["gateway"], "service/journal", 8443) as forward:
        admin = clients(c.task, forward.origin)["admin"]
        for entry in entries:
            nonce, (_, raw, _) = admin.journal(entry["registration"]["log_id"])
            end = json.loads(raw.splitlines()[-1])
            slots = framed(raw, nonce, end["last_record_hash"])
            require(slots and slots[0]["record"] == entry["record"]
                and record_hash(slots[0]["record"]) == entry["registration"]["genesis_hash"]
                and record_hash(slots[-1]["record"]) == end["last_record_hash"], "Storage replay changed retained genesis or terminal hash")
            for slot in slots:
                receipt = slot["receipt"]
                require(receipt["mode"] == "COMPLIANCE" and receipt["version_id"]
                    and datetime.fromisoformat(receipt["retain_until"].replace("Z", "+00:00")) > datetime.now(timezone.utc), "Storage replay lost valid version retention")
    current = c.current()
    require(current["scope"] == c.protocol.scope and current["genesis_hash"] == plan["genesisHash"]
        and current["snapshot"] == plan["snapshot"], "Resource repair changed the accepted canonical snapshot")
    own = OwnedNamespace(c.cluster, c.namespaces["storage"])
    deployment = own.get("Deployment", "storage")
    volumes = [volume["persistentVolumeClaim"]["claimName"] for volume in deployment["spec"]["template"]["spec"]["volumes"] if "persistentVolumeClaim" in volume]
    require(deployment["metadata"]["uid"] == plan["deploymentUID"] and len(volumes) == 1
        and own.get("PersistentVolumeClaim", volumes[0])["metadata"]["uid"] == plan["pvcUID"], "Storage resource identity changed")
    result = {"exactRetainedGenesisRecords": len(entries), "allCurrentVersionsComplianceRetained": True,
        "acceptedCanonicalSnapshotUnchanged": True, "originalVersionIDContinuityPinned": False,
        "deploymentAndPVCUIDsPreserved": True, "storageReset": False, "production": False}
    write_private(c.private / ("storage-memory-512-reverification.json" if latest else "storage-memory-reverification.json"), canonical(result))
    return result


def _mib(value):
    require(isinstance(value, str), "Memory quantity invalid")
    for suffix, scale in (("Gi", 1024), ("Mi", 1), ("Ki", 1 / 1024)):
        if value.endswith(suffix):
            number = value[:-len(suffix)]
            require(number.isdigit(), "Memory quantity invalid")
            return int(number) * scale
    require(value.isdigit(), "Memory quantity invalid")
    return int(value) / 1048576


def raise_to_512(coordinator, accepted_current):
    c = coordinator
    require(c.task.parent.as_posix() == "/var/tmp", "Storage experiment is local owned kind only")
    path = c.private / "storage-memory-512-experiment.json"
    require(not path.exists(), "Second memory experiment cannot reset an attempt")
    require(accepted_current["scope"] == c.protocol.scope and accepted_current["genesis_hash"] == c.protocol.genesis_hash,
        "Storage experiment accepted checkpoint context differs")
    own = {role: OwnedNamespace(c.cluster, c.namespaces[role]) for role in c.namespaces}
    quotas = {role: scope.get("ResourceQuota", "trial-memory-budget") for role, scope in own.items()}
    previous = {"storage": 512, "gateway": 256, "witness": 512, "panel": 1024, "apps": 1024, "isolation": 768}
    following = dict(previous, storage=768, witness=384, panel=896)
    require(sum(previous.values()) == sum(following.values()) == 4096, "Memory budget total differs")
    for role, quota in quotas.items():
        require(_mib(quota["spec"]["hard"]["limits.memory"]) == previous[role]
            and _mib(quota.get("status", {}).get("used", {}).get("limits.memory", "0")) <= following[role], "Memory donor quota is not available")
    old = own["storage"].get("Deployment", "storage")
    containers = old["spec"]["template"]["spec"]["containers"]
    require(old["spec"]["replicas"] == 1 and len(containers) == 3
        and {item["name"]: item["resources"]["limits"]["memory"] for item in containers} == {"storage": "256Mi", "s3-1": "128Mi", "s3-2": "128Mi"}
        and all(not any(env.get("name") == "GOMEMLIMIT" for env in item.get("env", [])) for item in containers), "Second storage experiment input differs")
    volumes = [item["persistentVolumeClaim"]["claimName"] for item in old["spec"]["template"]["spec"]["volumes"] if "persistentVolumeClaim" in item]
    require(len(volumes) == 1, "Storage PVC identity ambiguous")
    pvc = own["storage"].get("PersistentVolumeClaim", volumes[0])
    plan = {"deploymentUID": old["metadata"]["uid"], "pvcUID": pvc["metadata"]["uid"], "oldSpec": old["spec"],
        "snapshot": accepted_current["snapshot"], "genesisHash": accepted_current["genesis_hash"],
        "previousQuotas": previous, "followingQuotas": following}
    write_private(path, canonical(plan))
    for role in ("witness", "panel", "storage"):
        own[role].patch("ResourceQuota", "trial-memory-budget", [{"op": "test", "path": "/spec", "value": quotas[role]["spec"]},
            {"op": "replace", "path": "/spec/hard/limits.memory", "value": str(following[role]) + "Mi"}])
    storage = own["storage"]
    storage.patch("Deployment", "storage", [{"op": "test", "path": "/spec", "value": old["spec"]}, {"op": "replace", "path": "/spec/replicas", "value": 0}])
    wait(lambda: not json.loads(c.cluster.kube("get", "pods", "-n", storage.namespace, "-o", "json").stdout)["items"])
    zero = copy.deepcopy(old["spec"])
    zero["replicas"] = 0
    desired = copy.deepcopy(old["spec"])
    for item in desired["template"]["spec"]["containers"]:
        if item["name"] == "storage":
            item["resources"]["limits"]["memory"] = "512Mi"
            item.setdefault("env", []).append({"name": "GOMEMLIMIT", "value": "384MiB"})
    storage.patch("Deployment", "storage", [{"op": "test", "path": "/spec", "value": zero}, {"op": "replace", "path": "/spec", "value": desired}])
    def ready():
        value = storage.get("Deployment", "storage")
        return value["spec"] == desired and value.get("status", {}).get("observedGeneration") == value["metadata"]["generation"] and value.get("status", {}).get("readyReplicas") == 1
    wait(ready, timeout=180)
    require(storage.get("PersistentVolumeClaim", volumes[0])["metadata"]["uid"] == plan["pvcUID"], "Storage PVC identity changed")
    return {"memoryBudgetMiB": 4096, "storageQuotaMiB": 768, "weedLimitMiB": 512, "weedGoMemoryMiB": 384,
        "sameDeploymentAndPVCUID": True, "storageReset": False, "stabilityVerified": False, "production": False}
