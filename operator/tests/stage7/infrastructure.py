"""Fresh six-namespace local trial infrastructure with a 4GiB Pod limit budget."""

import copy
import json
from pathlib import Path

from cluster import Cluster
from fixture import TrialFixture, canonical, safe_task, write_private
from manifests import LABEL, network_policies, object_resource, storage_manifests
from protocol import ProtocolAuthority
from run import secret
import database

BUDGETS = {"storage": 768, "gateway": 256, "witness": 384,
    "panel": 896, "apps": 1024, "isolation": 768}


class BudgetCluster(Cluster):
    def create(self, resource):
        value = copy.deepcopy(resource)
        if value["kind"] == "Deployment":
            pod = value["spec"]["template"]["spec"]
            role = value["spec"]["template"]["metadata"].get("labels", {}).get(LABEL)
            memory = {"storage": 128, "database": 256, "panel": 384, "witness": 128, "journal-gateway": 128}.get(role)
            if memory:
                for container in pod.get("containers", []):
                    limit_memory = 512 if role == "storage" and container["name"] == "storage" else memory
                    container["resources"] = {"requests": {"cpu": "20m", "memory": "32Mi"},
                        "limits": {"cpu": "1000m", "memory": str(limit_memory) + "Mi"}}
                    if role == "storage" and container["name"] == "storage":
                        environment = container.setdefault("env", [])
                        if any(item.get("name") == "GOMEMLIMIT" for item in environment):
                            raise RuntimeError("Unreviewed storage memory policy")
                        environment.append({"name": "GOMEMLIMIT", "value": "384MiB"})
                for container in pod.get("initContainers", []):
                    container["resources"] = {"requests": {"cpu": "10m", "memory": "16Mi"},
                        "limits": {"cpu": "500m", "memory": "64Mi"}}
        return super().create(value)


def prepare(task, expected_version):
    task = safe_task(task)
    if (task / "private" / "stage7-infrastructure-created.json").exists():
        raise RuntimeError("Infrastructure was already created; use exact owned continuation")
    cluster = BudgetCluster(task)
    if expected_version not in ("v1.37.0", "v1.34.1+k0s") or json.loads(cluster.kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"] != expected_version:
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


def ready(task):
    cluster = BudgetCluster(safe_task(task))
    for role, name in (("storage", "storage"), ("panel", "database")):
        cluster.kube("-n", cluster.fixture["namespaces"][role], "rollout", "status", "deployment/" + name, "--timeout=180s")
    return {"storageReady": True, "postgresReady": True, "operatorInstalled": False, "production": False}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("prepare", "ready"), required=True)
    parser.add_argument("--expected-kubernetes", choices=("v1.37.0", "v1.34.1+k0s"))
    args = parser.parse_args()
    result = prepare(args.task_dir, args.expected_kubernetes) if args.phase == "prepare" else ready(args.task_dir)
    print(json.dumps(result), flush=True)
