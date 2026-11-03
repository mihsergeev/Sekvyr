#!/usr/bin/env python3
"""Prepare or explicitly deploy ONLY the isolated stage-6 trial storage profile."""

import argparse
import hashlib
import json
from pathlib import Path

from cluster import Cluster
from fixture import TrialFixture, canonical, safe_task
from manifests import gateway_manifests, network_policies, object_resource, storage_manifests
from protocol import ProtocolAuthority, gateway_config


def secret(namespace, name, values):
    import base64
    result = object_resource("Secret", name, namespace)
    result.update(type="Opaque", immutable=True, data={
        key: base64.b64encode(value).decode("ascii") for key, value in values.items()})
    return result


def manifests(fixture, storage_class, node_name):
    if not storage_class:
        raise ValueError("Exact approved test storage class required")
    namespaces = fixture["namespaces"]
    output = []
    for role, namespace in namespaces.items():
        resource = object_resource("Namespace", namespace)
        resource["metadata"]["labels"] = {"secrets.sekvyr.ru/trial": "stage6", "secrets.sekvyr.ru/trial-domain": role}
        output.append(resource)
    return output + network_policies(namespaces) + storage_manifests(namespaces, storage_class, node_name)


def infrastructure(task, storage_class, node_name, expected_version):
    cluster = Cluster(task)
    actual = json.loads(cluster.kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if not expected_version or actual != expected_version:
        raise RuntimeError("Exact approved Kubernetes version mismatch")
    # Namespace names must be unused. There is no apply/adoption path.
    for name in cluster.namespaces:
        if cluster.kube("get", "namespace", name, "--ignore-not-found", "-o", "name").stdout.strip():
            raise RuntimeError("A trial namespace already exists")
    fixture = cluster.fixture
    resources = manifests(fixture, storage_class, node_name)
    for resource in resources:
        if resource["kind"] == "Deployment":
            continue
        cluster.create(resource)
    private = task / "private"
    namespace = fixture["namespaces"]["storage"]
    cluster.create(secret(namespace, "storage-tls", {name: (private / name).read_bytes() for name in ("storage.crt", "storage.key")}))
    cluster.create(secret(namespace, "storage-identities", {"s3-identities.json": (private / "s3-identities.json").read_bytes()}))
    for resource in resources:
        if resource["kind"] == "Deployment":
            cluster.create(resource)
    return {"production": False, "namespacesCreated": len(cluster.namespaces),
        "storageDeploymentCreated": True, "journalInitialized": False, "gatewayOrOperatorInstalled": False}


def install_gateway(task, image, node_name):
    cluster = Cluster(task)
    # Verify creation-time identities without executing cleanup.
    cluster.cleanup_namespaces(execute=False)
    ready = json.loads((task / "private" / "storage-ready.json").read_text(encoding="utf-8"))
    if not ready.get("fsync") or ready.get("ttl") or ready.get("production"):
        raise ValueError("Storage must be explicitly bootstrapped before gateway")
    protocol = ProtocolAuthority.load(task)
    private = task / "private"
    namespace = cluster.fixture["namespaces"]["gateway"]
    credentials = json.loads((private / "storage-credentials.json").read_text(encoding="utf-8"))["gateway"]
    cluster.create(secret(namespace, "gateway-upstream-access", {
        "access-key": credentials["access_key"].encode(), "secret-key": credentials["secret_key"].encode()}))
    cluster.create(secret(namespace, "journal-gateway-files", {name: (private / name).read_bytes()
        for name in ("journal.crt", "journal.key", "journal-ca.crt", "storage-ca.crt")}))
    raw_config = canonical(gateway_config(task, protocol)).decode()
    config_name = "journal-config-" + hashlib.sha256(raw_config.encode()).hexdigest()[:12]
    config = object_resource("ConfigMap", config_name, namespace)
    config.update(immutable=True, data={"config.json": raw_config})
    cluster.create(config)
    for resource in gateway_manifests(cluster.fixture["namespaces"], image, node_name, config_name):
        cluster.create(resource)
    return {"gatewayCreated": True, "journalInitialized": False, "production": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("prepare", "render", "infrastructure", "gateway", "cleanup", "cleanup-cluster-before", "cleanup-cluster-after"), required=True)
    parser.add_argument("--storage-class", default="")
    parser.add_argument("--node-name", default="")
    parser.add_argument("--expected-kubernetes", default="")
    parser.add_argument("--gateway-image", default="")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--acknowledge-trial-storage-destruction", action="store_true")
    args = parser.parse_args()
    task = safe_task(args.task_dir)
    if args.phase == "prepare":
        task.mkdir(mode=0o700, exist_ok=True)
        fixture = TrialFixture(task)
        ProtocolAuthority(task)
        print(json.dumps({"prepared": True, "production": False, "namespaceCount": len(fixture.namespaces)}))
    elif args.phase == "render":
        fixture = json.loads((task / "private" / "fixture.json").read_text(encoding="utf-8"))
        print(json.dumps({"apiVersion": "v1", "kind": "List", "items": manifests(fixture, args.storage_class, args.node_name)}, indent=2))
    elif args.phase == "infrastructure":
        if not args.execute:
            raise ValueError("Remote infrastructure requires explicit --execute and coordinator approval")
        print(json.dumps(infrastructure(task, args.storage_class, args.node_name, args.expected_kubernetes)))
    elif args.phase == "gateway":
        if not args.execute:
            raise ValueError("Gateway deployment requires explicit coordinator approval")
        print(json.dumps(install_gateway(task, args.gateway_image, args.node_name)))
    elif args.phase.startswith("cleanup-cluster-"):
        phase = "before-namespaces" if args.phase.endswith("before") else "after-namespaces"
        print(json.dumps(Cluster(task).cleanup_cluster_resources(phase, args.execute)))
    else:
        result = Cluster(task).cleanup_namespaces(args.execute, args.acknowledge_trial_storage_destruction)
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("FAIL isolated trial phase: " + type(error).__name__)
        raise SystemExit(1)
