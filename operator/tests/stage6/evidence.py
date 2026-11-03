#!/usr/bin/env python3
"""Read-only baseline/cleanup evidence; real workload identities stay private."""

import argparse
import hashlib
import json
from pathlib import Path

from cluster import Cluster
from fixture import canonical, safe_task, write_private


def snapshot(cluster):
    nodes = json.loads(cluster.kube("get", "nodes", "-o", "json").stdout)["items"]
    workloads = json.loads(cluster.kube("get", "deployments,statefulsets,daemonsets", "-A", "-o", "json").stdout)["items"]
    baseline = {}
    below_ready = 0
    for value in workloads:
        if value["metadata"]["namespace"] in cluster.namespaces:
            continue
        identity = "/".join([value["apiVersion"], value["kind"], value["metadata"]["namespace"], value["metadata"]["name"]])
        baseline[identity] = {"uid": value["metadata"]["uid"], "spec": value["spec"]}
        desired = value.get("status", {}).get("desiredNumberScheduled", 0) if value["kind"] == "DaemonSet" else value["spec"].get("replicas", 1)
        actual = value.get("status", {}).get("numberReady", 0) if value["kind"] == "DaemonSet" else value.get("status", {}).get("readyReplicas", 0)
        below_ready += actual < desired
    ready_nodes = sum(any(condition["type"] == "Ready" and condition["status"] == "True"
                         for condition in node.get("status", {}).get("conditions", [])) for node in nodes)
    return baseline, {"nodeCount": len(nodes), "readyNodeCount": ready_nodes,
        "baselineWorkloadCount": len(baseline), "baselineWorkloadsBelowReady": below_ready}


def capture(cluster, phase):
    baseline, counts = snapshot(cluster)
    private = cluster.task / "private" / "baseline.json"
    if phase == "before":
        if counts["nodeCount"] == 0 or counts["readyNodeCount"] != counts["nodeCount"] or counts["baselineWorkloadsBelowReady"]:
            raise RuntimeError("Baseline not ready before trial")
        write_private(private, canonical(baseline))
        return {"phase": phase, "baselineReady": True, **counts}
    saved = json.loads(private.read_text(encoding="utf-8"))
    if baseline != saved:
        raise RuntimeError("Baseline workload UID or spec changed")
    namespaces = json.loads(cluster.kube("get", "namespaces", "-o", "json").stdout)["items"]
    remaining_namespaces = sum(value["metadata"]["name"] in cluster.namespaces for value in namespaces)
    volumes = json.loads(cluster.kube("get", "pv", "-o", "json").stdout)["items"]
    remaining_volumes = sum(value.get("spec", {}).get("claimRef", {}).get("namespace") in cluster.namespaces for value in volumes)
    if remaining_namespaces or remaining_volumes or counts["readyNodeCount"] != counts["nodeCount"] or counts["baselineWorkloadsBelowReady"]:
        raise RuntimeError("Cleanup or baseline readiness remains incomplete")
    return {"phase": phase, "remainingTrialNamespaces": 0, "remainingTrialPersistentVolumes": 0,
        "baselineWorkloadUIDsAndSpecsUnchanged": True, **counts,
        "clusterScopedResourcesAndPrivateProcessCleanup": "separate explicit evidence required"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    args = parser.parse_args()
    task = safe_task(args.task_dir)
    result = capture(Cluster(task), args.phase)
    # Public evidence excludes names, addresses, credentials and private paths.
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("FAIL trial baseline evidence: " + type(error).__name__)
        raise SystemExit(1)
