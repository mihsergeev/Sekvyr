#!/usr/bin/env python3
"""Append only counts, opaque identities and hashes to the isolated E2E report."""

import argparse
import base64
import json
from pathlib import Path

import run as runner


def baseline(task):
    kube = runner.common.kube
    nodes = json.loads(kube("get", "nodes", "-o", "json").stdout)["items"]
    ready = sum(any(item["type"] == "Ready" and item["status"] == "True"
                    for item in node["status"]["conditions"]) for node in nodes)
    workloads = json.loads(kube("get", "deployments,statefulsets,daemonsets", "-A", "-o", "json").stdout)["items"]
    counts = {"nodeCount": len(nodes), "readyNodeCount": ready, "workloadCount": 0, "workloadsBelowDesiredReady": 0}
    for workload in workloads:
        if workload["metadata"]["namespace"].startswith("sekvyr-stage"):
            continue
        counts["workloadCount"] += 1
        status, spec = workload.get("status", {}), workload["spec"]
        desired = status.get("desiredNumberScheduled", 0) if workload["kind"] == "DaemonSet" else spec.get("replicas", 1)
        actual = status.get("numberReady", 0) if workload["kind"] == "DaemonSet" else status.get("readyReplicas", 0)
        counts["workloadsBelowDesiredReady"] += actual < desired
    volumes = json.loads(kube("get", "pv", "-o", "json").stdout)["items"]
    counts["testPersistentVolumes"] = sum(volume.get("spec", {}).get("claimRef", {}).get("namespace", "").startswith(task.name + "-")
                                         for volume in volumes)
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("before-cleanup", "after-cleanup"), required=True)
    args = parser.parse_args()
    task = runner.Authority.safe_task(args.task_dir)
    runner.common.configure("k0s", task)
    runner.infrastructure.configure(task.name, release=runner.RELEASE)
    runner.base.APP_NS = runner.infrastructure.APP_NS
    path = task / "results.json"
    report = json.loads(path.read_text())
    if "images" in report:
        report["imageDigests"] = {name: image.split("@", 1)[1] for name, image in report.pop("images").items()}
    report["baseline" + ("BeforeCleanup" if args.phase == "before-cleanup" else "AfterCleanup")] = baseline(task)
    if args.phase == "before-cleanup":
        deployment = runner.deployment()
        events = json.loads(runner.common.kube("get", "events", "-n", runner.infrastructure.APP_NS, "-o", "json").stdout)["items"]
        state = runner.common.get("secret", "operator-state", runner.infrastructure.APP_NS)
        state_body = json.loads(base64.b64decode(state["data"]["state.json"]))
        checkpoint_sequences = sorted({value["head"]["Sequence"] for value in state_body["bindings"].values()})
        status = {item["type"]: {"status": item["status"], "reason": item["reason"]}
                  for item in runner.child()["status"]["conditions"]}
        report["postRunEvidence"] = {
            "currentDeploymentUID": deployment["metadata"]["uid"],
            "currentReplicaSetUIDs": sorted(runner.replica_set_uids()),
            "currentApp": runner.app_status(task),
            "historicalReplicaSetUIDsFromEvents": sorted({event["involvedObject"]["uid"] for event in events
                if event.get("involvedObject", {}).get("kind") == "ReplicaSet" and
                event["involvedObject"].get("name", "").startswith(runner.APP + "-")}),
            "durableCheckpointSequences": checkpoint_sequences, "conditions": status,
            "expectedFinalState": "Fail-closed after intentional state UID replacement",
        }
    else:
        namespaces = json.loads(runner.common.kube("get", "namespaces", "-o", "json").stdout)["items"]
        report["cleanup"] = {
            "remainingTestNamespaces": sum(item["metadata"]["name"].startswith(task.name + "-") for item in namespaces),
            "remainingTestCRDs": sum(bool(runner.common.kube("get", "crd", name, "--ignore-not-found", "-o", "name").stdout.strip())
                                      for name in ("sekvyrstores.secrets.sekvyr.ru", "sekvyrsecrets.secrets.sekvyr.ru")),
            "deleteUIDPreconditionsUsed": True,
        }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("PASS sanitized evidence captured for " + args.phase)


if __name__ == "__main__":
    main()
