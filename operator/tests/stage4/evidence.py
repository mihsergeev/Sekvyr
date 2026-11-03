#!/usr/bin/env python3
"""Capture sanitized final evidence without exporting credentials or Secret data."""

import argparse
import base64
import json
from pathlib import Path
import urllib.request

from authority import Authority
import common
import infrastructure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--driver", choices=("kind", "k0s"), required=True)
    args = parser.parse_args()
    task = Authority.safe_task(args.task_dir)
    common.configure(args.driver, task)
    if args.driver == "k0s":
        infrastructure.configure(task.name)
    app_ns = infrastructure.APP_NS
    metadata = json.loads((task / "private" / "bootstrap.json").read_text())
    authority = Authority.load(task)
    forward = common.Forward(task, app_ns, "pod/canary", 8080)
    try:
        with urllib.request.urlopen("http://127.0.0.1:" + str(forward.port) + "/status", timeout=5) as response:
            canary = json.load(response)
    finally:
        forward.close()
    pod = common.get("pod", "canary", app_ns)
    state = common.get("secret", "operator-state", app_ns)
    state_body = json.loads(base64.b64decode(state["data"]["state.json"]))
    record = state_body["bindings"][metadata["store_uid"] + "/" + authority.binding_id]
    images = {}
    for label, namespace, name in (("panel", infrastructure.PANEL_NS, "panel"),
                                    ("witness", infrastructure.WITNESS_NS, "witness"),
                                    ("operator", app_ns, "stage4-operator")):
        images[label] = common.get("deployment", name, namespace)["spec"]["template"]["spec"]["containers"][0]["image"]
    resources = {kind: common.get(kind, name, app_ns)["status"]
                 for kind, name in (("sekvyrsecret", "runtime"), ("sekvyrstore", "application-secrets"))}
    report = json.loads((task / "results.json").read_text())
    startup = json.loads(common.kube("logs", "canary", "-n", app_ns).stdout.strip())
    nodes = json.loads(common.kube("get", "nodes", "-o", "json").stdout)["items"]
    ready_nodes = sum(any(item["type"] == "Ready" and item["status"] == "True"
                          for item in node["status"]["conditions"]) for node in nodes)
    workloads = json.loads(common.kube("get", "deployments,statefulsets,daemonsets", "-A", "-o", "json").stdout)["items"]
    baseline = {"checked": 0, "belowDesiredReady": 0}
    for workload in workloads:
        if workload["metadata"]["namespace"].startswith("sekvyr-stage4-"):
            continue
        baseline["checked"] += 1
        status, spec = workload.get("status", {}), workload["spec"]
        desired = status.get("desiredNumberScheduled", 0) if workload["kind"] == "DaemonSet" else spec.get("replicas", 1)
        ready = status.get("numberReady", 0) if workload["kind"] == "DaemonSet" else status.get("readyReplicas", 0)
        baseline["belowDesiredReady"] += ready < desired
    evidence = {
        "kubernetesVersion": json.loads(common.kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"],
        "images": images, "canaryStatus": canary,
        "canaryPodUID": pod["metadata"]["uid"],
        "canaryContainerRestarts": [item["restartCount"] for item in pod["status"]["containerStatuses"]],
        "durableCheckpointSequence": record["head"]["Sequence"],
        "stateReplacementRejected": state["metadata"]["uid"] != metadata["state_uid"],
        "resourceStatus": resources,
        "appBootIDMatchesStartup": startup["boot_id"] == canary["boot_id"],
        "nodes": {"checked": len(nodes), "ready": ready_nodes},
        "baselineWorkloadsBeforeCleanup": baseline,
        "scope": report["scope"], "limitations": report["limitations"], "passed": report["passed"],
    }
    (task / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print("PASS sanitized app, checkpoint, status and pinned-image evidence captured")


if __name__ == "__main__":
    main()
