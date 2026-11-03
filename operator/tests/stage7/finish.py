#!/usr/bin/env python3
"""Resume only a creation-pinned local node; never create or adopt a cluster."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from prepare import CLUSTER, NODE, canonical, capacity, docker, run, save


def exact_file(path, raw, mode=0o600):
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.resolve() != path or path.read_bytes() != raw:
            raise RuntimeError("Saved stage7 input differs from exact resume")
    else:
        save(path, raw, mode)


def finish(task, crd_dir):
    task = Path(task).absolute()
    if task.parent != Path("/var/tmp") or not re.fullmatch(r"sekvyr-stage7\.[A-Za-z0-9_-]+", task.name) or task.resolve() != task:
        raise RuntimeError("Unreviewed local resume root")
    pin = json.loads((task / "private" / "node-pin.json").read_bytes())
    nodes = docker("ps", "-a", "--filter=label=io.x-k8s.kind.cluster=" + CLUSTER, "--format={{.ID}}").split()
    if len(nodes) != 1:
        raise RuntimeError("Creation-pinned local node count changed")
    obj = json.loads(docker("inspect", nodes[0]))[0]
    if obj["Id"] != pin["id"] or pin["image"] != NODE or obj["Config"]["Image"] != NODE or obj["Config"]["Labels"].get("io.x-k8s.kind.cluster") != CLUSTER:
        raise RuntimeError("Local node replaced; resume refused")
    # Docker requires the two memory limits to change atomically. This disables
    # swap for this node only and does not change WSL or host swap settings.
    docker("update", "--cpus=4", "--memory=6g", "--memory-swap=6g", obj["Id"])
    obj = json.loads(docker("inspect", pin["id"]))[0]
    if obj["HostConfig"]["Memory"] != 6 << 30 or obj["HostConfig"]["MemorySwap"] != 6 << 30 or obj["HostConfig"]["NanoCpus"] != 4_000_000_000:
        raise RuntimeError("Local node resource caps not enforced")
    config = task / "kubeconfig"
    if config.is_symlink() or config.resolve() != config or not config.is_file():
        raise RuntimeError("Local kubeconfig path unsafe")
    run(["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), str(config)])
    config.chmod(0o600)
    binary = docker("exec", pin["id"], "cat", "/usr/bin/kubectl", binary=True)
    if not binary.startswith(b"\x7fELF"):
        raise RuntimeError("Matching private client is not ELF")
    exact_file(task / "tools" / "kubectl", binary, 0o755)
    exact_file(task / "kubectl", ("#!/bin/sh\nexec '" + str(task / "tools" / "kubectl") + "' \"$@\"\n").encode(), 0o755)
    kube = [str(task / "kubectl"), "--kubeconfig", str(config)]
    actual = json.loads(run(kube + ["version", "-o", "json"]))
    if actual["serverVersion"]["gitVersion"] != "v1.37.0" or actual["clientVersion"]["gitVersion"] != "v1.37.0":
        raise RuntimeError("Exact local client/server version mismatch")
    items = json.loads(run(kube + ["get", "nodes", "-o", "json"]))["items"]
    if len(items) != 1 or not any(v.get("type") == "Ready" and v.get("status") == "True" for v in items[0].get("status", {}).get("conditions", [])):
        raise RuntimeError("Local node is not uniquely ready")
    if "failCgroupV1: false" not in docker("exec", pin["id"], "cat", "/var/lib/kubelet/config.yaml"):
        raise RuntimeError("Kubelet-only local cgroup compatibility patch missing")
    (task / "crds").mkdir(mode=0o700, exist_ok=True)
    files = sorted(Path(crd_dir).glob("*.yaml"))
    if len(files) != 2:
        raise RuntimeError("Expected two reviewed operator CRDs")
    pins = []
    for file in files:
        raw = file.read_bytes()
        target = task / "crds" / file.name
        exact_file(target, raw)
        receipt = task / "private" / ("initial-crd-" + file.name + ".json")
        if receipt.exists():
            record = json.loads(receipt.read_bytes())
            created = json.loads(run(kube + ["get", "crd", record["name"], "-o", "json"]))
            if created["metadata"]["uid"] != record["uid"] or record["sourceSHA256"] != hashlib.sha256(raw).hexdigest():
                raise RuntimeError("Pinned CRD changed before resume")
        else:
            created = json.loads(run(kube + ["create", "-f", str(target), "-o", "json"]))
            if created["kind"] != "CustomResourceDefinition":
                raise RuntimeError("Unexpected admission baseline resource")
            record = {"kind": created["kind"], "name": created["metadata"]["name"], "uid": created["metadata"]["uid"],
                "sourceSHA256": hashlib.sha256(raw).hexdigest()}
            save(receipt, canonical(record))
        pins.append(record)
        run(kube + ["wait", "--for=condition=Established", "crd/" + record["name"], "--timeout=60s"], timeout=70)
    exact_file(task / "private" / "initial-crd-pins.json", canonical(pins))
    exact_file(task / "private" / "capacity-after.json", canonical(capacity()))
    before = json.loads((task / "private" / "docker-baseline.json").read_bytes())
    result = {"localOnly": True, "production": False, "serverGitVersion": "v1.37.0", "clientGitVersion": "v1.37.0",
        "nodeCount": 1, "readyNodes": 1, "establishedCRDs": len(pins), "preexistingContainers": len(before["containers"]),
        "globalConfigurationChanged": False, "cgroupV1CompatibilityKubeletOnly": True, "nodeCPUCap": 4, "nodeMemoryCapGiB": 6}
    exact_file(task / "initial-admission-evidence.json", canonical(result))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--crd-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(finish(args.task_dir, args.crd_dir)), flush=True)
