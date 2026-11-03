"""Fresh same-host remote Linux kind creator. No action on import.

The coordinator supplies independently reviewed private kind/Helm binary hashes.
No daemon, clock, sysctl, existing container or network configuration is changed.
Partial creator failures need explicit review; they are never adopted/recreated.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal

from app_modes import require
from fixture import canonical
from prepare import NODE, ROLES, SOCKET, run, save
from remote_kind_capability import (CAPS, FORMAT, MARKER, Capability, digest, directory, docker, host, network_hash, paths, process, root_creation, container_snapshot, mounts_hash)


def baseline():
    containers, volumes, networks = {}, {}, {}
    for cid in docker("ps", "-a", "--format={{.ID}}").decode().split():
        value = json.loads(docker("inspect", cid))[0]
        containers[value["Id"]] = container_snapshot(value)
    for name in docker("volume", "ls", "--format={{.Name}}").decode().split():
        volumes[name] = digest(canonical(json.loads(docker("volume", "inspect", name))[0]))
    kind = None
    for netid in docker("network", "ls", "--format={{.ID}}").decode().split():
        value = json.loads(docker("network", "inspect", netid))[0]
        networks[value["Id"]] = digest(canonical(value))
        if value["Name"] == "kind":
            require(kind is None and not value.get("Containers"), "Existing kind network is shared; no disconnect or reuse")
            kind = {"id": value["Id"], "configSHA256": network_hash(value), "fullSHA256": digest(canonical(value))}
    return {"containers": containers, "volumes": volumes, "networks": networks, "kindNetwork": kind}


def foreign_unchanged(before, own_cid=None, own_network=None, own_volumes=()):
    for cid, expected in before["containers"].items():
        value = json.loads(docker("inspect", cid))[0]
        actual = container_snapshot(value)
        require(value["Id"] == cid and actual == expected, "Foreign container changed during isolated trial")
    for name, expected in before["volumes"].items():
        require(digest(canonical(json.loads(docker("volume", "inspect", name))[0])) == expected, "Foreign volume changed")
    for identifier, expected in before["networks"].items():
        value = json.loads(docker("network", "inspect", identifier))[0]
        if own_network and identifier == own_network and before["kindNetwork"]:
            require(network_hash(value) == before["kindNetwork"]["configSHA256"]
                and set(value.get("Containers", {})).issubset({own_cid} if own_cid else set()), "Existing kind network changed or became shared")
        else:
            require(digest(canonical(value)) == expected, "Foreign Docker network changed")


def reviewed_tool(root, binary, expected, version):
    binary = Path(binary)
    require(binary.resolve() == binary and binary.is_file() and not binary.is_symlink()
        and binary.stat().st_uid == 0 and binary.stat().st_size <= 128 << 20 and binary.name in ("kind", "helm", "kubectl") and binary.parent in (root / "tools", root / "tools" / "bin")
        and len(expected) == 64 and digest(binary.read_bytes()) == expected, "Exact reviewed private tool required")
    if binary.name == "kubectl":
        actual = json.loads(run([str(binary), "version", "--client=true", "-o", "json"]))
        require(actual["clientVersion"]["gitVersion"] == version, "Private kubectl version differs")
    else:
        require(run([str(binary), "version", *(["--short"] if binary.name == "helm" else [])]).startswith(version), "Private tool version differs")
    return binary


def runtime_capabilities():
    require(hasattr(os, "setns") and hasattr(os, "CLONE_NEWNET") and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"), "Python network-namespace/pidfd runtime prerequisites unavailable")


def create(root_task, runtime_task, kind_binary, helm_binary, kubectl_binary, kind_sha256, helm_sha256, kubectl_sha256, crd_dir):
    require(os.geteuid() == 0 and os.uname().sysname == "Linux" and os.uname().machine == "x86_64",
        "Root Linux amd64 creator required")
    runtime_capabilities()
    root, task, backup = paths(root_task, runtime_task)
    directory(root)
    root_receipt, _ = root_creation(root, task)  # Existing ROOT task is not TOFU.
    require(not task.exists() and not task.is_symlink() and not backup.exists() and not backup.is_symlink(),
        "Remote kind creator reservation already exists; explicit partial-run review required")
    kind = reviewed_tool(root, kind_binary, kind_sha256, "kind v0.33.0")
    helm = reviewed_tool(root, helm_binary, helm_sha256, "v4.3.1")
    kubectl = reviewed_tool(root, kubectl_binary, kubectl_sha256, "v1.37.0")
    memory = {key: int(value.split()[0]) for line in Path("/proc/meminfo").read_text().splitlines()
        for key, _, value in [line.partition(":")] if key in ("MemAvailable", "MemTotal")}
    docker_root = docker("info", "--format={{.DockerRootDir}}").decode().strip()
    require(memory["MemAvailable"] >= 12 * 1024 * 1024 and shutil.disk_usage(docker_root).free >= 20 << 30
        and shutil.disk_usage(task.parent).free >= 12 << 30, "Reviewed remote capacity floor unavailable")
    before = baseline()
    cluster_name = "sekvyr-stage7-" + task.name.split(".")[1]
    require(not docker("ps", "-a", "--filter=label=io.x-k8s.kind.cluster=" + cluster_name, "--format={{.ID}}").strip()
        and not docker("ps", "-a", "--filter=name=^/" + cluster_name + "-control-plane$", "--format={{.ID}}").strip(), "Exclusive kind cluster name already exists")
    image = json.loads(docker("image", "inspect", NODE))
    repository = NODE.split("@", 1)[0].rsplit(":", 1)[0] + "@" + NODE.split("@", 1)[1]
    require(len(image) == 1 and any(value in (repository, "docker.io/" + repository) for value in image[0].get("RepoDigests", [])), "Exact cached kind image required")
    private = root / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    directory(private)
    backup.mkdir(mode=0o700)  # Exclusive independent creator directory.
    task.mkdir(mode=0o700)  # Fresh reservation; never adopt another runtime.
    for folder in ("private", "tools"):
        (task / folder).mkdir(mode=0o700)
    for name, source in (("kind", kind), ("helm", helm), ("kubectl", kubectl)):
        save(task / "tools" / name, source.read_bytes(), 0o755)
    fixture = {"format": "sekvyr-stage7-fixture-v1", "production": False,
        "namespaces": {role: cluster_name + "-" + role for role in ROLES}}
    save(task / "private" / "fixture.json", canonical(fixture))
    preflight = {"format": "sekvyr-stage7-remote-kind-preflight-v1", "rootTask": str(root), "runtimeTask": str(task),
        "rootCreationReceiptSHA256": digest(root_receipt),
        "directories": [directory(path) for path in (root, task, backup)], "host": host(), "clusterName": cluster_name,
        "nodeImage": NODE, "limits": CAPS, "baseline": before, "toolSHA256": {"kind": kind_sha256, "helm": helm_sha256, "kubectl": kubectl_sha256}}
    save(backup / "preflight.json", canonical(preflight))  # BEFORE kind create.
    config = b"kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  apiServerAddress: 127.0.0.1\nnodes:\n  - role: control-plane\n"
    save(task / "cluster.yaml", config)
    run(["sudo", "-n", "env", "DOCKER_HOST=" + SOCKET, "KIND_EXPERIMENTAL_PROVIDER=docker", str(kind), "create", "cluster",
        "--name", cluster_name, "--image", NODE, "--config", str(task / "cluster.yaml"), "--kubeconfig", str(task / "kubeconfig"),
        "--wait", "180s", "--retain"], timeout=240)
    identifiers = docker("ps", "-a", "--filter=label=io.x-k8s.kind.cluster=" + cluster_name, "--format={{.ID}}").decode().split()
    require(len(identifiers) == 1, "Created kind node count differs")
    node = json.loads(docker("inspect", identifiers[0]))[0]
    require(node["Id"] not in before["containers"] and node["Config"]["Image"] == NODE and node["Image"] == image[0]["Id"]
        and node["Config"]["Labels"].get("io.x-k8s.kind.cluster") == cluster_name
        and node["Config"]["Labels"].get("io.x-k8s.kind.role") == "control-plane" and node["State"]["Running"] is True,
        "Post-create read differs from exclusive preflight and reviewed kind invocation")
    volumes = sorted(value["Name"] for value in node.get("Mounts", []) if value.get("Type") == "volume")
    require(volumes and all(name not in before["volumes"] for name in volumes) and set(node["NetworkSettings"]["Networks"]) == {"kind"}, "Created node storage/network differs")
    network = json.loads(docker("network", "inspect", node["NetworkSettings"]["Networks"]["kind"]["NetworkID"]))[0]
    require(set(network.get("Containers", {})) == {node["Id"]} and (before["kindNetwork"] is None or network["Id"] == before["kindNetwork"]["id"]
        and network_hash(network) == before["kindNetwork"]["configSHA256"]), "Created kind network differs from preflight")
    pin = {"id": node["Id"], "image": NODE, "volumes": volumes}
    created = {"format": "sekvyr-stage7-remote-kind-created-v1", "preflightSHA256": digest(canonical(preflight)), "node": pin,
        "nodeName": node["Name"], "configSHA256": digest(canonical(node["Config"])), "mountsSHA256": mounts_hash(node.get("Mounts", [])),
        "nodeOCIImageID": node["Image"], "process": process(node["State"]["Pid"]), "fixture": fixture,
        "network": {"id": network["Id"], "configSHA256": network_hash(network), "created": before["kindNetwork"] is None},
        "volumeSHA256": {name: digest(canonical(json.loads(docker("volume", "inspect", name))[0])) for name in volumes}}
    save(backup / "creation.json", canonical(created))  # Before caps OR CRDs.
    save(task / "private" / "node-pin.json", canonical(pin))
    # Repeat exact creation identity before the first own-container mutation.
    require(host() == preflight["host"] and process(node["State"]["Pid"]) == created["process"]
        and json.loads(docker("inspect", pin["id"]))[0]["Id"] == pin["id"], "Creator changed before cap mutation")
    docker("update", "--cpus=4", "--memory=8g", "--memory-swap=8g", pin["id"])
    capped = json.loads(docker("inspect", pin["id"]))[0]
    require(all(capped["HostConfig"].get(key) == expected for key, expected in CAPS.items()), "Own Docker resource limits did not apply")
    caps = {"format": "sekvyr-stage7-remote-kind-caps-v1", "creatorSHA256": digest(canonical(created)), "limits": CAPS,
        "hostConfigSHA256": digest(canonical(capped["HostConfig"]))}
    save(backup / "caps.json", canonical(caps))
    capability = {"format": FORMAT, "rootTask": str(root), "runtimeTask": str(task), "preflightSHA256": digest(canonical(preflight)),
        "creatorSHA256": digest(canonical(created)), "capsSHA256": digest(canonical(caps))}
    save(task / "private" / MARKER, canonical(capability))
    from types import SimpleNamespace
    owner = Capability(SimpleNamespace(task=task, fixture=fixture))
    kubeconfig = task / "kubeconfig"
    require(kubeconfig.resolve() == kubeconfig and kubeconfig.is_file() and not kubeconfig.is_symlink(), "Private kind kubeconfig identity differs")
    run(["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), str(kubeconfig)])
    kubeconfig.chmod(0o600)
    save(task / "kubectl", ("#!/bin/sh\nexec '" + str(task / "tools" / "kubectl") + "' \"$@\"\n").encode(), 0o755)
    client = [str(task / "kubectl"), "--kubeconfig", str(kubeconfig)]
    actual = json.loads(run(client + ["version", "-o", "json"]))
    require(actual["serverVersion"]["gitVersion"] == actual["clientVersion"]["gitVersion"] == "v1.37.0", "Exact remote kind API version differs")
    nodes = json.loads(run(client + ["get", "nodes", "-o", "json"]))["items"]
    require(len(nodes) == 1 and any(value.get("type") == "Ready" and value.get("status") == "True"
        for value in nodes[0].get("status", {}).get("conditions", [])), "One ready owned kind node required")
    crds = sorted(Path(crd_dir).glob("*.yaml"))
    require({source.name for source in crds} == {"sekvyrstores.secrets.sekvyr.ru.yaml", "sekvyrsecrets.secrets.sekvyr.ru.yaml"}, "Exactly two reviewed Sekvyr CRDs required")
    (task / "crds").mkdir(mode=0o700)
    pins = []
    for source in crds:
        require(source.resolve() == source and source.is_file() and not source.is_symlink() and source.stat().st_size <= 4 << 20, "Exact bounded reviewed CRD source required")
        raw = source.read_bytes()
        target = task / "crds" / source.name
        save(target, raw)
        owner.guard()
        value = json.loads(run(client + ["create", "-f", str(target), "-o", "json"]))
        require(value["kind"] == "CustomResourceDefinition" and value["metadata"]["name"] + ".yaml" == source.name, "Unexpected CRD create response")
        receipt = {"kind": value["kind"], "name": value["metadata"]["name"], "uid": value["metadata"]["uid"], "sourceSHA256": digest(raw)}
        save(task / "private" / ("initial-crd-" + source.name + ".json"), canonical(receipt))
        pins.append(receipt)
        run(client + ["wait", "--for=condition=Established", "crd/" + receipt["name"], "--timeout=60s"], timeout=70)
    save(task / "private" / "initial-crd-pins.json", canonical(pins))
    foreign_unchanged(before, pin["id"], network["Id"], volumes)
    save(task / "initial-admission-evidence.json", canonical({"remoteKind": True, "serverGitVersion": "v1.37.0", "creatorCIDPinnedBeforeCapsAndCRDs": True,
        "preexistingContainers": len(before["containers"]), "foreignConfigurationAndRunningStateUnchanged": True, "production": False}))
    return task


def cleanup(owner, execute=False):
    """Only actor-requested exact-CID cleanup, never kind delete by name."""
    owner.guard()
    before, created = owner.preflight["baseline"], owner.creator
    cid, network = owner.pin["id"], created["network"]
    foreign_unchanged(before, cid, network["id"], owner.pin["volumes"])
    for name, expected in created["volumeSHA256"].items():
        require(name not in before["volumes"] and digest(canonical(json.loads(docker("volume", "inspect", name))[0])) == expected,
            "Owned anonymous volume differs from its creation receipt")
        members = docker("ps", "-a", "--filter=volume=" + name, "--format={{.ID}}").decode().split()
        require(all(cid.startswith(value) for value in members), "Owned volume became shared")
    if not execute:
        return {"ownedCreatorValidated": True, "deleteRequested": False, "production": False}
    docker("rm", "-f", cid)
    for name, expected in created["volumeSHA256"].items():
        require(not docker("ps", "-a", "--filter=volume=" + name, "--format={{.ID}}").strip()
            and digest(canonical(json.loads(docker("volume", "inspect", name))[0])) == expected, "Volume changed or became shared before deletion")
        docker("volume", "rm", name)
    live = json.loads(docker("network", "inspect", network["id"]))[0]
    require(live["Id"] == network["id"] and not live.get("Containers") and network_hash(live) == network["configSHA256"],
        "Owned network changed or is shared; deletion refused")
    if network["created"]:
        require(network["id"] not in before["networks"], "Existing network cannot be deleted")
        docker("network", "rm", network["id"])
    else:
        require(digest(canonical(live)) == before["kindNetwork"]["fullSHA256"], "Original kind network did not return to exact baseline")
    foreign_unchanged(before)
    return {"ownContainerAndAnonymousVolumesRemoved": True, "onlyCreatedUnsharedNetworkRemoved": network["created"],
        "foreignBaselineUnchanged": True, "production": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    for name in ("root-task", "runtime-task", "kind-bin", "helm-bin", "kubectl-bin", "kind-sha256", "helm-sha256", "kubectl-sha256", "crd-dir"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(args.execute, "Explicit coordinator execution required")
    create(args.root_task, args.runtime_task, args.kind_bin, args.helm_bin, args.kubectl_bin, args.kind_sha256, args.helm_sha256, args.kubectl_sha256, args.crd_dir)
