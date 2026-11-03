"""Fresh Stage 8 native kind creation. No work on import; no asset importer."""

import json
from pathlib import Path
from types import FunctionType

from app_modes import require
from fixture import canonical
from .profiles import PROFILE_RECEIPT, receipt, reviewed
from .capability import Capability
import remote_kind_capability as cap
import prepare_remote_kind as legacy

def _create_template(root_task, runtime_task, kind_binary, helm_binary, kubectl_binary, kind_sha256, helm_sha256, kubectl_sha256, crd_dir):
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
    kubectl = reviewed_tool(root, kubectl_binary, kubectl_sha256, EXPECTED_VERSION)
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
        "stage8ProfileSHA256": STAGE8_PROFILE_SHA256,
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
    require(actual["serverVersion"]["gitVersion"] == actual["clientVersion"]["gitVersion"] == EXPECTED_VERSION, "Exact remote kind API version differs")
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
    save(task / "initial-admission-evidence.json", canonical({"remoteKind": True, "serverGitVersion": EXPECTED_VERSION, "creatorCIDPinnedBeforeCapsAndCRDs": True,
        "preexistingContainers": len(before["containers"]), "foreignConfigurationAndRunningStateUnchanged": True, "production": False}))
    return task

def create(profile, root_task, runtime_task, kind_binary, helm_binary, kubectl_binary,
        kind_sha256, helm_sha256, kubectl_sha256, crd_dir):
    selected, artifacts = reviewed(profile)  # Unset pins reject BEFORE any read/action.
    require(hasattr(legacy.os, "geteuid") and legacy.os.geteuid() == 0
        and hasattr(legacy.os, "uname") and legacy.os.uname().sysname == "Linux"
        and legacy.os.uname().machine == "x86_64", "Root Linux amd64 creator required")
    legacy.runtime_capabilities()
    root, task, backup = cap.paths(root_task, runtime_task)
    cap.directory(root)
    original, _ = cap.root_creation(root, task)
    require(not task.exists() and not task.is_symlink()
        and not backup.exists() and not backup.is_symlink(),
        "Only an exclusive fresh Stage 8 creator is accepted")
    value = receipt(selected, artifacts, root, task, cap.digest(original))
    profile_raw = canonical(value)
    legacy.save(root / "receipts" / PROFILE_RECEIPT, profile_raw)
    scope = dict(legacy.create.__globals__, NODE=selected.node, EXPECTED_VERSION=selected.version,
        STAGE8_PROFILE_SHA256=cap.digest(profile_raw),
        Capability=lambda cluster: Capability(cluster, profile=selected.name))
    operation = FunctionType(_create_template.__code__, scope)
    return operation(root, task, kind_binary, helm_binary, kubectl_binary,
        kind_sha256, helm_sha256, kubectl_sha256, crd_dir)

def cleanup(owner, *, execute=False):
    require(type(owner) is Capability, "Explicit Stage 8 capability required")
    owner.guard()
    return legacy.cleanup(owner, execute=execute)

def verify_asset_map(assets):
    """Pure map validation only; it never imports, pulls, tags or runs images."""
    expected = reviewed_artifacts_for_assets()
    require(type(assets) is dict and assets == expected, "Exact reviewed Stage 8 assets required")
    return {"sourceStage": 8, "production": False, "imported": False}

def reviewed_artifacts_for_assets():
    from .profiles import reviewed_artifacts
    return reviewed_artifacts()
