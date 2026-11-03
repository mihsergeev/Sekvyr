#!/usr/bin/env python3
"""Create one explicitly approved local kind cluster; no global setup/reset."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

CLUSTER = "sekvyr-stage7"
NODE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
SOCKET = "unix:///var/run/docker.sock"
ROLES = ("apps", "isolation", "panel", "witness", "gateway", "storage")
FLOOR = 12 << 30


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, raw, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def run(argv, *, timeout=30, binary=False):
    try:
        result = subprocess.run(argv, text=not binary, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Stage7 local operation unavailable") from None
    if result.returncode:
        raise RuntimeError("Stage7 local operation failed")
    return result.stdout


def docker(*args, **kwargs):
    return run(["sudo", "-n", "docker", "--host=" + SOCKET, *args], **kwargs)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def baseline():
    # Raw inspect values may contain environment credentials. Persist hashes
    # only; never write their contents to disk, stdout or an exception.
    containers = {}
    for cid in docker("ps", "-a", "--format={{.ID}}").split():
        obj = json.loads(docker("inspect", cid))[0]
        containers[obj["Id"]] = digest({k: obj.get(k) for k in ("Config", "HostConfig", "Mounts")})
    volumes = {}
    for name in docker("volume", "ls", "--format={{.Name}}").split():
        volumes[name] = digest(json.loads(docker("volume", "inspect", name))[0])
    networks = docker("network", "ls", "--filter=name=^kind$", "--format={{.ID}}").split()
    if len(networks) != 1:
        raise RuntimeError("Expected one existing kind network; refusing provider network mutation")
    network = json.loads(docker("network", "inspect", networks[0]))[0]
    if network.get("Containers"):
        raise RuntimeError("Existing kind network is occupied")
    return {"containers": containers, "volumes": volumes,
        "kindNetworkID": network["Id"], "kindNetworkHash": digest(network)}


def capacity():
    if not Path("/mnt/c").is_dir():
        raise RuntimeError("Windows backing capacity cannot be checked")
    backing, linux = shutil.disk_usage("/mnt/c").free, shutil.disk_usage("/var/tmp").free
    mem = {k: int(v.split()[0]) for line in Path("/proc/meminfo").read_text().splitlines()
        for k, _, v in [line.partition(":")] if k in ("MemAvailable", "MemTotal")}
    if min(backing, linux) < FLOOR or mem["MemAvailable"] < 5 * 1024 * 1024:
        raise RuntimeError("Stage7 reserved local capacity floor unavailable")
    return {"windowsBackingFreeBytes": backing, "linuxFreeBytes": linux,
        "availableMemoryKiB": mem["MemAvailable"]}


def download(url, maximum):
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(maximum + 1)
    if not raw or len(raw) > maximum:
        raise RuntimeError("Official tool download bounds invalid")
    return raw


def install_tool(task, name, url, checksum_url, member=None):
    raw = download(url, 100 << 20)
    checksum = download(checksum_url, 4096).decode("ascii").split()[0]
    if len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum) or hashlib.sha256(raw).hexdigest() != checksum:
        raise RuntimeError("Official tool checksum mismatch")
    if member:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            info = archive.getmember(member)
            if not info.isfile() or info.size > 100 << 20:
                raise RuntimeError("Official tool archive shape invalid")
            raw = archive.extractfile(info).read()
    save(task / "tools" / name, raw, 0o755)
    save(task / "private" / (name + "-download-proof.json"), canonical({"url": url, "archiveSHA256": checksum}))
    return task / "tools" / name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--crd-dir", type=Path, required=True)
    parser.add_argument("--receipt-backup-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.execute:
        raise RuntimeError("Coordinator approval and explicit execute required")
    before_capacity = capacity()
    before = baseline()
    if docker("ps", "-a", "--filter=label=io.x-k8s.kind.cluster=" + CLUSTER, "--format={{.ID}}").strip():
        raise RuntimeError("Named isolated cluster already exists; no reuse or replacement")
    inspect = json.loads(docker("image", "inspect", NODE))[0]
    if not any("@" + NODE.split("@", 1)[1] in item for item in inspect.get("RepoDigests", [])):
        raise RuntimeError("Cached official node digest unavailable")
    backup = args.receipt_backup_dir.absolute()
    if backup.resolve() != backup or not backup.is_dir() or backup.is_symlink():
        raise RuntimeError("Exact native receipt backup directory required")
    task = Path(tempfile.mkdtemp(prefix="sekvyr-stage7.", dir="/var/tmp"))
    task.chmod(0o700)
    (task / "private").mkdir(mode=0o700)
    (task / "tools").mkdir(mode=0o700)
    save(task / "private" / "docker-baseline.json", canonical(before))
    save(task / "private" / "capacity-before.json", canonical(before_capacity))
    print(json.dumps({"taskDirectory": str(task), "phase": "reserved", "production": False}), flush=True)
    prefix = "sekvyr-stage7-" + task.name.rsplit(".", 1)[1].lower().replace("_", "-")
    save(task / "private" / "fixture.json", canonical({"format": "sekvyr-stage7-fixture-v1",
        "production": False, "namespaces": {role: prefix + "-" + role for role in ROLES}}))
    kind = install_tool(task, "kind", "https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64",
        "https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64.sha256sum")
    helm = install_tool(task, "helm", "https://get.helm.sh/helm-v4.3.1-linux-amd64.tar.gz",
        "https://get.helm.sh/helm-v4.3.1-linux-amd64.tar.gz.sha256sum", "linux-amd64/helm")
    if not run([str(kind), "version"]).startswith("kind v0.33.0") or not run([str(helm), "version", "--short"]).startswith("v4.3.1"):
        raise RuntimeError("Private tool version mismatch")
    config = b"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: 127.0.0.1
kubeadmConfigPatches:
  - |
    kind: KubeletConfiguration
    failCgroupV1: false
nodes:
  - role: control-plane
"""
    save(task / "cluster.yaml", config)
    print(json.dumps({"taskDirectory": str(task), "phase": "prepared", "production": False}), flush=True)
    run(["sudo", "-n", "env", "DOCKER_HOST=" + SOCKET, "KIND_EXPERIMENTAL_PROVIDER=docker", str(kind),
        "create", "cluster", "--name", CLUSTER, "--image", NODE, "--config", str(task / "cluster.yaml"),
        "--kubeconfig", str(task / "kubeconfig"), "--wait", "180s", "--retain"], timeout=240)
    nodes = docker("ps", "-a", "--filter=label=io.x-k8s.kind.cluster=" + CLUSTER, "--format={{.ID}}").split()
    if len(nodes) != 1:
        raise RuntimeError("Isolated cluster node count invalid")
    obj = json.loads(docker("inspect", nodes[0]))[0]
    if obj["Config"]["Labels"].get("io.x-k8s.kind.cluster") != CLUSTER or obj["Config"]["Image"] != NODE:
        raise RuntimeError("Created node identity mismatch")
    pin = {"id": obj["Id"], "image": NODE,
        "volumes": [x["Name"] for x in obj.get("Mounts", []) if x.get("Type") == "volume"]}
    save(task / "private" / "node-pin.json", canonical(pin))
    # Native metadata backup contains no kubeconfig or raw environment/spec.
    native_receipt = backup / (task.name + "-receipts.json")
    save(native_receipt, canonical({"taskDirectory": str(task), "node": pin,
        "baseline": before, "fixture": json.loads((task / "private" / "fixture.json").read_bytes())}))
    save(task / "private" / "native-backup-reference.json", canonical({"path": str(native_receipt)}))
    from finish import finish
    print(json.dumps(finish(task, args.crd_dir)), flush=True)


if __name__ == "__main__":
    main()
