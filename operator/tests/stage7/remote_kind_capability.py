"""Explicit same-host Linux kind capability; never infer ownership by name."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from app_modes import require
from fixture import canonical
from prepare import NODE, SOCKET, ROLES

FORMAT = "sekvyr-stage7-remote-kind-v1"
CAPS = {"NanoCpus": 4_000_000_000, "Memory": 8 << 30, "MemorySwap": 8 << 30}
MARKER = "remote-kind-capability.json"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def docker(*args, data=None, timeout=30):
    try:
        result = subprocess.run(["sudo", "-n", "/usr/bin/docker", "--host=" + SOCKET, *args], input=data,
            capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Remote kind Docker operation unavailable") from None
    require(result.returncode == 0 and len(result.stdout) <= 8 << 20, "Remote kind Docker operation rejected")
    return result.stdout


def read(path, maximum=8 << 20):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
        and path.stat().st_size <= maximum and path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o600, "Exact private remote kind receipt required")
    raw = path.read_bytes()
    value = json.loads(raw)
    require(raw == canonical(value), "Remote kind receipt encoding changed")
    return raw, value


def directory(path):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "Exact private remote kind directory required")
    return {"path": str(path), "uid": info.st_uid, "dev": info.st_dev, "ino": info.st_ino}


def paths(root, runtime):
    root, runtime = Path(root), Path(runtime)
    require(root.parent == Path("/opt/sekvyr-trial") and re.fullmatch(r"sekvyr-stage7-[0-9]{8}-[0-9a-f]{8}", root.name)
        and runtime.parent == Path("/var/tmp") and re.fullmatch(r"sekvyr-stage7\.[0-9a-f]{8}", runtime.name), "Explicit remote kind root/runtime pair required")
    return root, runtime, root / "private" / "creator"


def root_creation(root, runtime):
    path = root / "receipts" / "root-task-create.json"
    info = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
        and stat.S_IMODE(info.st_mode) in (0o600, 0o644) and info.st_size <= 8192,
        "Explicit root task CREATE receipt required")
    raw = path.read_bytes()
    value = json.loads(raw)
    actual = root.lstat()
    require(set(value) == {"format", "path", "uid", "gid", "dev", "ino", "mode", "stage", "runtimeProposed", "containerCreated", "production"}
        and value["format"] == "sekvyr-stage7-root-task-creation-v1" and value["path"] == str(root)
        and value["runtimeProposed"] == str(runtime) and value["uid"] == value["gid"] == actual.st_uid == actual.st_gid == 0
        and (value["dev"], value["ino"]) == (actual.st_dev, actual.st_ino) and value["mode"] == "0700"
        and stat.S_IMODE(actual.st_mode) == 0o700 and value["containerCreated"] is False and value["production"] is False,
        "Root task differs from the independent creation receipt")
    return raw, value


def host():
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(re.fullmatch(r"[0-9a-f-]{36}", boot), "Remote host boot identity unavailable")
    return {"bootID": boot, "daemonIDHash": digest(docker("info", "--format={{.ID}}").strip())}


def process(pid):
    require(type(pid) is int and pid > 1, "Owned kind PID unavailable")
    fields = Path("/proc/" + str(pid) + "/stat").read_text().rsplit(")", 1)[-1].split()
    require(len(fields) > 19 and fields[19].isdigit() and fields[0] not in ("Z", "X"), "Owned kind process unavailable")
    return {"pid": pid, "starttime": fields[19]}


def network_hash(value):
    return digest(canonical({key: item for key, item in value.items() if key != "Containers"}))


def mounts_hash(value):
    return digest(canonical(sorted(value, key=canonical)))


def container_snapshot(value):
    # Keep every Config/Env/HostConfig/Mount field. Only Mounts is a set-like
    # Docker map projected as an unstable array; normalize its order, not data.
    configuration = {key: value.get(key) for key in ("Image", "Path", "Args", "Config", "HostConfig")}
    configuration["Mounts"] = sorted(value.get("Mounts", []), key=canonical)
    configuration["Networks"] = value["NetworkSettings"]["Networks"]
    return {"configurationSHA256": digest(canonical(configuration)), "running": value["State"]["Running"],
        "restartCount": value["RestartCount"], "startedAt": value["State"]["StartedAt"]}


def node_identity(value, preflight, creator, caps, image):
    pin = creator["node"]
    require(re.fullmatch(r"[0-9a-f]{64}", pin["id"]) and pin["id"] not in preflight["baseline"]["containers"]
        and pin["image"] == NODE and value["Id"] == pin["id"] and value["Config"]["Image"] == NODE
        and value["Config"].get("Labels", {}).get("io.x-k8s.kind.cluster") == preflight["clusterName"]
        and value["Config"].get("Labels", {}).get("io.x-k8s.kind.role") == "control-plane"
        and value["State"].get("Running") is True and value["State"].get("Pid") == creator["process"]["pid"], "Remote kind creator identity changed")
    require(caps["limits"] == CAPS and all(type(value["HostConfig"].get(key)) is int and value["HostConfig"][key] == expected for key, expected in CAPS.items()),
        "Remote kind reviewed resource limits changed")
    require(value["Name"] == creator["nodeName"] and digest(canonical(value["Config"])) == creator["configSHA256"]
        and mounts_hash(value.get("Mounts", [])) == creator["mountsSHA256"]
        and digest(canonical(value["HostConfig"])) == caps["hostConfigSHA256"], "Remote kind captured configuration changed")
    repository = NODE.split("@", 1)[0].rsplit(":", 1)[0] + "@" + NODE.split("@", 1)[1]
    require(len(image) == 1 and image[0]["Id"] == creator["nodeOCIImageID"] == value["Image"]
        and any(item in (repository, "docker.io/" + repository) for item in image[0].get("RepoDigests", [])), "Remote kind OCI image changed")
    require(sorted(item["Name"] for item in value.get("Mounts", []) if item.get("Type") == "volume") == sorted(pin["volumes"])
        and set(value["NetworkSettings"]["Networks"]) == {"kind"}
        and value["NetworkSettings"]["Networks"]["kind"]["NetworkID"] == creator["network"]["id"], "Remote kind volume/network membership changed")


class Capability:
    def __init__(self, cluster):
        self.cluster, self.task = cluster, Path(cluster.task)
        self.marker = self.task / "private" / MARKER
        self.raw, self.value = read(self.marker)
        cap = self.value
        require(set(cap) == {"format", "rootTask", "runtimeTask", "preflightSHA256", "creatorSHA256", "capsSHA256"}
            and cap["format"] == FORMAT and cap["runtimeTask"] == str(self.task), "Explicit remote kind capability required")
        self.root, runtime, self.backup = paths(cap["rootTask"], cap["runtimeTask"])
        self.preflight_raw, self.preflight = read(self.backup / "preflight.json")
        self.creator_raw, self.creator = read(self.backup / "creation.json")
        self.caps_raw, self.caps = read(self.backup / "caps.json")
        require(digest(self.preflight_raw) == cap["preflightSHA256"] == self.creator["preflightSHA256"]
            and digest(self.creator_raw) == cap["creatorSHA256"] == self.caps["creatorSHA256"]
            and digest(self.caps_raw) == cap["capsSHA256"], "Remote kind creation receipt chain changed")
        require(self.preflight["format"] == "sekvyr-stage7-remote-kind-preflight-v1"
            and self.creator["format"] == "sekvyr-stage7-remote-kind-created-v1"
            and self.caps["format"] == "sekvyr-stage7-remote-kind-caps-v1"
            and self.preflight["runtimeTask"] == str(runtime) and self.preflight["rootTask"] == str(self.root)
            and self.preflight["clusterName"] == "sekvyr-stage7-" + runtime.name.split(".")[1]
            and self.preflight["nodeImage"] == NODE and self.preflight["limits"] == CAPS
            and self.creator["fixture"]["namespaces"] == cluster.fixture["namespaces"], "Remote kind creator scope differs")
        require(self.creator["fixture"].get("format") == "sekvyr-stage7-fixture-v1" and self.creator["fixture"].get("production") is False
            and self.creator["fixture"]["namespaces"] == {role: self.preflight["clusterName"] + "-" + role for role in ROLES},
            "Remote kind must retain its six exact reserved namespaces")
        require(digest(root_creation(self.root, self.task)[0]) == self.preflight["rootCreationReceiptSHA256"], "Root CREATE receipt changed")
        self.pin_file = self.task / "private" / "node-pin.json"
        self.pin_raw, pin = read(self.pin_file)
        require(pin == self.creator["node"], "Runtime node pin differs from independent creator receipt")
        self.pin = pin
        self.guard()

    def guard(self):
        require(self.marker.read_bytes() == self.raw and not self.marker.is_symlink(), "Remote kind capability changed")
        for name, raw in (("preflight.json", self.preflight_raw), ("creation.json", self.creator_raw), ("caps.json", self.caps_raw)):
            current, _ = read(self.backup / name)
            require(current == raw, "Remote kind creator receipt changed")
        require(read(self.pin_file)[0] == self.pin_raw and self.preflight["host"] == host(), "Remote kind host/daemon or node pin changed")
        require(digest(root_creation(self.root, self.task)[0]) == self.preflight["rootCreationReceiptSHA256"], "Root CREATE receipt changed")
        require(self.preflight["directories"] == [directory(path) for path in (self.root, self.task, self.backup)], "Remote kind directory identity changed")
        nodes = json.loads(docker("inspect", self.pin["id"]))
        require(len(nodes) == 1, "One exact creator-pinned kind node required")
        node_identity(nodes[0], self.preflight, self.creator, self.caps, json.loads(docker("image", "inspect", NODE)))
        require(process(nodes[0]["State"]["Pid"]) == self.creator["process"], "Remote kind PID/starttime changed")
        network = json.loads(docker("network", "inspect", self.creator["network"]["id"]))
        require(len(network) == 1 and network[0]["Id"] == self.creator["network"]["id"]
            and network_hash(network[0]) == self.creator["network"]["configSHA256"]
            and set(network[0].get("Containers", {})) == {self.pin["id"]}, "Remote kind network changed or became shared")
        return nodes[0]

    def exec(self, *args, data=None):
        self.guard()
        return docker("exec", *(["-i"] if data is not None else []), self.pin["id"], *args, data=data)

    def root_plan(self):
        return {"capabilityPath": str(self.marker), "capabilitySHA256": digest(self.raw),
            "preflightPath": str(self.backup / "preflight.json"), "preflightSHA256": digest(self.preflight_raw),
            "creatorPath": str(self.backup / "creation.json"), "creatorSHA256": digest(self.creator_raw),
            "capsPath": str(self.backup / "caps.json"), "capsSHA256": digest(self.caps_raw),
            "nodePinPath": str(self.pin_file), "nodePinSHA256": digest(self.pin_raw)}
