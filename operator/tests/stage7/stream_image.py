#!/usr/bin/env python3
"""Hash an approved SSH image stream into only the creation-pinned kind node."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from prepare import CLUSTER, NODE, SOCKET, canonical, capacity, docker, save


def node(task):
    task = Path(task).absolute()
    if task.parent != Path("/var/tmp") or task.resolve() != task or not re.fullmatch(r"sekvyr-stage7\.[A-Za-z0-9_-]+", task.name):
        raise RuntimeError("Unreviewed streaming task root")
    pin = json.loads((task / "private" / "node-pin.json").read_bytes())
    obj = json.loads(docker("inspect", pin["id"]))[0]
    if obj["Id"] != pin["id"] or obj["Config"]["Image"] != NODE or pin["image"] != NODE or obj["Config"]["Labels"].get("io.x-k8s.kind.cluster") != CLUSTER or not obj["State"]["Running"]:
        raise RuntimeError("Creation-pinned streaming node unavailable")
    return pin["id"]


def normalize_import_refs(task, image):
    """CRI normalizes bare ctr import names; retain their exact verified targets."""
    cid = node(task)
    target = image.split("@", 1)[1]
    raw = docker("exec", cid, "ctr", "-n", "k8s.io", "content", "get", target, binary=True)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != target:
        raise RuntimeError("Import parent manifest changed")
    manifest = json.loads(raw)
    allowed = {target}
    if "manifests" in manifest:
        children = [item for item in manifest["manifests"] if item.get("platform", {}).get("os") == "linux"
            and item.get("platform", {}).get("architecture") == "amd64"]
        if len(children) != 1:
            raise RuntimeError("Imported amd64 platform descriptor is not unique")
        child = children[0]["digest"]
        payload = docker("exec", cid, "ctr", "-n", "k8s.io", "content", "get", child, binary=True)
        if "sha256:" + hashlib.sha256(payload).hexdigest() != child:
            raise RuntimeError("Imported platform content changed")
        allowed.add(child)
    raw = docker("exec", cid, "ctr", "-n", "k8s.io", "images", "list")
    rows = [line.split() for line in raw.splitlines()[1:] if line.split()]
    count = 0
    for row in rows:
        if len(row) < 3 or not re.fullmatch(r"import-[0-9]{4}-[0-9]{2}-[0-9]{2}@sha256:[0-9a-f]{64}", row[0]):
            continue
        if row[2] not in allowed:
            # ctr also retains the archive's outer index. It is accepted only
            # if its sole descriptor is this independently pinned image/root.
            wrapper_raw = docker("exec", cid, "ctr", "-n", "k8s.io", "content", "get", row[2], binary=True)
            if "sha256:" + hashlib.sha256(wrapper_raw).hexdigest() != row[2]:
                raise RuntimeError("Archive wrapper content changed")
            wrapper = json.loads(wrapper_raw)
            descriptors = wrapper.get("manifests", [])
            if len(descriptors) != 1 or descriptors[0].get("digest") not in allowed:
                continue
        if row[0].split("@", 1)[1] != row[2]:
            raise RuntimeError("Bare import reference has an unexpected target")
        normalized = "docker.io/library/" + row[0]
        matches = [r for r in rows if r[0] == normalized]
        if matches:
            if len(matches) != 1 or matches[0][2] != row[2]:
                raise RuntimeError("Normalized CRI import alias has a different target")
        else:
            docker("exec", cid, "ctr", "-n", "k8s.io", "images", "tag", row[0], normalized)
            count += 1
    return count


def transfer(task, host, port, remote_file, expected_sha, expected_bytes, image, label):
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", host) or not 1 <= port <= 65535:
        raise ValueError("Explicit SSH endpoint required")
    if not re.fullmatch(r"/opt/sekvyr-trial/sekvyr-stage[67]-[0-9]{8}-[0-9a-f]{8}/(?:out|exports)/[a-z0-9-]+\.tar", remote_file):
        raise ValueError("Only reviewed trial image export paths may stream")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha) or not 0 < expected_bytes <= 4 << 30:
        raise ValueError("Explicit bounded image archive digest and size required")
    if not re.fullmatch(r"[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}", image) or not re.fullmatch(r"[a-z0-9-]{1,50}", label):
        raise ValueError("Explicit canonical image and evidence label required")
    task = Path(task)
    cid = node(task)
    capacity()
    source = subprocess.Popen(["ssh", "-p", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", host, "cat", remote_file],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        importer = subprocess.Popen(["sudo", "-n", "docker", "--host=" + SOCKET, "exec", "-i", cid,
            "ctr", "-n", "k8s.io", "images", "import", "--digests", "--platform", "linux/amd64", "-"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except BaseException:
        source.terminate()
        source.wait(timeout=5)
        raise
    count, h = 0, hashlib.sha256()
    try:
        while True:
            raw = source.stdout.read(1 << 20)
            if not raw:
                break
            count += len(raw)
            if count > expected_bytes:
                raise RuntimeError("Image stream exceeds reviewed size")
            h.update(raw)
            importer.stdin.write(raw)
        importer.stdin.close()
        if source.wait(timeout=20) or importer.wait(timeout=180):
            raise RuntimeError("Bounded image transport/import failed")
        if count != expected_bytes or h.hexdigest() != expected_sha:
            raise RuntimeError("Raw image stream checksum mismatch; no acceptance")
    finally:
        for process in (source, importer):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    cid = node(task)
    target = image.split("@", 1)[1]
    raw = docker("exec", cid, "ctr", "-n", "k8s.io", "content", "get", target, binary=True)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != target:
        raise RuntimeError("Imported immutable manifest SHA mismatch")
    listing = docker("exec", cid, "ctr", "-n", "k8s.io", "images", "list")
    rows = [line.split() for line in listing.splitlines()[1:] if line.split()]
    existing = [r for r in rows if r[0] == image]
    if existing:
        if len(existing) != 1 or existing[0][2] != target:
            raise RuntimeError("Canonical import alias has a different target")
    else:
        candidates = sorted(r[0] for r in rows if len(r) >= 3 and r[2] == target)
        if not candidates:
            raise RuntimeError("Verified imported manifest lacks a retained image reference")
        docker("exec", cid, "ctr", "-n", "k8s.io", "images", "tag", candidates[0], image)
    listing = docker("exec", cid, "ctr", "-n", "k8s.io", "images", "list", "name==" + json.dumps(image))
    rows = [r.split() for r in listing.splitlines()[1:] if r.split() and r.split()[0] == image]
    if len(rows) != 1 or rows[0][2] != target:
        raise RuntimeError("Final canonical image reference is not unique/exact")
    normalize_import_refs(task, image)
    capacity()
    proof = {"rawArchiveSHA256": expected_sha, "archiveBytes": count, "image": image,
        "manifestSHA256Verified": True, "importedIntoCreationPinnedKindNode": True, "localTarWritten": False,
        "production": False, "baselineOnly": label == "operator-baseline"}
    save(task / "private" / ("image-transfer-" + label + ".json"), canonical(proof))
    return {k: v for k, v in proof.items() if k != "image"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--remote-file", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--bytes", type=int, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    print(json.dumps(transfer(args.task_dir, args.host, args.port, args.remote_file, args.sha256,
        args.bytes, args.image, args.label)), flush=True)
