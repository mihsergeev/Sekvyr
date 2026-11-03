"""Fresh read-only proof after an external desktop interruption; no regeneration."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time

from coordinator import Coordinator
from fixture import canonical, safe_task, write_private
from forward import Forward
from gateway_probe import clients, framed
from infrastructure import BudgetCluster
from journal_client import JournalClient
from prepare import docker
from protocol import ProtocolAuthority


def check(task, keepalive_pid, keepalive_label):
    task = safe_task(task)
    reference = json.loads((task / "private" / "native-backup-reference.json").read_bytes())
    native = json.loads(Path(reference["path"]).read_bytes())
    pin = json.loads((task / "private" / "node-pin.json").read_bytes())
    obj = json.loads(docker("inspect", pin["id"]))[0]
    if native["taskDirectory"] != str(task) or native["node"] != pin or obj["Id"] != pin["id"] or obj["Config"]["Image"] != pin["image"] or obj["Config"]["Labels"].get("io.x-k8s.kind.cluster") != "sekvyr-stage7" or not obj["State"]["Running"]:
        raise RuntimeError("Native creator identity not retained")
    base = native["baseline"]
    for cid, expected in base["containers"].items():
        current = json.loads(docker("inspect", cid))[0]
        actual = hashlib.sha256(canonical({key: current.get(key) for key in ("Config", "HostConfig", "Mounts")})).hexdigest()
        if actual != expected:
            raise RuntimeError("Foreign Docker static configuration changed")
    for name, expected in base["volumes"].items():
        if hashlib.sha256(canonical(json.loads(docker("volume", "inspect", name))[0])).hexdigest() != expected:
            raise RuntimeError("Preexisting Docker volume metadata changed")
    network = json.loads(docker("network", "inspect", base["kindNetworkID"]))[0]
    if network["Id"] != base["kindNetworkID"] or network.get("Name") != "kind" or network.get("Driver") != "bridge" or set(network.get("Containers", {})) != {pin["id"]}:
        raise RuntimeError("Preexisting kind network identity or attachments changed outside this trial")
    cluster = BudgetCluster(task)
    counts = {"Namespace": 0, "PersistentVolumeClaim": 0, "CustomResourceDefinition": 0}
    for file in cluster.pins.glob("*.json"):
        p = json.loads(file.read_bytes())
        if p["kind"] not in counts:
            continue
        args = ["get", p["kind"], p["name"], "-o", "json"]
        if p["namespace"]:
            args += ["-n", p["namespace"]]
        current = json.loads(cluster.kube(*args).stdout)
        if current["metadata"]["uid"] != p["uid"] or current["metadata"].get("deletionTimestamp"):
            raise RuntimeError("Creator-pinned trial API resource replaced")
        counts[p["kind"]] += 1
    if counts != {"Namespace": 6, "PersistentVolumeClaim": 3, "CustomResourceDefinition": 2}:
        raise RuntimeError("Expected complete foundation creation pins unavailable")
    node = json.loads(cluster.kube("get", "nodes", "-o", "json").stdout)["items"]
    if len(node) != 1 or not any(x.get("type") == "Ready" and x.get("status") == "True" for x in node[0]["status"].get("conditions", [])):
        raise RuntimeError("Control plane node is not ready")
    epoch = time.time()
    boot_epoch = epoch - float(Path("/proc/uptime").read_text().split()[0])
    created = datetime.fromisoformat(node[0]["metadata"]["creationTimestamp"].replace("Z", "+00:00")).timestamp()
    if created >= boot_epoch:
        raise RuntimeError("Node object does not predate the desktop interruption")
    observation = task / "private" / "post-interruption-node.json"
    if not observation.exists():
        write_private(observation, canonical({"uid": node[0]["metadata"]["uid"], "provenance": "post-interruption-observation"}))
    elif json.loads(observation.read_bytes())["uid"] != node[0]["metadata"]["uid"]:
        raise RuntimeError("Post-interruption node observation changed")
    deployments = 0
    for role, names in (("storage", ("storage",)), ("gateway", ("journal",)), ("witness", ("witness-a", "witness-b")), ("panel", ("database", "panel"))):
        for name in names:
            cluster.kube("-n", cluster.fixture["namespaces"][role], "rollout", "status", "deployment/" + name, "--timeout=180s")
            deployments += 1
    protocol = ProtocolAuthority.load(task)
    with Forward(cluster, cluster.fixture["namespaces"]["gateway"], "service/journal", 8443) as forward:
        admin = clients(task, forward.origin)["admin"]
        for entry in [{"record": protocol.genesis_record, "registration": protocol.registration}, *protocol.fault_logs.values()]:
            nonce, (_, raw, _) = admin.journal(entry["registration"]["log_id"])
            slots = framed(raw, nonce, entry["registration"]["genesis_hash"])
            if len(slots) != 1 or slots[0]["record"] != entry["record"]:
                raise RuntimeError("Retained canonical genesis differs after interruption")
            receipt = slots[0]["receipt"]
            until = datetime.fromisoformat(receipt["retain_until"].replace("Z", "+00:00"))
            if receipt["mode"] != "COMPLIANCE" or not receipt["version_id"] or until <= datetime.now(timezone.utc):
                raise RuntimeError("Current retained genesis version invalid")
    if not (task / "private" / "panel-vault-key.json").is_file():
        raise RuntimeError("Existing private panel recovery material missing")
    coordinator = Coordinator(task)
    try:
        current = coordinator.current()
        if current["genesis_hash"] != protocol.genesis_hash or current["authority"] != protocol.authority:
            raise RuntimeError("Witness canonical authority changed during interruption")
        coordinator.panel.connect()
        coordinator.panel.login()
        _, status = coordinator.panel.owner_request("GET", "/api/vault/status")
        if not status["initialized"]:
            raise RuntimeError("Panel data state was lost; initialization is forbidden")
        coordinator.panel.unseal()
    finally:
        coordinator.close()
    proc = Path("/proc") / str(keepalive_pid)
    command = proc.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    if command[-1] != keepalive_label or "time.sleep(21600)" not in command[-2] or proc.stat().st_uid != os.getuid():
        raise RuntimeError("Owned long-lived keepalive identity changed")
    start = int(proc.joinpath("stat").read_text().split(")", 1)[1].split()[19]) / os.sysconf("SC_CLK_TCK")
    expiry = boot_epoch + start + 21600
    if expiry - epoch < 1800:
        raise RuntimeError("Owned keepalive remaining budget too short")
    write_private(task / "private" / "keepalive-receipt.json", canonical({"pid": keepalive_pid, "label": keepalive_label,
        "bootID": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "startTicksSeconds": start, "expiryEpoch": expiry}))
    result = {"creatorControlPlaneContainerRetained": True, "sameNamespaceUIDs": 6, "samePVCUIDs": 3, "sameCRDUIDs": 2,
        "readyFoundationDeployments": deployments, "nodeObjectPredatesCurrentBoot": True,
        "directPreviousNodeUIDComparisonAvailable": False, "exactRetainedGenesisReplay": True,
        "currentVersionAndComplianceRetentionVerified": True, "panelDataInitializedExistingKeyUnsealed": True,
        "foreignDockerStaticConfigurationUnchanged": True, "continuousDesktopUptimeClaimed": False,
        "preexistingNetworkIDRetainedOnlyOwnAttachment": True, "fullNetworkHashComparisonDeferredUntilCleanup": True,
        "keepaliveRemainingAtLeastSeconds": 1800, "production": False}
    write_private(task / "foundation-resume-evidence.json", canonical(result))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--keepalive-pid", type=int, required=True)
    parser.add_argument("--keepalive-label", required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.task_dir, args.keepalive_pid, args.keepalive_label)), flush=True)
