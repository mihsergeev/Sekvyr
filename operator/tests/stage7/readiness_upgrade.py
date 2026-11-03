"""Native Helm change limited to fencer probe timing, then observed stability."""

import copy
import json
from pathlib import Path
import shutil
import time

from app_modes import require, wait
from application import TARGET, REVISION
from e2e_cases import replicas_current
from fixture import canonical, write_private
from helm_lifecycle import identity


def review_diff(before, after):
    left, right = ({identity(value): value for value in values} for values in (before, after))
    require(set(left) == set(right), "Readiness upgrade changed the resource identities")
    changed = 0
    for key, old in left.items():
        expected = copy.deepcopy(old)
        if old["kind"] == "Deployment" and old["metadata"]["name"] == "stage6-fencer":
            containers = expected["spec"]["template"]["spec"]["containers"]
            require(len(containers) == 1 and containers[0]["readinessProbe"].get("timeoutSeconds", 1) == 1,
                "Readiness upgrade requires the exact original one-second timeout")
            containers[0]["readinessProbe"].update(timeoutSeconds=10, periodSeconds=10, failureThreshold=3, successThreshold=1)
            containers[0]["livenessProbe"].update(timeoutSeconds=1, periodSeconds=10, failureThreshold=3, successThreshold=1)
            changed += 1
        require(expected == right[key], "Readiness upgrade changes another manifest or probe policy")
    require(changed == 1, "Readiness upgrade requires exactly the captured fencer Deployment")


def _processes(e):
    values = {}
    for role in ("operator", "fencer"):
        deployment = e.app.get("Deployment", "stage6-" + role)
        labels = ",".join(key + "=" + value for key, value in sorted(deployment["spec"]["selector"]["matchLabels"].items()))
        sets = json.loads(e.c.cluster.kube("get", "replicasets", "-n", e.app.namespace, "-l", labels, "-o", "json").stdout)["items"]
        require(all(any(ref.get("kind") == "Deployment" and ref.get("uid") == deployment["metadata"]["uid"] for ref in item["metadata"].get("ownerReferences", [])) for item in sets), "Stability ReplicaSet owner differs")
        owners = {item["metadata"]["uid"] for item in sets}
        pods = json.loads(e.c.cluster.kube("get", "pods", "-n", e.app.namespace, "-l", labels, "-o", "json").stdout)["items"]
        pods = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp")]
        require(len(pods) == 2 and all(any(ref.get("kind") == "ReplicaSet" and ref.get("uid") in owners for ref in item["metadata"].get("ownerReferences", [])) for item in pods), "Stability Pod owner differs")
        for pod in pods:
            statuses = pod.get("status", {}).get("containerStatuses", [])
            require(statuses and all(status.get("state", {}).get("running") and status.get("ready") is True for status in statuses), "Stability container is not running and ready")
            values[pod["metadata"]["uid"]] = [(status["name"], status["containerID"], status["restartCount"]) for status in statuses]
    return values


def _events(e, processes):
    events = json.loads(e.c.cluster.kube("get", "events", "-n", e.app.namespace, "-o", "json").stdout)["items"]
    return {event["metadata"]["uid"]: event.get("count", 1) for event in events if event.get("reason") == "Unhealthy" and event.get("involvedObject", {}).get("uid") in processes}


def run(e, new_chart):
    root = e.root / "readiness-upgrade"
    root.mkdir(mode=0o700, exist_ok=True)
    require(not root.is_symlink() and not (root / "plan.json").exists(), "Readiness upgrade cannot silently reset an attempt")
    new_chart = Path(new_chart)
    require(new_chart.is_dir() and not new_chart.is_symlink() and (e.root / "node-rotation" / "complete.json").exists(), "Reviewed chart and completed node proof required")
    snapshot = e.c.current()["snapshot"]
    wait(lambda: e.app.current(snapshot, True))
    before, status, target = e.app.footprint(), wait(e.app.status), e.app.get("Secret", TARGET)
    old_render, _ = e.lifecycle.render(e.values)
    old_chart = e.lifecycle.chart
    values = copy.deepcopy(e.values)
    values["ha"]["fencer"]["readinessTimeoutSeconds"] = 10
    try:
        e.lifecycle.chart = new_chart
        new_render, _ = e.lifecycle.render(values)
    finally:
        e.lifecycle.chart = old_chart
    review_diff(old_render, new_render)
    write_private(root / "plan.json", canonical({"oldValues": e.values, "newValues": values, "oldRender": old_render, "newRender": new_render,
        "snapshot": snapshot, "appFootprint": before, "appStatus": status, "targetUID": target["metadata"]["uid"], "data": target["data"], "revision": target["metadata"]["annotations"][REVISION]}))
    backup = e.c.task / "charts-before-readiness" / "sekvyr-operator"
    require(not backup.exists(), "Readiness chart backup already exists")
    backup.parent.mkdir(mode=0o700, exist_ok=True)
    shutil.copytree(old_chart, backup)
    shutil.copytree(new_chart, old_chart, dirs_exist_ok=True)
    e.lifecycle.upgrade(values)
    e.register_managed()
    e.values = values
    wait(lambda: replicas_current(e.app), timeout=240)
    wait(lambda: e.app.current(snapshot, True), timeout=240)
    processes = _processes(e)
    events = _events(e, processes)
    started, samples = time.monotonic(), 0
    while True:
        require(replicas_current(e.app) and e.app.current(snapshot, True), "HA readiness or verified current data became unavailable")
        require(_processes(e) == processes and _events(e, processes) == events, "HA Pod process restarted or new unhealthy probe event appeared")
        actual = e.app.get("Secret", TARGET)
        require(actual["metadata"]["uid"] == target["metadata"]["uid"] and actual["data"] == target["data"]
            and actual["metadata"]["annotations"][REVISION] == target["metadata"]["annotations"][REVISION], "Probe upgrade changed application data or revision")
        e.app.frozen(before, seconds=0)
        now = wait(e.app.status)
        require((now["pod_uid"], now["boot_id"]) == (status["pod_uid"], status["boot_id"]), "Probe upgrade restarted the application")
        samples += 1
        elapsed = time.monotonic() - started
        if elapsed >= 120:
            break
        time.sleep(min(5, 120 - elapsed))
    result = {"nativeHelmUpgrade": True, "onlyFencerProbeTimingChanged": True, "readinessTimeoutSeconds": 10,
        "freshJournalHealthGatePreserved": True, "stableSeconds": int(elapsed), "healthySamples": samples,
        "twoOperatorAndFencerReplicasStable": True, "sameHAPodUIDsAndContainerIDs": True, "newUnhealthyEvents": 0,
        "appDataRevisionPodBootAndReplicaSetsUnchanged": True, "priorFlappingRootCauseConfirmed": False, "production": False}
    write_private(root / "complete.json", canonical(result))
    return result
