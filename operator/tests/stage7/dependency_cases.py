"""Controlled dependency loss with fresh failure and last-good-data proofs."""

from contextlib import contextmanager
import copy
from datetime import datetime
import json

from app_modes import OwnedNamespace, require, wait
from application import APP, TARGET, RESOURCE, REVISION
from fixture import canonical, write_private

# Source: panelauth/client.go; verification/reader.go; syncer/fencing.go.
REASONS = {"panel": {"PanelUnavailable"}, "witness": {"WitnessUnavailable"},
    "fencer": {"FencingUnavailable"}, "gateway": {"JournalUnavailable"}}


def _after(now, previous):
    return datetime.fromisoformat(now.replace("Z", "+00:00")) > datetime.fromisoformat(previous.replace("Z", "+00:00"))


def _failed_status(value, label, stopped_attempt):
    state = value.get("status", {})
    conditions = {item["type"]: item for item in state.get("conditions", [])}
    data, bootstrap = (conditions.get(name, {}) for name in ("DataCurrent", "BootstrapReady"))
    generation = value["metadata"]["generation"]
    good = data.get("status") == "False" and data.get("observedGeneration") == generation and data.get("reason") in REASONS[label] and bootstrap.get("status") == "True" and bootstrap.get("observedGeneration") == generation and state.get("lastAttemptTime") and _after(state["lastAttemptTime"], stopped_attempt)
    return value if good else False


def _no_pods(scope, name):
    value = scope.get("Deployment", name)
    selector = value["spec"]["selector"]
    require(set(selector) == {"matchLabels"} and selector["matchLabels"], "Dependency selector is not exact")
    labels = ",".join(key + "=" + item for key, item in sorted(selector["matchLabels"].items()))
    pods = json.loads(scope.cluster.kube("get", "pods", "-n", scope.namespace, "-l", labels, "-o", "json").stdout)["items"]
    return value["spec"]["replicas"] == 0 and value.get("status", {}).get("observedGeneration", 0) >= value["metadata"]["generation"] and not pods


def _no_endpoints(scope, name):
    service = scope.get("Service", name)
    slices = json.loads(scope.cluster.kube("get", "endpointslices", "-n", scope.namespace, "-l", "kubernetes.io/service-name=" + name, "-o", "json").stdout)["items"]
    for item in slices:
        require(item["metadata"].get("namespace") == scope.namespace and any(ref.get("kind") == "Service" and ref.get("uid") == service["metadata"]["uid"]
            for ref in item["metadata"].get("ownerReferences", [])), "EndpointSlice has an unexpected Service owner")
        endpoints = item.get("endpoints")
        if endpoints is None:
            endpoints = []
        require(isinstance(endpoints, list) and all(isinstance(endpoint, dict) for endpoint in endpoints), "EndpointSlice shape invalid")
        if any(endpoint.get("conditions", {}).get("ready") is not False for endpoint in endpoints):
            return False
    return True


@contextmanager
def _gateway_down(c):
    scope = OwnedNamespace(c.cluster, c.namespaces["gateway"])
    old = scope.get("Deployment", "journal")
    require(old["spec"]["replicas"] == 1, "Gateway fault requires its original one replica")
    try:
        scope.patch("Deployment", "journal", [{"op": "test", "path": "/spec", "value": old["spec"]}, {"op": "replace", "path": "/spec/replicas", "value": 0}])
        wait(lambda: _no_pods(scope, "journal"))
        yield
    finally:
        value = scope.get("Deployment", "journal")
        expected = copy.deepcopy(old["spec"])
        expected["replicas"] = value["spec"]["replicas"]
        require(value["spec"] == expected and expected["replicas"] in (0, 1), "Gateway changed while restoring the exact fault")
        scope.patch("Deployment", "journal", [{"op": "test", "path": "/spec", "value": expected}, {"op": "replace", "path": "/spec/replicas", "value": 1}])
        c.cluster.kube("-n", scope.namespace, "rollout", "status", "deployment/journal", "--timeout=180s")


def run(e2e, *, labels=("panel", "witness", "fencer", "gateway")):
    require(labels in (("panel",), ("panel", "witness", "fencer", "gateway")),
        "Explicit reviewed dependency cases required")
    c, app = e2e.c, e2e.app
    require(e2e.installed, "Dependency acceptance requires the captured active Helm installation")
    directory = e2e.root / "dependency-cases"
    directory.mkdir(mode=0o700, exist_ok=True)
    require(not directory.is_symlink() and not (directory / "started.json").exists(), "Dependency cases cannot silently restart")
    snapshot = c.current()["snapshot"]
    wait(lambda: app.current(snapshot, True))
    target = app.get("Secret", TARGET)
    before, status = app.footprint(), wait(app.status)
    write_private(directory / "started.json", canonical({"snapshot": snapshot, "targetUID": target["metadata"]["uid"], "footprint": before, "status": status}))
    def frozen():
        current = app.get("Secret", TARGET)
        require(current["metadata"]["uid"] == target["metadata"]["uid"] and current["data"] == target["data"]
            and current["metadata"]["annotations"][REVISION] == target["metadata"]["annotations"][REVISION], "Dependency failure changed last good target data")
        app.frozen(before, seconds=1)
        current_status = wait(app.status)
        require((current_status["pod_uid"], current_status["boot_id"]) == (status["pod_uid"], status["boot_id"]), "Dependency failure restarted the consumer")
    targets = {"panel": [("panel", "panel")], "witness": [("witness", "witness-a"), ("witness", "witness-b")],
        "fencer": [("apps", "stage6-fencer")], "gateway": [("gateway", "journal")]}
    services = {"panel": ("panel", "panel"), "witness": ("witness", "witness"),
        "fencer": ("apps", "stage6-fencer"), "gateway": ("gateway", "journal")}
    completed = []
    for label in labels:
        with (_gateway_down(c) if label == "gateway" else c.outage(label)):
            for role, name in targets[label]:
                scope = OwnedNamespace(c.cluster, c.namespaces[role])
                wait(lambda scope=scope, name=name: _no_pods(scope, name))
            role, service = services[label]
            service_scope = OwnedNamespace(c.cluster, c.namespaces[role])
            wait(lambda: _no_endpoints(service_scope, service))
            stopped_attempt = app.get("SekvyrSecret", RESOURCE).get("status", {}).get("lastAttemptTime")
            require(stopped_attempt, "Dependency fault needs an observed prior attempt")
            app.poke()
            def failed():
                value = app.get("SekvyrSecret", RESOURCE)
                return _failed_status(value, label, stopped_attempt)
            rejected = wait(failed, timeout=120)
            reason = next(item["reason"] for item in rejected["status"]["conditions"] if item["type"] == "DataCurrent")
            require(_no_endpoints(service_scope, service), "Dependency endpoint became ready before failure proof")
            frozen()
            failure_time = app.get("SekvyrSecret", RESOURCE)["status"]["lastAttemptTime"]
        app.poke()
        def healed():
            value = app.current(snapshot, True)
            return value if value and _after(value["status"]["lastSuccessfulSyncTime"], failure_time) else False
        wait(healed, timeout=240)
        frozen()
        write_private(directory / (label + ".json"), canonical({"actualDependencyPodsAbsent": True, "freshPostStopFailure": True,
            "noReadyServiceEndpoints": True, "reason": reason, "lastGoodDataAndProcessPreserved": True, "freshVerifiedRecovery": True}))
        completed.append(label)
    result = {"actualDependencyOutages": completed, "freshPostStopFailures": len(completed), "targetDataAndRevisionPreserved": True,
        "noExtraAppReplicaSetPodOrBoot": True, "freshVerifiedRecoveryAfterEveryOutage": True, "production": False}
    write_private(directory / "complete.json", canonical(result))
    return result
