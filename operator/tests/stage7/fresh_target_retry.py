"""One explicitly authorized fresh-target retry after an incomplete harness run.

The earlier Store/CR/target remains untouched. This is another administrative
binding in the same installation, source and namespace, with no rollout grant.
"""

import base64
import copy
import hashlib
import json
import re
import uuid

from app_modes import require, resource, wait
from helm_lifecycle import canonical, private_exact
from plain_installation import API, CHECKPOINT, REVISION, binding_identity
from plain_rollout import target_proof
from plain_secondary_store import _active, _later, _panel_view, _poke, _stable, _validate

STORE, CR, BINDING, TARGET = "plain-store-fresh-retry", "plain-runtime-fresh-retry", "runtime-fresh-retry", "plain-fresh-retry-env"


def _absent(p):
    return not p.cluster.kube("get", "Secret", TARGET, "-n", p.namespace, "--ignore-not-found", "-o", "name").stdout.strip()


def _status(p, current):
    store, cr = p.owned.get("SekvyrStore", STORE), p.owned.get("SekvyrSecret", CR)
    status = cr.get("status", {})
    conditions = {item["type"]: item for item in status.get("conditions", [])}
    data, bootstrap, witness = (conditions.get(name, {}) for name in ("DataCurrent", "BootstrapReady", "WitnessReady"))
    if status.get("observedGeneration") != cr["metadata"]["generation"] or status.get("observedStoreUID") != store["metadata"]["uid"] or status.get("observedStoreGeneration") != store["metadata"]["generation"]:
        return False
    if data.get("observedGeneration") != cr["metadata"]["generation"] or data.get("status") != ("True" if current else "False"):
        return False
    require(bootstrap.get("status") == "True" and bootstrap.get("observedGeneration") == cr["metadata"]["generation"]
        and witness.get("status") == "Unknown" and witness.get("reason") == "NotApplicablePlain" and not status.get("lastVerifiedCheckpoint"),
        "Fresh retry requires valid Plain bootstrap and no checkpoint claim")
    if current:
        require(status.get("lastSuccessfulSyncTime") and status.get("lastSuccessfulSyncTime") == status.get("lastAttemptTime"), "Fresh retry success is stale")
    else:
        require(data.get("reason") == "PanelUnavailable" and status.get("lastAttemptTime")
            and not status.get("lastSuccessfulSyncTime") and not status.get("lastAppliedRevision"), "Fresh retry failed for another reason or already succeeded")
    return cr


def _retained_second(p, expected=None):
    store = p.owned.get("SekvyrStore", "plain-store-secondary")
    cr = p.owned.get("SekvyrSecret", "plain-runtime-secondary")
    state = json.loads(base64.b64decode(p.owned.get("Secret", p.state_name)["data"]["state.json"], validate=True))
    records = [value for value in state.get("bindings", {}).values() if value.get("targetName") == "plain-secondary-env"]
    require(len(records) == 1 and records[0].get("storeUID") == store["metadata"]["uid"] and records[0].get("crUID") == cr["metadata"]["uid"]
        and records[0].get("mode") == "Plain" and "head" in records[0] and records[0]["head"] is None, "Earlier target lacks its protected creation history")
    target = json.loads(p.cluster.kube("get", "Secret", "plain-secondary-env", "-n", p.namespace, "-o", "json").stdout)
    require(target["metadata"]["uid"] == records[0].get("targetUID") and not target["metadata"].get("deletionTimestamp"), "Earlier target UID changed")
    result = {"uid": target["metadata"]["uid"], "dataDigest": hashlib.sha256(canonical(target.get("data", {}))).hexdigest(), "revision": target["metadata"].get("annotations", {}).get(REVISION)}
    require(expected is None or result == expected, "Earlier failed-attempt target changed")
    return result


def _target(p, plan):
    cr, store = _status(p, True), p.owned.get("SekvyrStore", STORE)
    require(cr, "Fresh target has no current successful status")
    state = p.owned.get("Secret", p.state_name)
    body = json.loads(base64.b64decode(state["data"]["state.json"], validate=True))
    require(body.get("version") == 1 and body.get("installationID") == p.context["installationID"] and body.get("bootstrapGeneration") == 1
        and body.get("trustBundleUID") == p.owned.get("Secret", p.trust_name)["metadata"]["uid"] and body.get("nodeFingerprint") == p.fingerprint and not body.get("recovery"), "Fresh target bootstrap identity differs")
    binding = plan["binding"]
    record = body.get("bindings", {}).get(store["metadata"]["uid"] + "/" + binding["id"], {})
    require(record.get("mode") == "Plain" and "head" in record and record["head"] is None
        and record.get("storeUID") == store["metadata"]["uid"] and record.get("bindingID") == binding["id"]
        and record.get("crUID") == cr["metadata"]["uid"] and record.get("crName") == CR
        and record.get("identity") == binding_identity(binding) and record.get("targetName") == TARGET and record.get("targetUID"), "Fresh target protected binding differs")
    target = json.loads(p.cluster.kube("get", "Secret", TARGET, "-n", p.namespace, "-o", "json").stdout)
    meta, annotations = target["metadata"], target["metadata"].get("annotations", {})
    require(meta["namespace"] == p.namespace and meta["name"] == TARGET and meta["uid"] == record["targetUID"]
        and not meta.get("deletionTimestamp") and target.get("type") == "Opaque" and not target.get("immutable") and CHECKPOINT not in annotations
        and re.fullmatch(r"[0-9a-f]{32}", annotations.get(REVISION, "")) and annotations[REVISION] == cr["status"].get("lastAppliedRevision")
        and hashlib.sha256(canonical(target.get("data", {}))).hexdigest() == plan["primary_target"]["dataDigest"], "Fresh target UID, data or revision differs")
    require(p.owned.get("Secret", p.state_name)["metadata"]["resourceVersion"] == state["metadata"]["resourceVersion"], "Fresh target protected state changed during proof")


def run(cases):
    p = cases.installation
    directory = p.root / "fresh-target-retry"
    directory.mkdir(mode=0o700, exist_ok=True)
    require(not directory.is_symlink() and not (directory / "plan.json").exists(), "Fresh retry cannot reset a prior attempt")
    require(p.lifecycle and p.lifecycle.managed and p.values["ha"]["enabled"] is False and p.binding["encryption"] == {"mode": "Plain"}, "Fresh retry requires the original Plain lifecycle")
    _active(p)
    require(_absent(p), "Fresh retry target already exists")
    p.owned.reload_pins()
    require(all((kind, name) not in p.owned.pins for kind, name in (("SekvyrStore", STORE), ("SekvyrSecret", CR), ("Secret", TARGET))), "Fresh retry names have prior creation history")
    current = p.current()
    require(current, "Primary Plain source is not current")
    history = json.loads(base64.b64decode(p.owned.get("Secret", p.state_name)["data"]["state.json"], validate=True))
    require(all(record.get("targetName") != TARGET for record in history.get("bindings", {}).values()), "Fresh retry target has protected prior creation history")
    old_values, values = copy.deepcopy(p.values), copy.deepcopy(p.values)
    require(TARGET not in values["installation"]["allowedTargetSecrets"], "Fresh retry target was already allowed")
    values["installation"]["allowedTargetSecrets"].append(TARGET)
    binding = copy.deepcopy(p.binding)
    binding.update(id=str(uuid.uuid4()), name=BINDING, resourceName=CR, target={"name": TARGET, "type": "Opaque", "deletionPolicy": "Retain", "allowEmpty": False}, rollout={"allowedDeployments": []})
    primary = p.owned.get("SekvyrStore", p.store_name)
    store = resource("SekvyrStore", STORE, p.namespace, {"endpoint": copy.deepcopy(primary["spec"]["endpoint"]), "bindings": [binding]}, API)
    requested = resource("SekvyrSecret", CR, p.namespace, {"storeRef": {"name": STORE, "uid": binding["id"]}, "binding": BINDING,
        "refreshIntervalSeconds": 30, "suspend": False, "rollout": {"enabled": False, "deployments": []}}, API)
    _validate(p, store, requested)
    plan = {"context": copy.deepcopy(p.context), "primary_binding": copy.deepcopy(p.binding), "primary_store_uid": primary["metadata"]["uid"],
        "primary_store_spec": primary["spec"], "primary_target": target_proof(p), "retained_second": _retained_second(p),
        "apps": {name: cases.apps.capture(name) for name in (cases.env_name, cases.volume_name, cases.agent_name)},
        "old_values": old_values, "new_values": values, "binding": binding, "store": store, "cr": requested, "before_success": current["status"]["lastSuccessfulSyncTime"]}
    private_exact(directory / "plan.json", canonical(plan))
    p.lifecycle.upgrade(values)
    p.values = copy.deepcopy(values)
    _poke(p, p.cr_name)
    wait(lambda: p.current(after_success=plan["before_success"]))
    def stable():
        _stable(cases, plan)
        _retained_second(p, plan["retained_second"])
    stable()
    with cases.provider.sealed():
        require(_absent(p), "Fresh retry appeared before sealed creation")
        created = p._ensure_custom(store)
        requested["spec"]["storeRef"]["uid"] = created["metadata"]["uid"]
        p._ensure_custom(requested)
        def failed():
            require(_absent(p), "Unavailable panel produced the fresh retry target")
            return _status(p, False)
        wait(failed)
        stable()
        panel = cases.c.panel
        deployment = panel.get("Deployment", "panel")
        uid, spec = deployment["metadata"]["uid"], copy.deepcopy(deployment["spec"])
        require(spec["replicas"] == 1 and _panel_view(panel, uid, spec, 1), "Panel is not current and ready before the transport fault")
        try:
            panel.scale(0)
            wait(lambda: _panel_view(panel, uid, spec, 0))
            previous = p.owned.get("SekvyrSecret", CR)["status"]["lastAttemptTime"]
            _poke(p, CR)
            def failed_after_stop():
                cr = failed()
                return cr if cr and _later(cr["status"]["lastAttemptTime"], previous) else False
            observed = wait(failed_after_stop)
            require(_panel_view(panel, uid, spec, 0), "Panel was not actually stopped during the fresh failed request")
            stable()
            private_exact(directory / "outage-proven.json", canonical({"lastAttemptTime": observed["status"]["lastAttemptTime"], "sealedBeforeFirstTarget": True, "transportDownBeforeFirstTarget": True, "targetAbsent": True}))
        finally:
            live = panel.get("Deployment", "panel")
            expected = copy.deepcopy(spec)
            expected["replicas"] = live["spec"]["replicas"]
            require(live["metadata"]["uid"] == uid and live["spec"] == expected and expected["replicas"] in (0, 1), "Panel changed while restoring fresh retry")
            panel.scale(1)
            wait(lambda: _panel_view(panel, uid, spec, 1))
            panel.connect()
            panel.login()
            _, vault = panel.owner_request("GET", "/api/vault/status")
            require(vault.get("initialized") is True and vault.get("sealed") is True and _absent(p), "Panel restoration unsealed or produced a target")
            stable()
    outage = json.loads((directory / "outage-proven.json").read_bytes())
    _poke(p, CR)
    _poke(p, p.cr_name)
    wait(lambda: cr if (cr := _status(p, True)) and _later(cr["status"]["lastSuccessfulSyncTime"], outage["lastAttemptTime"]) else False)
    wait(lambda: p.current())
    _target(p, plan)
    stable()
    result = {"sealedAndTransportDownBeforeFirstTarget": True, "freshPostStopPanelUnavailableAttempt": True,
        "validBootstrapWhileUnavailable": True, "newTargetUIDFromProtectedState": True, "earlierTargetsRetainedUnchanged": True,
        "sameSourceIdentityNamespace": True, "noRolloutPermissionAdded": True, "noExtraAppReplicaSetOrBoot": True, "production": False}
    private_exact(directory / "complete.json", canonical(result))
    return result
