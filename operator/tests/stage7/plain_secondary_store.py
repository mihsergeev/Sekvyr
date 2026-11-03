"""Coordinator-only sealed-before-first-target acceptance for a second Store.

One existing Plain installation/SA/source is reused. Only its explicit target
allowlist is broadened; no source policy, bootstrap, primary binding or rollout
permission is changed. No action runs on import and no target is adopted.
"""

import base64
import copy
from datetime import datetime
import hashlib
import json
import re
import time
import uuid

from app_modes import require, resource, wait
from helm_lifecycle import canonical, private_exact
from plain_installation import API, CHECKPOINT, REVISION, binding_identity, strict_client_schema
from plain_rollout import target_proof

STORE, CR, BINDING, TARGET = "plain-store-secondary", "plain-runtime-secondary", "runtime-secondary", "plain-secondary-env"


def _absent(p):
    return not p.cluster.kube("get", "Secret", TARGET, "-n", p.namespace, "--ignore-not-found", "-o", "name").stdout.strip()


def _stable(cases, plan):
    p = cases.installation
    reference = plan["primary_target"]["reference"]
    current = json.loads(p.cluster.kube("get", "Secret", reference["name"], "-n", p.namespace, "-o", "json").stdout)
    require(current["metadata"]["uid"] == reference["uid"] and not current["metadata"].get("deletionTimestamp")
        and current["metadata"].get("annotations", {}).get(REVISION) == plan["primary_target"]["revision"]
        and hashlib.sha256(canonical(current.get("data", {}))).hexdigest() == plan["primary_target"]["dataDigest"],
        "Secondary Store case changed the primary target data, revision or UID")
    require(p.binding == plan["primary_binding"] and p.context == plan["context"], "Primary binding or bootstrap context changed")
    primary = p.owned.get("SekvyrStore", p.store_name)
    require(primary["metadata"]["uid"] == plan["primary_store_uid"] and primary["spec"] == plan["primary_store_spec"], "Primary administrative Store changed")
    for name, before in plan["apps"].items():
        cases.apps.frozen(name, before, seconds=0)


def _validate(p, store, cr):
    import yaml
    from jsonschema import Draft7Validator, Draft202012Validator
    design = json.loads((p.chart.parents[1] / "design" / "resource.schema.json").read_bytes())
    for value, filename in ((store, "sekvyrstores.secrets.sekvyr.ru.yaml"), (cr, "sekvyrsecrets.secrets.sekvyr.ru.yaml")):
        schema = yaml.safe_load((p.chart / "crds" / filename).read_text(encoding="utf-8"))["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
        Draft7Validator(strict_client_schema(schema)).validate(value)
        Draft202012Validator(design).validate(value)


def _active(p):
    p.lifecycle._external_guard()
    p.lifecycle._retained_guard()
    for saved in p.lifecycle.managed.values():
        current = p.lifecycle._get(saved["manifest"])
        p.lifecycle._owned(current, saved["uid"])
        p.lifecycle._matches(current, saved["manifest"])


def _poke(p, name):
    current = p.owned.get("SekvyrSecret", name)
    annotations = dict(current["metadata"].get("annotations", {}))
    annotations["stage7-secondary-store-reconcile"] = uuid.uuid4().hex
    p.owned.patch("SekvyrSecret", name, [{"op": "add", "path": "/metadata/annotations", "value": annotations}])


def _later(current, previous):
    return datetime.fromisoformat(current.replace("Z", "+00:00")) > datetime.fromisoformat(previous.replace("Z", "+00:00"))


def _panel_view(panel, uid, original_spec, replicas):
    deployment = panel.get("Deployment", "panel")
    expected = copy.deepcopy(original_spec)
    expected["replicas"] = replicas
    require(deployment["metadata"]["uid"] == uid and deployment["spec"] == expected, "Transport fault panel UID or exact specification changed")
    status = deployment.get("status", {})
    observed = status.get("observedGeneration", 0) >= deployment["metadata"]["generation"]
    if replicas:
        return observed and status.get("readyReplicas", 0) == 1 and status.get("availableReplicas", 0) == 1
    selector = deployment["spec"]["selector"]
    require(set(selector) == {"matchLabels"} and selector["matchLabels"], "Panel transport selector is ambiguous")
    label = ",".join(key + "=" + value for key, value in sorted(selector["matchLabels"].items()))
    pods = json.loads(panel.cluster.kube("get", "pods", "-n", panel.namespace, "-l", label, "-o", "json").stdout)["items"]
    service = panel.get("Service", "panel")
    require(service["spec"].get("selector") == selector["matchLabels"], "Panel Service differs from the pinned Deployment selector")
    slices = json.loads(panel.cluster.kube("get", "endpointslices", "-n", panel.namespace,
        "-l", "kubernetes.io/service-name=panel", "-o", "json").stdout)["items"]
    endpoints = []
    for item in slices:
        values = item.get("endpoints")
        # API may encode an empty optional slice as null during scale-down.
        if values is None:
            values = []
        require(isinstance(values, list) and all(isinstance(value, dict) for value in values),
            "EndpointSlice endpoints shape invalid")
        endpoints.extend(values)
    no_ready_endpoint = not any(endpoint.get("conditions", {}).get("ready") is not False for endpoint in endpoints)
    return observed and not pods and no_ready_endpoint and all(status.get(key, 0) == 0 for key in ("replicas", "readyReplicas", "availableReplicas"))


def _transport_while_sealed(cases, plan):
    p, panel = cases.installation, cases.c.panel
    deployment = panel.get("Deployment", "panel")
    uid, spec = deployment["metadata"]["uid"], copy.deepcopy(deployment["spec"])
    require(spec.get("replicas", 1) == 1, "Transport test needs one current owned panel replica")
    require(_panel_view(panel, uid, spec, 1), "Owned panel must be ready before the transport fault")
    proof = None
    try:
        panel.scale(0)  # Provider patch retains its creation UID + RV tests.
        wait(lambda: _panel_view(panel, uid, spec, 0))
        require(_absent(p), "New target existed before the transport failure observation")
        before = p.owned.get("SekvyrSecret", CR)["status"]["lastAttemptTime"]
        _poke(p, CR)
        def failed_after_stop():
            require(_absent(p), "Stopped panel produced the new target")
            observed = _status(p, False)
            return observed if observed and _later(observed["status"]["lastAttemptTime"], before) else False
        observed = wait(failed_after_stop)
        require(_panel_view(panel, uid, spec, 0), "Panel was not actually stopped during the fresh failed attempt")
        _stable(cases, plan)
        proof = {"panelUID": uid, "newAttemptAfterNoPodsOrReadyEndpoints": True,
            "lastAttemptTime": observed["status"]["lastAttemptTime"], "newTargetAbsent": True}
    finally:
        # Restore the exact owned deployment BEFORE the outer context unseals.
        current = panel.get("Deployment", "panel")
        require(current["metadata"]["uid"] == uid, "Panel was replaced; transport restoration refused")
        expected = copy.deepcopy(spec)
        expected["replicas"] = current["spec"].get("replicas", 1)
        require(current["spec"] == expected and expected["replicas"] in (0, 1), "Unreviewed panel change during transport fault")
        panel.scale(1)
        wait(lambda: _panel_view(panel, uid, spec, 1))
        panel.connect()
        panel.login()
        _, vault = panel.owner_request("GET", "/api/vault/status")
        require(vault.get("initialized") is True and vault.get("sealed") is True, "Panel must be restored and authenticated while the vault remains sealed")
        require(_absent(p), "New target appeared before explicit unseal")
        _stable(cases, plan)
    require(proof is not None, "Transport outage was not proven")
    return {**proof, "samePanelUIDRestoredWhileSealed": True}


def _status(p, current):
    store = p.owned.get("SekvyrStore", STORE)
    cr = p.owned.get("SekvyrSecret", CR)
    status = cr.get("status", {})
    conditions = {item["type"]: item for item in status.get("conditions", [])}
    data = conditions.get("DataCurrent", {})
    if status.get("observedGeneration") != cr["metadata"]["generation"] or status.get("observedStoreUID") != store["metadata"]["uid"] or status.get("observedStoreGeneration") != store["metadata"]["generation"]:
        return False
    if data.get("observedGeneration") != cr["metadata"]["generation"] or data.get("status") != ("True" if current else "False"):
        return False
    witness = conditions.get("WitnessReady", {})
    require(witness.get("status") == "Unknown" and witness.get("reason") == "NotApplicablePlain" and not status.get("lastVerifiedCheckpoint"),
        "Secondary Plain Store must not claim witness or checkpoint verification")
    if current:
        require(status.get("lastSuccessfulSyncTime") and status.get("lastSuccessfulSyncTime") == status.get("lastAttemptTime"), "Secondary Plain success is stale")
    else:
        bootstrap = conditions.get("BootstrapReady", {})
        require(data.get("reason") == "PanelUnavailable" and bootstrap.get("status") == "True"
            and bootstrap.get("observedGeneration") == cr["metadata"]["generation"], "Fresh target failure must be sealed-panel unavailability with valid bootstrap")
        require(status.get("lastAttemptTime") and not status.get("lastSuccessfulSyncTime") and not status.get("lastAppliedRevision"),
            "Fresh secondary CR already has a successful target observation")
    return cr


def _target_ref(p, plan):
    cr = _status(p, True)
    require(cr, "Secondary target needs successful current CR status")
    store = p.owned.get("SekvyrStore", STORE)
    state = p.owned.get("Secret", p.state_name)
    body = json.loads(base64.b64decode(state["data"]["state.json"], validate=True))
    require(body.get("version") == 1 and body.get("installationID") == p.context["installationID"] and body.get("bootstrapGeneration") == 1
        and body.get("trustBundleUID") == p.owned.get("Secret", p.trust_name)["metadata"]["uid"]
        and body.get("nodeFingerprint") == p.fingerprint and not body.get("recovery"), "Secondary target bootstrap state differs")
    binding = plan["binding"]
    record = body.get("bindings", {}).get(store["metadata"]["uid"] + "/" + binding["id"], {})
    require(record.get("mode") == "Plain" and "head" in record and record["head"] is None
        and record.get("storeUID") == store["metadata"]["uid"] and record.get("bindingID") == binding["id"]
        and record.get("crUID") == cr["metadata"]["uid"] and record.get("crName") == CR
        and record.get("identity") == binding_identity(binding) and record.get("targetName") == TARGET
        and isinstance(record.get("targetUID"), str) and bool(record["targetUID"]), "Secondary target lacks its exact protected binding")
    target = json.loads(p.cluster.kube("get", "Secret", TARGET, "-n", p.namespace, "-o", "json").stdout)
    meta, annotations = target["metadata"], target["metadata"].get("annotations", {})
    require(target["kind"] == "Secret" and meta["name"] == TARGET and meta["namespace"] == p.namespace and meta["uid"] == record["targetUID"]
        and not meta.get("deletionTimestamp") and target.get("type") == "Opaque" and not target.get("immutable")
        and CHECKPOINT not in annotations and re.fullmatch(r"[0-9a-f]{32}", annotations.get(REVISION, ""))
        and annotations.get(REVISION) == cr["status"].get("lastAppliedRevision")
        and hashlib.sha256(canonical(target.get("data", {}))).hexdigest() == plan["primary_target"]["dataDigest"], "Secondary target UID, revision or data differs")
    require(p.owned.get("Secret", p.state_name)["metadata"]["resourceVersion"] == state["metadata"]["resourceVersion"], "Protected state changed during secondary target proof")
    return {"name": TARGET, "uid": meta["uid"]}


def run(cases):
    p = cases.installation
    require(p.cluster is cases.c.cluster and p.lifecycle is not None and p.lifecycle.managed and p.values is not None
        and p.values["ha"]["enabled"] is False and p.binding["encryption"] == {"mode": "Plain"},
        "Secondary Store needs the original captured non-HA Plain installation")
    directory = p.root / "secondary-store"
    directory.mkdir(mode=0o700, exist_ok=True)
    require(not directory.is_symlink(), "Unsafe secondary Store context")
    path = directory / "plan.json"
    if path.exists():
        require(not path.is_symlink(), "Unsafe secondary Store plan")
        plan = json.loads(path.read_bytes())
        require(plan["context"] == p.context and p.values in (plan["old_values"], plan["new_values"])
            and plan["primary_binding"] == p.binding, "Secondary Store resume differs from reviewed input")
    else:
        current = p.current()
        require(current and _absent(p), "Secondary target must never have existed before this case")
        state = p.owned.get("Secret", p.state_name)
        prior = json.loads(base64.b64decode(state["data"]["state.json"], validate=True))
        require(all(record.get("targetName") != TARGET for record in prior.get("bindings", {}).values()), "Secondary target already has protected creation history")
        p.owned.reload_pins()
        require(all((kind, name) not in p.owned.pins for kind, name in (("SekvyrStore", STORE), ("SekvyrSecret", CR), ("Secret", TARGET))),
            "Secondary names already have creation history")
        old_values, next_values = copy.deepcopy(p.values), copy.deepcopy(p.values)
        allowed = next_values["installation"]["allowedTargetSecrets"]
        require(TARGET not in allowed and TARGET != p.binding["target"]["name"], "Secondary target is not a new explicit allowlist entry")
        allowed.append(TARGET)
        binding = copy.deepcopy(p.binding)
        binding.update(id=str(uuid.uuid4()), name=BINDING, resourceName=CR,
            target={"name": TARGET, "type": "Opaque", "deletionPolicy": "Retain", "allowEmpty": False}, rollout={"allowedDeployments": []})
        primary = p.owned.get("SekvyrStore", p.store_name)
        store = resource("SekvyrStore", STORE, p.namespace, {"endpoint": copy.deepcopy(primary["spec"]["endpoint"]), "bindings": [binding]}, API)
        cr = resource("SekvyrSecret", CR, p.namespace, {"storeRef": {"name": STORE, "uid": binding["id"]}, "binding": BINDING,
            "refreshIntervalSeconds": 30, "suspend": False, "rollout": {"enabled": False, "deployments": []}}, API)
        _validate(p, store, cr)
        names = [cases.env_name, cases.volume_name]
        if cases.agent_name in cases.apps.modes:
            names.append(cases.agent_name)
        plan = {"context": copy.deepcopy(p.context), "primary_binding": copy.deepcopy(p.binding), "primary_store_uid": primary["metadata"]["uid"],
            "primary_store_spec": primary["spec"], "old_values": old_values, "new_values": next_values, "binding": binding, "store": store, "cr": cr,
            "primary_target": target_proof(p), "before_success": current["status"]["lastSuccessfulSyncTime"],
            "apps": {name: cases.apps.capture(name) for name in names}}
        private_exact(path, canonical(plan))
    # One exact administrative delta, no source/bootstrap/rollout broadening.
    previous = copy.deepcopy(plan["new_values"])
    expected = plan["old_values"]["installation"]["allowedTargetSecrets"] + [TARGET]
    require(previous["installation"]["allowedTargetSecrets"] == expected, "Secondary Store target allowlist differs")
    previous["installation"]["allowedTargetSecrets"] = plan["old_values"]["installation"]["allowedTargetSecrets"]
    expected_binding = copy.deepcopy(p.binding)
    expected_binding.update(id=plan["binding"]["id"], name=BINDING, resourceName=CR,
        target={"name": TARGET, "type": "Opaque", "deletionPolicy": "Retain", "allowEmpty": False}, rollout={"allowedDeployments": []})
    require(str(uuid.UUID(expected_binding["id"])) == expected_binding["id"] and expected_binding["id"] != p.binding["id"], "Secondary binding needs its distinct exact UUID")
    expected_store = resource("SekvyrStore", STORE, p.namespace, {"endpoint": copy.deepcopy(plan["primary_store_spec"]["endpoint"]), "bindings": [expected_binding]}, API)
    expected_cr = resource("SekvyrSecret", CR, p.namespace, {"storeRef": {"name": STORE, "uid": expected_binding["id"]}, "binding": BINDING,
        "refreshIntervalSeconds": 30, "suspend": False, "rollout": {"enabled": False, "deployments": []}}, API)
    require(previous == plan["old_values"] and plan["binding"]["source"] == p.binding["source"]
        and plan["binding"]["encryption"] == {"mode": "Plain"} and plan["binding"]["rollout"] == {"allowedDeployments": []},
        "Secondary Store plan changes another gate or source")
    require(plan["binding"] == expected_binding and plan["store"] == expected_store and plan["cr"] == expected_cr, "Secondary Store requests differ from exact reviewed context")
    _stable(cases, plan)
    private_exact(directory / "reviewed-active-values.json", canonical(plan["new_values"]))
    if not (directory / "helm-complete.json").exists():
        p.lifecycle.upgrade(plan["new_values"])
        private_exact(directory / "helm-complete.json", canonical({"upgraded": True}))
    else:
        _active(p)
    p.values = copy.deepcopy(plan["new_values"])
    _poke(p, p.cr_name)
    wait(lambda: p.current(after_success=plan["before_success"]))
    _stable(cases, plan)
    if not (directory / "outage-proven.json").exists():
        p.owned.reload_pins()
        require(all((kind, name) not in p.owned.pins for kind, name in (("SekvyrStore", STORE), ("SekvyrSecret", CR)))
            and _absent(p), "Partial secondary outage requires explicit coordinator review")
        with cases.provider.sealed():
            require(_absent(p), "Secondary target appeared before sealed creation")
            store = p._ensure_custom(plan["store"])
            requested = copy.deepcopy(plan["cr"])
            requested["spec"]["storeRef"]["uid"] = store["metadata"]["uid"]
            p._ensure_custom(requested)
            def rejected():
                require(_absent(p), "Sealed panel produced a new target")
                return _status(p, False)
            observed = wait(rejected)
            end = time.monotonic() + 2
            while True:
                require(_absent(p), "New target appeared while panel remained sealed")
                _stable(cases, plan)
                if time.monotonic() >= end:
                    break
                time.sleep(.2)
            sealed_attempt = observed["status"]["lastAttemptTime"]
            transport = _transport_while_sealed(cases, plan)
            private_exact(directory / "transport-proven.json", canonical(transport))
            private_exact(directory / "outage-proven.json", canonical({"storeUID": store["metadata"]["uid"],
                "crUID": observed["metadata"]["uid"], "lastAttemptTime": transport["lastAttemptTime"], "sealedAttemptTime": sealed_attempt,
                "sealedBeforeCRCreated": True, "transportUnavailableBeforeFirstTarget": True,
                "samePanelUIDRestoredWhileSealed": True, "newTargetAbsent": True}))
    outage = json.loads((directory / "outage-proven.json").read_bytes())
    require(outage.get("transportUnavailableBeforeFirstTarget") is True and outage.get("samePanelUIDRestoredWhileSealed") is True,
        "Sealed 503 alone cannot substitute for a restored transport outage")
    require(p.owned.get("SekvyrStore", STORE)["metadata"]["uid"] == outage["storeUID"]
        and p.owned.get("SekvyrSecret", CR)["metadata"]["uid"] == outage["crUID"], "Secondary Store/CR replaced after outage")
    _poke(p, CR)
    _poke(p, p.cr_name)
    def recovered():
        cr = _status(p, True)
        if not cr:
            return False
        return cr if _later(cr["status"]["lastSuccessfulSyncTime"], outage["lastAttemptTime"]) else False
    wait(recovered)
    wait(lambda: p.current())
    _target_ref(p, plan)
    require(target_proof(p) == plan["primary_target"], "Primary current target changed after secondary recovery")
    _stable(cases, plan)
    result = {"freshSecondPlainStore": True, "sameInstallationSourceAndNamespace": True,
        "sealedBeforeFirstTarget": True, "newTargetAbsentDuringOutage": True, "newTargetUIDFromProtectedState": True,
        "transportUnavailableBeforeFirstTarget": True, "samePanelUIDRestoredBeforeUnseal": True,
        "oldTargetDataRevisionAndApplicationsUnchanged": True, "secondaryRolloutDisabled": True, "production": False}
    private_exact(directory / "complete.json", canonical(result))
    return result
