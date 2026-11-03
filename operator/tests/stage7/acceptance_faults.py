"""Two missing original-stage7 fault cases, coordinator invoked only.

The existing installation and published data history are preserved. A partial
case cannot reset/rebase itself. Private artifacts contain exact candidates;
public results contain only safe predicates, never wrapper/key/plaintext bytes.
"""

import base64
import copy
from datetime import datetime
import hashlib
import json
import os
import re

from cryptography.exceptions import InvalidTag

from application import APP, RESOURCE, REVISION, SA, STORE, TARGET
from app_modes import require, wait
from e2e_cases import PYTHON, replicas_current
from fixture import canonical, write_private
from process_control import ProcessControl
from protocol import domain
from rotation_cases import decrypt_snapshot, envelope_hash, unwrap

INTENT = "secrets.sekvyr.ru/rollout-intent"
LEADER_CASE_LABELS = ("leader-pending-restart", "leader-pending-restart-after-debounce-fix")


def _after(value, previous):
    return bool(value and previous and datetime.fromisoformat(value.replace("Z", "+00:00")) >
        datetime.fromisoformat(previous.replace("Z", "+00:00")))


def _start(e2e, label):
    require(e2e.installed and e2e.lifecycle and e2e.lifecycle.managed, "Original captured Helm installation required")
    directory = e2e.root / label
    directory.mkdir(mode=0o700, exist_ok=True)
    require(not directory.is_symlink() and not (directory / "started.json").exists(), "Partial fault case requires explicit review; no reset or rebase")
    app, current = e2e.app, e2e.c.current()
    wait(lambda: app.current(current["snapshot"], True), timeout=240)
    target = app.get("Secret", TARGET)
    baseline = {"canonical": current, "targetUID": target["metadata"]["uid"], "data": target["data"],
        "revision": target["metadata"]["annotations"][REVISION], "footprint": app.footprint(), "status": wait(app.status),
        "crUID": app.get("SekvyrSecret", RESOURCE)["metadata"]["uid"], "storeUID": app.get("SekvyrStore", STORE)["metadata"]["uid"]}
    write_private(directory / "started.json", canonical(baseline))
    return directory, baseline


def _frozen(app, baseline, data_unchanged=True):
    target = app.get("Secret", TARGET)
    require(target["metadata"]["uid"] == baseline["targetUID"], "Fault replaced target Secret UID")
    if data_unchanged:
        require(target["data"] == baseline["data"] and target["metadata"]["annotations"][REVISION] == baseline["revision"],
            "Fault changed last-good Secret bytes or revision")
    require(app.get("SekvyrSecret", RESOURCE)["metadata"]["uid"] == baseline["crUID"]
        and app.get("SekvyrStore", STORE)["metadata"]["uid"] == baseline["storeUID"], "Fault custom-resource identity changed")
    app.frozen(baseline["footprint"], seconds=1)
    status = wait(app.status)
    require((status["pod_uid"], status["boot_id"]) == (baseline["status"]["pod_uid"], baseline["status"]["boot_id"]),
        "Fault restarted consuming application")


def _failure(app, after, reason):
    cr, store = app.get("SekvyrSecret", RESOURCE), app.get("SekvyrStore", STORE)
    status = cr.get("status", {})
    conditions = {value["type"]: value for value in status.get("conditions", [])}
    data, bootstrap = (conditions.get(name, {}) for name in ("DataCurrent", "BootstrapReady"))
    return (status.get("observedGeneration") == cr["metadata"]["generation"]
        and status.get("observedStoreUID") == store["metadata"]["uid"]
        and status.get("observedStoreGeneration") == store["metadata"]["generation"]
        and data.get("status") == "False" and data.get("reason") == reason
        and data.get("observedGeneration") == cr["metadata"]["generation"]
        and bootstrap.get("status") == "True" and bootstrap.get("observedGeneration") == cr["metadata"]["generation"]
        and _after(status.get("lastAttemptTime"), after))


def wrong_e2e_key(e2e):
    """Publisher-signed current context, wrong wrapped AES; exact wrap restore."""
    directory, baseline = _start(e2e, "wrong-e2e-key")
    c, app, panel, protocol = e2e.c, e2e.app, e2e.c.panel, e2e.c.protocol
    current, view = baseline["canonical"], protocol.scope["view_id"]
    require(current["enrollments"][protocol.installation_id] == app.enrollment(), "Wrong-key test enrollment differs from current pins")
    token = c.cluster.kube("create", "token", SA, "-n", app.namespace, "--audience=sekvyr", "--duration=10m").stdout.strip()
    _, session = panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": token})
    route = "/api/v1/machine/e2e2/views/" + view + "/reader-wrap?envelope_hash=" + current["snapshot"]["envelope_hash"]
    _, original = panel.request("GET", route, access_token=session["access_token"])
    _, envelope = panel.owner_request("GET", "/api/e2e2/views/" + view + "/envelopes/" + current["snapshot"]["envelope_hash"])
    require(envelope_hash(envelope) == current["snapshot"]["envelope_hash"]
        and unwrap(protocol, original, protocol.node) == protocol.read_key, "Original wrapper or canonical envelope differs")
    decrypt_snapshot(protocol, envelope, protocol.read_key)
    bad_protocol = copy.copy(protocol)
    bad_protocol.read_key = os.urandom(32)
    require(bad_protocol.read_key != protocol.read_key, "Wrong AES fixture must differ")
    bad = bad_protocol.reader_wrap()
    wrong_key = unwrap(protocol, bad, protocol.node)  # Verifies publisher signature and context.
    require(wrong_key != protocol.read_key and bad["body"]["context"] == original["body"]["context"], "Wrong-key wrapper changed cryptographic context")
    try:
        decrypt_snapshot(protocol, envelope, wrong_key)
    except InvalidTag:
        pass
    else:
        raise RuntimeError("Wrong AES fixture unexpectedly decrypted current snapshot")
    write_private(directory / "wrappers.json", canonical({"original": original, "wrong": bad}))
    meta = json.loads((panel.private / "panel-bootstrap.json").read_bytes())
    def same_context():
        live = c.current()
        require(live["snapshot"] == current["snapshot"] and live["authority"] == current["authority"]
            and live["enrollments"][protocol.installation_id] == current["enrollments"][protocol.installation_id]
            and app.enrollment() == current["enrollments"][protocol.installation_id], "Concurrent authority/enrollment change requires review; no stale wrapper restore")
    previous = app.get("SekvyrSecret", RESOURCE)["status"]["lastAttemptTime"]
    failed_time = None
    try:
        panel.owner_request("POST", "/api/e2e2/views/" + view + "/readers", {"machine_id": meta["machine_id"], "wrapper": bad})
        app.poke()
        wait(lambda: _failure(app, previous, "CiphertextInvalid"), timeout=120)
        failed_time = app.get("SekvyrSecret", RESOURCE)["status"]["lastAttemptTime"]
        _frozen(app, baseline)
        same_context()
    finally:
        same_context()
        panel.owner_request("POST", "/api/e2e2/views/" + view + "/readers", {"machine_id": meta["machine_id"], "wrapper": original})
        _, restored = panel.request("GET", route, access_token=session["access_token"])
        require(restored == original, "Original reader wrapper was not restored exactly")
    require(failed_time is not None, "No fresh runtime wrong-key failure was proven")
    app.poke()
    wait(lambda: value if (value := app.current(current["snapshot"], True)) and _after(value["status"].get("lastSuccessfulSyncTime"), failed_time) else False, timeout=240)
    _frozen(app, baseline)
    result = {"validPublisherSignatureAndCurrentContext": True, "wrongWrappedAESRejectedByRuntime": True,
        "freshFailureReason": "CiphertextInvalid", "lastGoodDataRevisionUIDAndApplicationPreserved": True,
        "exactPreviousWrapperRestored": True, "freshVerifiedRecovery": True, "production": False}
    write_private(directory / "complete.json", canonical(result))
    return result


def _pending(app, snapshot, expected_data):
    cr = app.current(snapshot, False)
    if not cr:
        return False
    conditions = {value["type"]: value for value in cr["status"]["conditions"]}
    reason = conditions.get("RolloutReady", {}).get("reason")
    require(reason in ("Debouncing", "DeploymentPaused"), "Pending fixture is not blocked by the explicitly paused application")
    target, store = app.get("Secret", TARGET), app.get("SekvyrStore", STORE)
    deployment = app.get("Deployment", APP)
    require(deployment["spec"].get("paused") is True and target["data"] == expected_data, "New Secret data was not committed before leader termination")
    state = json.loads(base64.b64decode(app.get("Secret", app.state_name)["data"]["state.json"], validate=True))
    require(state["installationID"] == app.protocol.installation_id and state["bootstrapGeneration"] == app.generation
        and state["trustBundleUID"] == app.get("Secret", app.trust_name)["metadata"]["uid"]
        and state["nodeFingerprint"] == app.protocol.node_fingerprint, "Pending protected state identity differs")
    record = state["bindings"].get(store["metadata"]["uid"] + "/" + app.protocol.binding_id, {})
    authorization = record.get("rollout", {})
    intent = authorization.get("intent", {})
    head = record.get("head") or {}
    require(all(head.get(key) == snapshot[field] for key, field in (("Sequence", "sequence"), ("EnvelopeHash", "envelope_hash"),
        ("ReadKeyEpoch", "read_key_epoch"), ("PublisherPolicyEpoch", "publisher_policy_epoch")))
        and head.get("Scope") == {name.title().replace("_Id", "ID"): value for name, value in app.protocol.scope.items()}
        and head.get("WitnessEpoch") == app.protocol.authority["witness_epoch"], "Pending protected checkpoint differs from current verified snapshot")
    context = {"namespace": app.namespace, "crName": RESOURCE, "crUID": cr["metadata"]["uid"], "crGeneration": cr["metadata"]["generation"],
        "storeName": STORE, "storeUID": store["metadata"]["uid"], "storeGeneration": store["metadata"]["generation"],
        "bindingID": app.protocol.binding_id, "bootstrapGeneration": app.generation, "targetName": TARGET, "targetUID": target["metadata"]["uid"]}
    require(record.get("targetUID") == target["metadata"]["uid"] and record.get("crUID") == cr["metadata"]["uid"]
        and intent.get("version") == 1 and intent.get("eligible") is True and intent.get("context") == context
        and intent.get("revision") == target["metadata"]["annotations"][REVISION]
        and intent.get("deployments") == [{"name": APP, "uid": deployment["metadata"]["uid"]}]
        and authorization.get("applied") == [] and authorization.get("cancelled") is False
        and authorization.get("intentHash") == hashlib.sha256(canonical(intent)).hexdigest()
        and json.loads(target["metadata"]["annotations"][INTENT]) == intent,
        "Durable exact eligible pending authorization is not proven before leader restart")
    # Even a known transient must pass every protected context/intent check
    # above. It cannot authorize helper preparation or a signal before pause
    # has been reported explicitly by the rollout worker.
    return target if reason == "DeploymentPaused" else False


def _restarted(app, cluster, old_pod, old_holder, old_cid):
    raw = cluster.kube("get", "pod", old_pod["metadata"]["name"], "-n", app.namespace, "--ignore-not-found", "-o", "json").stdout.strip()
    if not raw:
        return False
    pod = json.loads(raw)
    require(pod["metadata"]["uid"] == old_pod["metadata"]["uid"] and not pod["metadata"].get("deletionTimestamp")
        and pod["spec"].get("serviceAccountName") == SA, "Terminated leader Pod was replaced or changed identity")
    statuses = [value for value in pod.get("status", {}).get("containerStatuses", []) if value["name"] == "operator"]
    if len(statuses) != 1 or statuses[0].get("state", {}).get("running") is None or statuses[0].get("containerID") == old_cid:
        return False
    require(re.fullmatch(r"containerd://[0-9a-f]{64}", statuses[0].get("containerID", "")) is not None, "New leader-process container identity invalid")
    try:
        selected, holder = app.operator_pod()
    except RuntimeError as error:
        if str(error) == "No unique bound operator leader pod":
            return False
        raise
    return (selected, holder) if holder != old_holder else False


def _active(state, protocol, pod, holder):
    grant = state.get("grants", {}).get(protocol.installation_id, {}).get("body", {})
    activation = state.get("activations", {}).get(protocol.installation_id, {}).get("body", {})
    enrollment = state.get("enrollments", {}).get(protocol.installation_id, {})
    keys = ("scope", "genesis_hash", "installation_id", "bootstrap_generation", "owner_pod_uid", "lease_holder_identity", "term", "authority_digest", "snapshot", "objects")
    return (grant.get("format") == "sekvyr-fence-grant-v1" and activation.get("format") == "sekvyr-fence-activation-v1"
        and all(key in grant and activation.get(key) == grant[key] for key in keys)
        and grant["scope"] == protocol.scope and grant["genesis_hash"] == protocol.genesis_hash
        and grant["installation_id"] == protocol.installation_id and grant["bootstrap_generation"] == enrollment.get("bootstrap_generation")
        and grant["owner_pod_uid"] == pod["metadata"]["uid"] and grant["lease_holder_identity"] == holder
        and grant["authority_digest"] == state.get("authority_digest") and grant["snapshot"] == state.get("snapshot")
        and grant["objects"] == enrollment.get("allowed_objects")
        and activation.get("grant_hash") == hashlib.sha256(domain("sekvyr-e2e2/fence-grant-hash/v1") + canonical(grant)).hexdigest())


def leader_pending_restart(e2e, helper_image=PYTHON, *, case_label="leader-pending-restart"):
    """An explicit retry is a fresh case after independently reviewed cleanup.

    The coordinator must first prove the original candidate completed its
    normal rollout without TERM and preserve its incomplete history. No
    original frame, candidate, directory or proof is resumed or overwritten.
    """
    require(isinstance(case_label, str) and case_label in LEADER_CASE_LABELS, "Unreviewed leader restart case label")
    directory, baseline = _start(e2e, case_label)
    c, app = e2e.c, e2e.app
    original = app.get("Deployment", APP)
    require(original["spec"].get("paused", False) is False, "Application was already paused")
    pair = e2e.pair(case_label)
    expected_data = {"GENERATION": base64.b64encode(pair["generation"].encode()).decode(), "DEMO_VALUE": base64.b64encode(pair["demo"].encode()).decode()}
    require(expected_data != baseline["data"], "Pending leader case requires actual changed data")
    snapshot, pending_target = None, None
    try:
        app.patch("Deployment", APP, [{"op": "test", "path": "/spec", "value": original["spec"]}, {"op": "add", "path": "/spec/paused", "value": True}])
        snapshot = c.publish(pair["generation"], pair["demo"])
        app.poke()
        pending_target = wait(lambda: _pending(app, snapshot, expected_data), timeout=240)
        require(pending_target["metadata"]["uid"] == baseline["targetUID"]
            and pending_target["metadata"]["annotations"][REVISION] != baseline["revision"], "Pending data commit must keep target UID and change revision")
        _frozen(app, baseline, data_unchanged=False)
        write_private(directory / "committed-pending.json", canonical({"snapshot": snapshot, "targetUID": baseline["targetUID"],
            "revision": pending_target["metadata"]["annotations"][REVISION]}))
        pod, holder = app.operator_pod()
        statuses = [value for value in pod["status"]["containerStatuses"] if value["name"] == "operator"]
        require(len(statuses) == 1 and re.fullmatch(r"containerd://[0-9a-f]{64}", statuses[0].get("containerID", "")), "Current leader container identity missing")
        old_cid = statuses[0]["containerID"]
        control = ProcessControl(c.cluster, pod, helper_image).prepare()
        # Preparation can take time. Re-prove pending immediately before TERM.
        require(_pending(app, snapshot, expected_data), "Pending authorization disappeared before TERM")
        selected, current_holder = app.operator_pod()
        require(selected["metadata"]["uid"] == pod["metadata"]["uid"] and current_holder == holder, "Leader changed before controlled TERM")
        acknowledged = False
        try:
            control.signal("TERM")
            acknowledged = True
        except RuntimeError as error:
            require(str(error) == "Owned process control was not acknowledged", "TERM ownership or transport guard failed")
        new_pod, new_holder = wait(lambda: _restarted(app, c.cluster, pod, holder, old_cid), timeout=120)
        app.poke()
        wait(lambda: _pending(app, snapshot, expected_data), timeout=240)
        wait(lambda: _active(c.current(), c.protocol, new_pod, new_holder), timeout=120)
        require(_pending(app, snapshot, expected_data), "New active leader lost durable pending intent")
        _frozen(app, baseline, data_unchanged=False)
        write_private(directory / "leader-restarted-pending.json", canonical({"sameOriginalPodNewContainer": True,
            "newLeaseProcessIdentity": True, "currentGrantActivation": True, "pendingSurvivedBeforeUnpause": True, "termAcknowledged": acknowledged}))
    finally:
        live = app.get("Deployment", APP)
        expected = copy.deepcopy(original["spec"])
        expected["paused"] = True
        require(live["metadata"]["uid"] == original["metadata"]["uid"] and live["spec"] in (expected, original["spec"]), "Application changed while restoring explicit pause")
        if live["spec"] != original["spec"]:
            operation = {"op": "replace", "path": "/spec/paused", "value": False} if "paused" in original["spec"] else {"op": "remove", "path": "/spec/paused"}
            app.patch("Deployment", APP, [{"op": "test", "path": "/spec", "value": expected}, operation])
    require((directory / "leader-restarted-pending.json").is_file() and snapshot and pending_target, "Leader/pending proof incomplete")
    app.poke()
    wait(lambda: app.current(snapshot, True), timeout=240)
    wait(lambda: replicas_current(app), timeout=240)
    new = wait(lambda: value if (value := app.status()) and value["generation"] == pair["generation"] else False)
    after = app.footprint()
    target = app.get("Secret", TARGET)
    expected = copy.deepcopy(baseline["footprint"]["template"])
    expected["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/restart-" + baseline["targetUID"]] = pending_target["metadata"]["annotations"][REVISION]
    require(target["metadata"]["uid"] == baseline["targetUID"] and target["data"] == expected_data
        and target["metadata"]["annotations"][REVISION] == pending_target["metadata"]["annotations"][REVISION]
        and new["pod_uid"] != baseline["status"]["pod_uid"] and new["boot_id"] != baseline["status"]["boot_id"]
        and new["value_digest"] == hashlib.sha256(pair["demo"].encode()).hexdigest()
        and len(set(after["replica_sets"]) - set(baseline["footprint"]["replica_sets"])) == 1 and after["template"] == expected,
        "Pending restart did not produce exactly one expected rollout with committed values")
    app.frozen(after, seconds=7)
    e2e.selected = pair
    result = {"leaderTerminatedAfterSecretAndProtectedPendingCommit": True, "sameOriginalOperatorPodNewContainer": True,
        "newLeaseAndCurrentGrantActivation": True, "pendingSurvivedRestartBeforeExplicitUnpause": True,
        "newReplicaSetsAfterUnpause": 1, "onlyOwnRestartAnnotation": True, "newProcessVerifiedCommittedEnv": True, "production": False}
    write_private(directory / "complete.json", canonical(result))
    return result
