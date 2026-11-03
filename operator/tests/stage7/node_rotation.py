"""Explicit node/read-key replacement in the existing captured HA Helm trial.

No live action on import. Signed candidates are persisted before RPC; a lost
CAS acknowledgement resolves only its exact journal slot. Interrupted native
Helm mutations need coordinator review, never reconstruction from live names.
"""

import base64
import copy
import hashlib
import json

from cryptography.exceptions import InvalidTag

from application import APP, RELEASE, RESOURCE, REVISION, SA, STORE, TARGET, node_fingerprint, wait
from app_modes import require
from e2e_cases import replicas_current, reviewed_values
from fixture import canonical, pem, write_private
from helm_lifecycle import identity
from reconfigure import Reconfiguration, next_trust_bundle
from protocol import domain
from rotation_cases import (decrypt_snapshot, envelope_hash, load_protocol_version,
    save_protocol_version, unwrap, binary)


def exact(path, factory):
    require(not path.is_symlink(), "Rotation artifact symlink refused")
    if path.exists():
        raw = path.read_bytes()
        value = json.loads(raw)
        require(raw == canonical(value), "Rotation artifact changed encoding")
        return value
    value = factory()
    write_private(path, canonical(value))
    return value


def validate_authority(old, new):
    require(new.scope == old.scope and new.installation_id == old.installation_id
        and new.binding_id == old.binding_id and new.registration == old.registration
        and new.genesis_record == old.genesis_record and new.genesis_hash == old.genesis_hash,
        "Node rotation cannot replace original scope or administrator genesis pin")
    expected = copy.deepcopy(old.authority)
    expected["revision"] = str(int(expected["revision"]) + 1)
    expected["read_key_epoch"] = str(int(expected["read_key_epoch"]) + 1)
    require(new.authority == expected and new.node_public != old.node_public and new.read_key != old.read_key,
        "Only node and AES read-key rotation is allowed")
    # Public role descriptors above and private/public correspondence checked by
    # load_protocol_version ensure no signer substitution hidden in the fixture.


def verify_key_revocation(old, new, envelope, wrapper):
    validate_authority(old, new)
    require(unwrap(new, wrapper, new.node) == new.read_key, "New node wrapper does not round trip")
    plain = decrypt_snapshot(new, envelope, new.read_key)
    for label, operation in (("Retired node still unwraps new key", lambda: unwrap(new, wrapper, old.node)),
            ("Retired AES key still decrypts new snapshot", lambda: decrypt_snapshot(new, envelope, old.read_key))):
        try:
            operation()
        except InvalidTag:
            pass
        else:
            raise RuntimeError(label)
    return plain


def successor_values(previous, reviewed, old_state):
    """Keep resource policy and external ownership; replace only bootstrap refs."""
    require(previous["ha"]["enabled"] and previous["ha"].get("maintenance") is True
        and previous["replicas"] == 0 and reviewed["ha"]["enabled"],
        "Native Helm stop must precede bootstrap replacement")
    result = copy.deepcopy(previous)
    before, after = previous["installation"], reviewed["installation"]
    require(after["bootstrapGeneration"] == before["bootstrapGeneration"] + 1
        and old_state == {"name": before["stateSecret"]["name"], "uid": before["stateSecret"]["uid"]},
        "Exact previous state creation pin and next generation required")
    mutable = {"bootstrapGeneration", "identityKeySecret", "trustBundleSecret", "stateSecret"}
    require({k: v for k, v in before.items() if k not in mutable} ==
        {k: v for k, v in after.items() if k not in mutable}, "Node recovery changes unrelated installation policy")
    result["installation"].update({key: copy.deepcopy(after[key]) for key in mutable})
    result["ha"]["managedObjects"] = copy.deepcopy(reviewed["ha"]["managedObjects"])
    result["ha"]["fencer"]["signingKeySecret"] = copy.deepcopy(reviewed["ha"]["fencer"]["signingKeySecret"])
    expected_ha = copy.deepcopy(previous["ha"])
    expected_ha["managedObjects"] = reviewed["ha"]["managedObjects"]
    expected_ha["fencer"]["signingKeySecret"] = reviewed["ha"]["fencer"]["signingKeySecret"]
    require(expected_ha == reviewed["ha"], "Node recovery cannot change TLS, gateway, identity roles or webhook endpoint")
    retired = result["ha"]["webhook"].setdefault("retiredStateSecrets", [])
    require(old_state not in retired and all(value["name"] != old_state["name"] and value["uid"] != old_state["uid"]
        for value in retired), "Previous state already retired or identity conflicts")
    retired.append(copy.deepcopy(old_state))
    # Retire old identity/trust too as local protected targets, not new rights.
    for key in ("identityKeySecret", "trustBundleSecret", "stateSecret"):
        for field, ref in (("protectedSecretNames", "name"), ("protectedSecretUIDs", "uid")):
            values = result["installation"][field]
            if before[key][ref] not in values:
                values.append(before[key][ref])
    return result


class NodeRotation:
    def __init__(self, e2e):
        require(e2e.installed and e2e.lifecycle and e2e.lifecycle.managed and e2e.app.generation == 1,
            "Node rotation requires the original captured generation-one Helm installation")
        self.e, self.c, self.app = e2e, e2e.c, e2e.app
        self.panel, self.original = self.c.panel, self.c.protocol
        self.root = e2e.root / "node-rotation"
        self.root.mkdir(mode=0o700, exist_ok=True)
        require(not self.root.is_symlink(), "Unsafe node rotation directory")

    def __repr__(self):
        return "<stage7 explicit node rotation [redacted]>"

    def _native_upgrade(self, label, values):
        intent = self.root / (label + "-intent.json")
        done = self.root / (label + "-done.json")
        if done.exists():
            require(exact(intent, lambda: None) == values, "Native Helm resume input changed")
            return
        require(not intent.exists(), "Interrupted native Helm change needs explicit coordinator review")
        exact(intent, lambda: values)
        self.e.lifecycle.upgrade(values)
        self.e.register_managed()
        self.e.values = copy.deepcopy(values)
        exact(done, lambda: {"nativeHelmUpgrade": True})

    def _transition(self, candidate, snapshot):
        body = candidate["body"]
        current = self.panel.current()
        prefix = "/v2/logs/" + self.original.scope["log_id"]
        if current["cursor"] == body["expected"]:
            require(current["authority_digest"] == body["previous_authority_digest"], "Transition parent authority changed")
            try:
                self.panel.witness_client.request("POST", prefix + "/transitions", canonical(candidate),
                    {"Content-Type": "application/json"}, expected=(200, 409))
            except RuntimeError:
                pass  # A lost acknowledgement is resolved only by this slot.
        sequence = str(int(body["expected"]["journal_sequence"]) + 1)
        _, raw, _ = self.panel.witness_client.request("GET", prefix + "/records/" + sequence)
        record = json.loads(raw)
        require(record.get("kind") == "transition" and record.get("transition") == candidate,
            "Rotation CAS conflict requires independent review; no rebase")
        current = self.panel.current()
        require(current["snapshot"] == snapshot and current["authority"] == body["authority"],
            "Transition activated a different authority or checkpoint")
        if body.get("enrollment") is not None:
            require(current["enrollments"][self.original.installation_id] == body["enrollment"],
                "New signed enrollment differs from prepared creation pins")
        return current

    def _unchanged(self, baseline):
        target = self.app.get("Secret", TARGET)
        require(target["metadata"]["uid"] == baseline["targetUID"] and target["data"] == baseline["data"]
            and target["metadata"]["annotations"][REVISION] == baseline["revision"], "Node recovery changed application bytes or opaque revision")
        self.app.frozen(baseline["footprint"])
        status = wait(self.app.status)
        require((status["pod_uid"], status["boot_id"]) == (baseline["status"]["pod_uid"], baseline["status"]["boot_id"]),
            "Node recovery restarted application")

    def _review_webhook(self, values):
        rendered, _ = self.e.lifecycle.render(values)
        desired = [value for value in rendered if value["kind"] == "ValidatingWebhookConfiguration"]
        require(len(desired) == 1, "Exactly one installation webhook required")
        value, lifecycle = desired[0], self.e.lifecycle
        key = identity(value)
        require(key in lifecycle.managed, "Webhook has no original captured Helm identity")
        saved = lifecycle.managed[key]
        current = lifecycle._get(saved["manifest"])
        lifecycle._owned(current, saved["uid"])
        lifecycle._matches(current, saved["manifest"])
        review = {"uid": saved["uid"], "before": saved["manifest"], "after": value}
        require(exact(self.root / "webhook-update-reviewed.json", lambda: review) == review,
            "Persisted webhook review differs from retained exact input")
        # Cluster API verifies immutable service/trust/rules/namespace, creation
        # UID, prior active guard and RV, then appends approval+applied receipts.
        updated = self.c.cluster.update_cluster_webhook(value)
        require(updated["metadata"]["uid"] == saved["uid"], "Webhook replacement is forbidden")
        lifecycle._matches(updated, value)
        lifecycle.managed[key] = {"manifest": copy.deepcopy(value), "uid": saved["uid"], "data": value.get("data")}
        exact(self.root / "webhook-update-complete.json", lambda: {"uid": saved["uid"],
            "guard": self.c.cluster.guard_hash(updated)})
        return rendered

    def run(self):
        require(not (self.root / "run-started.json").exists(), "Interrupted node rotation requires exact phase review, not automatic replay")
        initial = self.panel.current()
        old = copy.copy(self.original)
        old.authority = copy.deepcopy(initial["authority"])
        expected = copy.deepcopy(self.original.authority)
        expected["revision"] = old.authority["revision"]
        require(expected == old.authority, "Node rotation needs the independently known unchanged role keys")
        target = self.app.get("Secret", TARGET)
        wait(lambda: self.app.current(initial["snapshot"], True), timeout=240)
        baseline = {"targetUID": target["metadata"]["uid"], "data": target["data"],
            "revision": target["metadata"]["annotations"][REVISION], "footprint": self.app.footprint(), "status": wait(self.app.status),
            "oldState": {"name": self.app.state_name, "uid": self.app.get("Secret", self.app.state_name)["metadata"]["uid"]}}
        require(target["data"] == {"GENERATION": base64.b64encode(self.e.selected["generation"].encode()).decode(),
            "DEMO_VALUE": base64.b64encode(self.e.selected["demo"].encode()).decode()}, "Selected values differ from verified target")
        exact(self.root / "run-started.json", lambda: {"baseline": baseline, "values": self.e.values, "initial": initial})
        stopped = copy.deepcopy(self.e.values)
        stopped["replicas"] = 0
        stopped["ha"]["maintenance"] = True
        self._native_upgrade("stop", stopped)
        job = Reconfiguration(self.app, self.e.helm, self.e.chart, stopped, "stage7-node")
        job.stop_operator()  # Already zero: verifies exact specs and no old Pods.
        parent = self.panel.current()  # After old sessions have stopped writing.
        require(parent["snapshot"] == initial["snapshot"] and parent["authority"] == old.authority,
            "Canonical data changed while stopping old operator")
        node = save_protocol_version(self.root / "new-node", old, "node")
        new = save_protocol_version(self.root / "new-read-key", node, "read")
        new = load_protocol_version(self.root / "new-read-key", old)
        validate_authority(old, new)
        projected = self.c.cluster.kube("create", "token", SA, "-n", self.app.namespace,
            "--audience=sekvyr", "--duration=10m").stdout.strip()
        _, session = self.panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": projected})
        self.panel.request("POST", "/api/v1/machine/report", {"public_key": base64.b64encode(new.node_public).decode()}, session["access_token"])
        old_wrapper = exact(self.root / "old-node-wrapper.json", old.reader_wrap)
        meta = json.loads((self.panel.private / "panel-bootstrap.json").read_bytes())
        code, denied = self.panel.owner_request("POST", "/api/e2e2/views/" + old.scope["view_id"] + "/readers",
            {"machine_id": meta["machine_id"], "wrapper": old_wrapper}, (400, 403, 409))
        require(code in (400, 403, 409) and (denied.get("reason") or denied.get("detail")) in
            ("AwaitingProjectKey", "ContextMismatch"), "Old node report/wrap was not rejected")
        envelope = exact(self.root / "activating-envelope.json", lambda: new.snapshot(int(parent["snapshot"]["sequence"]) + 1,
            parent["snapshot"]["envelope_hash"], self.e.selected["generation"], self.e.selected["demo"], action="rotate-read-key")[0])
        wrapper = exact(self.root / "new-reader-wrapper.json", new.reader_wrap)
        verify_key_revocation(old, new, envelope, wrapper)
        rotation = exact(self.root / "read-transition.json", lambda: old.transition("rotate-read-key", parent,
            authority=new.authority, activating_envelope=envelope))
        self.panel.owner_request("POST", "/api/e2e2/views/" + old.scope["view_id"] + "/rotation-stage",
            {"envelope": envelope, "readers": [{"machine_id": meta["machine_id"], "wrapper": wrapper}]}, (201,))
        snapshot = {"sequence": envelope["body"]["header"]["sequence"], "envelope_hash": envelope_hash(envelope),
            "read_key_epoch": new.authority["read_key_epoch"], "publisher_policy_epoch": new.authority["publisher_policy_epoch"]}
        after_read = self._transition(rotation, snapshot)
        self.panel.protocol = new
        self.panel.owner_request("POST", "/api/e2e2/views/" + new.scope["view_id"] + "/rotation-project", {})
        self._unchanged(baseline)
        trust = exact(self.root / "next-trust.json", lambda: next_trust_bundle(self.app, new, 2, snapshot))
        enrollment = job.prepare(2, new, new.node, trust, new.fencer)
        candidate = exact(self.root / "enrollment.json", lambda: new.transition("enroll-installation", after_read, enrollment=enrollment))
        current = self._transition(candidate, snapshot)
        # Enrollment increments revision without replacing the original keys.
        new.authority = copy.deepcopy(current["authority"])
        self.c.protocol = self.app.protocol = self.panel.protocol = new
        previous = self.e.values
        subject = previous["ha"]["fencer"]["bootstrapSubjects"][0]
        params = json.loads((self.c.task / "infrastructure-parameters.json").read_bytes())
        reviewed = reviewed_values(self.app, self.e.image, subject, self.c.gateway_origin,
            self.app.materials["journal_ca"], params["node_name"])
        # Keep any already approved webhook endpoint/history and non-bootstrap
        # policy from the exact active values, never reset them to defaults.
        reviewed["ha"]["webhook"] = copy.deepcopy(previous["ha"]["webhook"])
        reviewed["ha"]["maintenance"] = True
        reviewed["installation"]["protectedSecretNames"] = copy.deepcopy(previous["installation"]["protectedSecretNames"])
        reviewed["installation"]["protectedSecretUIDs"] = copy.deepcopy(previous["installation"]["protectedSecretUIDs"])
        values = successor_values(previous, reviewed, baseline["oldState"])
        for (kind, name), pin in self.app.created.items():
            if any(value["manifest"]["kind"] == kind and value["manifest"]["metadata"]["name"] == name for value in self.e.lifecycle.managed.values()):
                continue
            if any(value["manifest"]["kind"] == kind and value["manifest"]["metadata"]["name"] == name for value in self.e.lifecycle.retained.values()):
                continue
            existing = [value for value in self.e.lifecycle.external if (value["kind"], value["name"]) == (kind, name)]
            require(not existing or existing == [{"kind": kind, "name": name, "uid": pin["uid"]}], "Historical external UID drift")
            if not existing:
                self.e.lifecycle.external.append({"kind": kind, "name": name, "uid": pin["uid"]})
        return self._finish_after_enrollment(values, current, baseline, new, snapshot, envelope, wrapper)

    def _finish_after_enrollment(self, values, current, baseline, new, snapshot, envelope, wrapper):
        rendered = self._review_webhook(values)
        self._native_upgrade("bootstrap", values)
        installation = [json.loads(value["data"]["installation.json"]) for value in rendered
            if value["kind"] == "ConfigMap" and "installation.json" in value.get("data", {})]
        require(len(installation) == 1, "Recovery installation render ambiguous")
        plan = exact(self.root / "recovery-plan.json", lambda: self.app.recovery_plan(current,
            previous_generation=1, previous_state_uid=baseline["oldState"]["uid"], allow_rollout=False))
        require(plan["body"]["cursor"] == current["cursor"] and not plan["body"]["allow_rollout"], "Recovery plan cursor/policy drift")
        self.panel.recover(plan, canonical(envelope), canonical(wrapper), installation[0])
        state = json.loads(base64.b64decode(self.app.get("Secret", self.app.state_name)["data"]["state.json"]))
        require(state["bootstrapGeneration"] == 2 and state["nodeFingerprint"] == node_fingerprint(new)
            and state["trustBundleUID"] == installation[0]["trustBundleSecret"]["uid"]
            and state["recovery"] == {"id": plan["body"]["recovery_id"], "planHash": hashlib.sha256(canonical(plan)).hexdigest(), "phase": "complete"}
            and len(state["bindings"]) == 1 and all(not value["rollout"]["intent"]["eligible"] for value in state["bindings"].values()),
            "Signed recovery lacks exact completion or invalidated rollout intent")
        self._unchanged(baseline)
        values = copy.deepcopy(values)
        values["replicas"] = 2
        values["ha"]["maintenance"] = False
        self._native_upgrade("resume", values)
        self.app.poke()
        wait(lambda: replicas_current(self.app), timeout=240)
        wait(lambda: self.app.current(snapshot, True), timeout=240)
        self._unchanged(baseline)
        self._post_change()
        result = {"nodeAndReadKeyRotated": True, "oldNodeAndReadKeyRejected": True, "bootstrapGeneration": 2,
            "nativeHelmLifecyclePreserved": True, "signedRecoveryWithoutHistoricalRollout": True,
            "postRotationNewReplicaSets": 1, "production": False}
        exact(self.root / "complete.json", lambda: result)
        return result

    def _post_change(self):
        before, old = self.app.footprint(), wait(self.app.status)
        pair = self.e.pair("after-node-rotation")
        require(pair != self.e.selected, "Post-rotation proof requires actual changed plaintext")
        snapshot = self.c.publish(pair["generation"], pair["demo"])
        self.app.poke()
        wait(lambda: self.app.current(snapshot, True), timeout=240)
        new = wait(lambda: value if (value := self.app.status()) and value["generation"] == pair["generation"] else False)
        after = self.app.footprint()
        require(new["pod_uid"] != old["pod_uid"] and new["boot_id"] != old["boot_id"]
            and new["value_digest"] == hashlib.sha256(pair["demo"].encode()).hexdigest()
            and len(set(after["replica_sets"]) - set(before["replica_sets"])) == 1, "Post-rotation change lacks one new verified process/ReplicaSet")
        target = self.app.get("Secret", TARGET)
        expected = copy.deepcopy(before["template"])
        expected["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/restart-" + target["metadata"]["uid"]] = target["metadata"]["annotations"][REVISION]
        require(after["template"] == expected, "Post-rotation rollout changed unrelated template fields")
        self.e.selected = pair


def resume_after_webhook_guard(rotation, retained_frame_locals):
    """Continue ONLY the exact retained failure before the reviewed webhook CAS.

    The coordinator explicitly supplies the still-live traceback frame. No
    context discovery, key generation, signed transition, enrollment, source
    publication or wholesale run replay occurs before this exact phase check.
    A later-phase interruption is intentionally outside this entry point.
    """
    saved = retained_frame_locals
    require(isinstance(saved, dict) and saved.get("self") is rotation,
        "Exact original NodeRotation failure frame required")
    required = {"values", "current", "baseline", "new", "snapshot", "envelope", "wrapper", "previous", "reviewed", "candidate", "job", "old", "parent"}
    require(required.issubset(saved), "Incomplete retained pre-webhook phase")
    root, app, e = rotation.root, rotation.app, rotation.e
    for name in ("webhook-update-complete.json", "bootstrap-intent.json", "bootstrap-done.json", "recovery-plan.json",
            "resume-intent.json", "resume-done.json", "complete.json", "webhook-guard-resume-started.json"):
        require(not (root / name).exists(), "Node resume phase already advanced; independent review required")
    for name in ("run-started.json", "read-transition.json", "enrollment.json", "activating-envelope.json",
            "new-reader-wrapper.json", "next-trust.json", "webhook-update-reviewed.json", "stop-intent.json", "stop-done.json"):
        require((root / name).is_file() and not (root / name).is_symlink(), "Required immutable Node phase artifact missing")
    baseline = exact(root / "run-started.json", lambda: None)
    require(baseline["baseline"] == saved["baseline"] and baseline["initial"]["snapshot"] == saved["parent"]["snapshot"],
        "Retained application baseline or stopped canonical checkpoint changed")
    previous, values = saved["previous"], saved["values"]
    require(e.values == previous == exact(root / "stop-intent.json", lambda: None)
        and previous["replicas"] == 0 and previous["ha"].get("maintenance") is True
        and values["replicas"] == 0 and values["ha"].get("maintenance") is True and app.generation == 2,
        "Only the captured stopped maintenance installation may resume")
    require(values == successor_values(previous, saved["reviewed"], saved["baseline"]["oldState"]),
        "Retained next values differ from the reviewed bootstrap-only delta")
    job = saved["job"]
    require(job.app is app and job.expected_values == previous and job.plan.get("phase") == "prepared"
        and job.plan_path.is_file() and not job.plan_path.is_symlink()
        and job.plan_path.read_bytes() == canonical(job.plan) and job._no_operator_pods(),
        "Prepared bootstrap receipt changed or an old operator is running")
    current, snapshot, new = saved["current"], saved["snapshot"], saved["new"]
    require(rotation.panel.current() == current and current["snapshot"] == snapshot,
        "Canonical cursor or authority advanced after the retained failure; no rebase")
    enrollment = exact(root / "enrollment.json", lambda: None)
    read = exact(root / "read-transition.json", lambda: None)
    require(enrollment == saved["candidate"] and read["body"]["expected"] == saved["parent"]["cursor"]
        and current["enrollments"][rotation.original.installation_id] == enrollment["body"]["enrollment"] == app.enrollment()
        and current["authority"] == enrollment["body"]["authority"] == new.authority,
        "Retained enrollment differs from committed canonical state or creation pins")
    prepared = load_protocol_version(root / "new-read-key", saved["old"])
    validate_authority(saved["old"], prepared)
    require(prepared.node_public == new.node_public and prepared.read_key == new.read_key
        and prepared.authority == read["body"]["authority"], "Retained node/read material differs from the saved version")
    for candidate in (read, enrollment):
        prepared.admin.public_key().verify(binary(candidate["signature"]),
            domain("sekvyr-e2e2/authority-transition/v1") + canonical(candidate["body"]))
    envelope = exact(root / "activating-envelope.json", lambda: None)
    wrapper = exact(root / "new-reader-wrapper.json", lambda: None)
    require(envelope == saved["envelope"] and wrapper == saved["wrapper"]
        and read["body"]["activating_envelope"] == envelope and envelope_hash(envelope) == snapshot["envelope_hash"],
        "Retained ciphertext or reader wrapper changed")
    verify_key_revocation(saved["old"], prepared, envelope, wrapper)
    trust = exact(root / "next-trust.json", lambda: None)
    for name, expected, immutable in ((app.node_secret_name, {"node.pem": pem(prepared.node)}, True),
            (app.trust_name, {"trust.json": canonical(trust)}, True),
            (app.fencer_signer_secret_name, {"key.pem": pem(prepared.fencer)}, True),
            (app.state_name, {"installation.json": canonical({"installationID": new.installation_id, "bootstrapGeneration": 2})}, False)):
        actual = app.get("Secret", name)
        require(actual.get("type") == "Opaque" and actual.get("immutable", False) is immutable
            and actual.get("data") == {key: base64.b64encode(raw).decode() for key, raw in expected.items()},
            "Prepared material or not-yet-recovered state changed")
    e.lifecycle._external_guard()
    e.lifecycle._retained_guard()
    rendered, _ = e.lifecycle.render(values)
    incoming = [value for value in rendered if value["kind"] == "ValidatingWebhookConfiguration"]
    require(len(incoming) == 1 and identity(incoming[0]) in e.lifecycle.managed, "Captured webhook identity missing")
    captured = e.lifecycle.managed[identity(incoming[0])]
    require(exact(root / "webhook-update-reviewed.json", lambda: None) == {"uid": captured["uid"],
        "before": captured["manifest"], "after": incoming[0]}, "Retained values differ from exact prior webhook review")
    live = e.lifecycle._get(captured["manifest"])
    e.lifecycle._owned(live, captured["uid"])
    e.lifecycle._matches(live, captured["manifest"])
    rotation._unchanged(saved["baseline"])
    # Receipt pins this explicit continuation before its first possible write.
    exact(root / "webhook-guard-resume-started.json", lambda: {"cursor": current["cursor"],
        "valuesSHA256": hashlib.sha256(canonical(values)).hexdigest(), "oldWebhookUID": captured["uid"]})
    return NodeRotation._finish_after_enrollment(rotation, values, current, saved["baseline"], new, snapshot, envelope, wrapper)


def resume_after_post_publish(rotation, retained_post_frame):
    """Observe only an already-published post-rotation change, never republish.

    Accepts the coordinator's exact still-live _post_change frame or its locals.
    Kubernetes calls are GET/server dry-run verification; only the final private
    receipt and e.selected in-memory observation are updated on success.
    """
    if hasattr(retained_post_frame, "f_locals"):
        require(retained_post_frame.f_code.co_name == "_post_change", "Exact post-change traceback frame required")
        saved = retained_post_frame.f_locals
    else:
        saved = retained_post_frame
    require(isinstance(saved, dict) and saved.get("self") is rotation
        and {"before", "old", "pair", "snapshot"}.issubset(saved), "Original already-published post-change frame required")
    app, e, root = rotation.app, rotation.e, rotation.root
    require(not (root / "complete.json").exists(), "Node completion already recorded; no replay")
    def artifact(path):
        require(path.is_file() and not path.is_symlink(), "Required exact post-publication artifact missing")
        return exact(path, lambda: None)
    started = artifact(root / "run-started.json")
    baseline = started["baseline"]
    before, old, pair, snapshot = (saved[name] for name in ("before", "old", "pair", "snapshot"))
    require(before == baseline["footprint"] and old == baseline["status"],
        "Pre-publication application differs from original no-historical-rollout baseline")
    require(pair == artifact(e.root / "after-node-rotation-values.json") and pair != e.selected
        and set(pair) == {"generation", "demo"} and all(isinstance(value, str) and 0 < len(value) <= 200 for value in pair.values()),
        "Post-publication values differ from exact original saved input")
    active = artifact(root / "resume-intent.json")
    require(artifact(root / "resume-done.json") == {"nativeHelmUpgrade": True}
        and artifact(root / "bootstrap-done.json") == {"nativeHelmUpgrade": True}
        and e.values == active and active["replicas"] == 2 and active["ha"].get("maintenance") is False
        and app.generation == active["installation"]["bootstrapGeneration"] == 2,
        "Exact completed native gen2 resume is required before post-publication observation")
    enrollment = artifact(root / "enrollment.json")
    plan = artifact(root / "recovery-plan.json")
    protocol = rotation.c.protocol
    current = rotation.c.current()
    require(current["scope"] == protocol.scope == rotation.original.scope
        and current["genesis_hash"] == protocol.genesis_hash == rotation.original.genesis_hash
        and current["snapshot"] == snapshot and current["authority"] == enrollment["body"]["authority"] == protocol.authority
        and current["enrollments"][protocol.installation_id] == enrollment["body"]["enrollment"] == app.enrollment()
        and enrollment["body"]["enrollment"]["bootstrap_generation"] == 2,
        "Canonical post-publication scope, snapshot, authority or enrollment changed; no rebase")
    bootstrap = copy.deepcopy(active)
    bootstrap["replicas"], bootstrap["ha"]["maintenance"] = 0, True
    require(artifact(root / "bootstrap-intent.json") == bootstrap
        and plan["body"]["operation"] == "recover" and plan["body"]["bootstrap_generation"] == 2
        and plan["body"]["allow_rollout"] is False and plan["body"]["scope"] == protocol.scope
        and plan["body"]["genesis_hash"] == protocol.genesis_hash and plan["body"]["node_fingerprint"] == node_fingerprint(protocol)
        and plan["body"]["previous_bootstrap_generation"] == 1
        and plan["body"]["previous_state_secret_uid"] == baseline["oldState"]["uid"],
        "Original signed recovery policy changed")
    # The signed plan's recovered snapshot must be the already persisted read
    # rotation; the later data publish must be exactly its next linked revision.
    activating = artifact(root / "activating-envelope.json")
    require(envelope_hash(activating) == plan["body"]["snapshot"]["envelope_hash"]
        and all(activating["body"]["header"][field] == plan["body"]["snapshot"][field]
            for field in ("sequence", "read_key_epoch", "publisher_policy_epoch"))
        and int(snapshot["sequence"]) == int(plan["body"]["snapshot"]["sequence"]) + 1,
        "Post-publication observation is not the one original next revision")
    protocol.admin.public_key().verify(binary(plan["signature"]), domain("sekvyr-e2e2/checkpoint-recovery/v1") + canonical(plan["body"]))
    e.lifecycle._external_guard()
    e.lifecycle._retained_guard()
    for captured in e.lifecycle.managed.values():
        live = e.lifecycle._get(captured["manifest"])
        e.lifecycle._owned(live, captured["uid"])
        e.lifecycle._matches(live, captured["manifest"])
    wait(lambda: replicas_current(app), timeout=240)
    status = wait(lambda: app.current(snapshot, True), timeout=240)
    target, state = app.get("Secret", TARGET), app.get("Secret", app.state_name)
    installation = active["installation"]
    require(state["metadata"]["uid"] == installation["stateSecret"]["uid"]
        and app.get("Secret", app.node_secret_name)["metadata"]["uid"] == installation["identityKeySecret"]["uid"]
        and app.get("Secret", app.trust_name)["metadata"]["uid"] == installation["trustBundleSecret"]["uid"],
        "Post-publication bootstrap creation pins changed")
    body = json.loads(base64.b64decode(state["data"]["state.json"], validate=True))
    require(body["version"] == 1 and body["installationID"] == protocol.installation_id and body["bootstrapGeneration"] == 2
        and body["nodeFingerprint"] == node_fingerprint(protocol) and body["trustBundleUID"] == installation["trustBundleSecret"]["uid"]
        and body["recovery"] == {"id": plan["body"]["recovery_id"], "planHash": hashlib.sha256(canonical(plan)).hexdigest(), "phase": "complete"},
        "Original gen2 signed recovery completion was lost or changed")
    store, cr = app.get("SekvyrStore", STORE), app.get("SekvyrSecret", RESOURCE)
    record = body["bindings"].get(store["metadata"]["uid"] + "/" + protocol.binding_id, {})
    head = record.get("head") or {}
    require(record.get("targetUID") == baseline["targetUID"] and record.get("crUID") == cr["metadata"]["uid"]
        and all(head.get(key) == snapshot[field] for key, field in (("Sequence", "sequence"), ("EnvelopeHash", "envelope_hash"),
            ("ReadKeyEpoch", "read_key_epoch"), ("PublisherPolicyEpoch", "publisher_policy_epoch"))),
        "Protected post-publication binding checkpoint differs")
    new = wait(lambda: value if (value := app.status()) and value["generation"] == pair["generation"] else False)
    after = app.footprint()
    revision = target["metadata"].get("annotations", {}).get(REVISION)
    expected = copy.deepcopy(before["template"])
    expected["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/restart-" + baseline["targetUID"]] = revision
    require(target["metadata"]["uid"] == baseline["targetUID"]
        and target["data"] == {"GENERATION": base64.b64encode(pair["generation"].encode()).decode(), "DEMO_VALUE": base64.b64encode(pair["demo"].encode()).decode()}
        and revision != baseline["revision"] and status["status"]["lastAppliedRevision"] == revision
        and new["pod_uid"] != old["pod_uid"] and new["boot_id"] != old["boot_id"]
        and new["value_digest"] == hashlib.sha256(pair["demo"].encode()).hexdigest()
        and after["deployment_uid"] == before["deployment_uid"] and set(before["replica_sets"]).issubset(after["replica_sets"])
        and len(set(after["replica_sets"]) - set(before["replica_sets"])) == 1 and after["template"] == expected,
        "Already-published change lacks exact one-ReplicaSet, new-process and own-annotation proof")
    require(rotation.c.current()["snapshot"] == snapshot and rotation.c.current()["authority"] == current["authority"],
        "Canonical context changed during post-publication observation")
    e.selected = copy.deepcopy(pair)
    result = {"nodeAndReadKeyRotated": True, "oldNodeAndReadKeyRejected": True, "bootstrapGeneration": 2,
        "nativeHelmLifecyclePreserved": True, "signedRecoveryWithoutHistoricalRollout": True,
        "postRotationNewReplicaSets": 1, "production": False}
    write_private(root / "post-publish-observed.json", canonical({"inputSHA256": hashlib.sha256(canonical({name: saved[name]
        for name in ("before", "old", "pair", "snapshot")})).hexdigest(), "alreadyPublishedObserved": True, "newReplicaSets": 1}))
    write_private(root / "complete.json", canonical(result))
    return result
