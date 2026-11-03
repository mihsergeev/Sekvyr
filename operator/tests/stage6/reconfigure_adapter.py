"""Explicit live-coordinator callback. Import/local tests perform no live work.

The independent protocol fixture supplies keys; replay-verified current state
supplies the exact cursor. Enrollment/recovery candidates are persisted BEFORE
requests and resolve only their exact slot. There is no automatic rebase/reset.
"""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import uuid

from application import IMAGE, RESOURCE, REVISION, TARGET, node_fingerprint, require, wait, write_values_once
from fixture import canonical, write_private
from protocol import key_descriptor
from reconfigure import Reconfiguration, next_trust_bundle


def _saved(path, factory):
    if path.exists():
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 64 << 20, "Saved recovery input path unsafe")
        return json.loads(path.read_bytes())
    value = factory()
    require(isinstance(value, dict), "Missing persisted recovery input requires explicit review")
    write_private(path, canonical(value))
    return value


class RecoveryAdapter:
    def __init__(self, coordinator, expected_values_path, image, helm, chart, node_name=""):
        self.coordinator, self.app, self.panel = coordinator, coordinator.app, coordinator.panel
        self.private = self.app.task / "private"
        self.image, self.helm, self.chart, self.node_name = image, helm, Path(chart), node_name
        require(IMAGE.fullmatch(image) is not None, "Recovery requires reviewed digest-pinned image")
        self.active_pointer = self.private / "recovery-adapter-active-values.json"
        self._active_bytes = None
        self.expected_values_path = self._values_path(expected_values_path)
        if self.active_pointer.exists():
            require(not self.active_pointer.is_symlink() and self.active_pointer.stat().st_size <= 16384, "Active values pointer unsafe")
            self._active_bytes = self.active_pointer.read_bytes()
            active = json.loads(self._active_bytes)
            require(active["format"] == "sekvyr-stage6-active-values-v1" and active["namespaceUID"] == self.app.namespace_uid
                and active["installationID"] == self.app.protocol.installation_id, "Active values pointer identity mismatch")
            selected = self._values_path(self.private / active["file"])
            require(hashlib.sha256(selected.read_bytes()).hexdigest() == active["sha256"], "Active values digest changed")
            self.expected_values_path = selected

    def __repr__(self):
        return "<explicit signed recovery adapter [redacted]>"

    def _values_path(self, value):
        path = Path(value).absolute()
        require(path.parent == self.private and path.resolve() == path and path.is_file() and not path.is_symlink()
            and path.stat().st_size <= 1 << 20, "Exact private reviewed values file required")
        return path

    def _keys(self, protocol):
        return {"node": node_fingerprint(protocol), **{name: key_descriptor(getattr(protocol, name))["key_id"]
            for name in ("admin", "publisher", "witness", "fencer")}}

    def _baseline(self):
        target, status = self.app.get("Secret", TARGET), wait(self.app.status)
        return {"targetUID": target["metadata"]["uid"], "dataHash": hashlib.sha256(canonical(target["data"])).hexdigest(),
            "revision": target["metadata"]["annotations"][REVISION], "footprint": self.app.footprint(),
            "bootID": status["boot_id"], "podUID": status["pod_uid"],
            "lastSuccessfulSyncTime": self.app.get("SekvyrSecret", RESOURCE).get("status", {}).get("lastSuccessfulSyncTime")}

    def _fresh_current(self, snapshot, stopped_status):
        current = self.app.current(snapshot, True)
        return current and current.get("status", {}).get("lastSuccessfulSyncTime") not in (None, stopped_status["lastSuccessfulSyncTime"])

    def _unchanged(self, baseline):
        target = self.app.get("Secret", TARGET)
        require(target["metadata"]["uid"] == baseline["targetUID"] and target["metadata"]["annotations"][REVISION] == baseline["revision"]
            and hashlib.sha256(canonical(target["data"])).hexdigest() == baseline["dataHash"], "Recovery changed verified target bytes or revision")
        self.app.frozen(baseline["footprint"], seconds=1)
        status = wait(self.app.status)
        require(status["boot_id"] == baseline["bootID"] and status["pod_uid"] == baseline["podUID"], "Recovery restarted the application")

    def _enroll(self, protocol, transition, input_state):
        """Panel.enroll constructs a fresh candidate; retries need this saved one."""
        client = self.panel.witness_client
        prefix = "/v2/logs/" + protocol.scope["log_id"]
        current = self.panel.current()
        if current["cursor"] == transition["body"]["expected"]:
            require(current["authority"] == input_state["authority"] and current["snapshot"] == input_state["snapshot"],
                "Enrollment parent changed before exact CAS")
            try:
                client.request("POST", prefix + "/transitions", canonical(transition),
                    {"Content-Type": "application/json"}, expected=(200, 409))
            except RuntimeError:
                # Lost acknowledgement can only resolve the exact next record.
                pass
        sequence = str(int(transition["body"]["expected"]["journal_sequence"]) + 1)
        _, raw, _ = client.request("GET", prefix + "/records/" + sequence)
        record = json.loads(raw)
        require(record.get("kind") == "transition" and record.get("transition") == transition,
            "Enrollment CAS conflict requires independent review; no rebase")
        current = self.panel.current()
        require(current["snapshot"] == input_state["snapshot"] and current["authority"] == transition["body"]["authority"]
            and current["enrollments"][protocol.installation_id] == transition["body"]["enrollment"],
            "Committed enrollment differs from exact saved candidate")
        return current

    def _mark_active(self, values_path, generation):
        value = {"format": "sekvyr-stage6-active-values-v1", "namespaceUID": self.app.namespace_uid,
            "installationID": self.app.protocol.installation_id, "generation": generation, "file": values_path.name,
            "sha256": hashlib.sha256(values_path.read_bytes()).hexdigest()}
        raw = canonical(value)
        if self.active_pointer.exists():
            require(not self.active_pointer.is_symlink(), "Active values pointer symlink refused")
            current = self.active_pointer.read_bytes()
            if current == raw:
                self._active_bytes = raw
                self.expected_values_path = values_path
                return
            require(current == self._active_bytes, "Active values pointer changed concurrently")
        else:
            require(self._active_bytes is None, "Active values pointer disappeared")
        temporary = self.private / (".recovery-active-values-" + uuid.uuid4().hex)
        write_private(temporary, raw)
        os.replace(temporary, self.active_pointer)
        self._active_bytes, self.expected_values_path = raw, values_path

    def __call__(self, new_protocol, current_state, generation):
        require(type(generation) is int and 2 <= generation <= 9007199254740991, "Explicit recovery generation required")
        directory = self.private / ("recovery-adapter-g" + str(generation))
        directory.mkdir(mode=0o700, exist_ok=True)
        require(not directory.is_symlink(), "Recovery adapter directory symlink refused")
        require(new_protocol.scope == self.app.protocol.scope and new_protocol.genesis_hash == self.app.protocol.genesis_hash
            and new_protocol.registration == self.app.protocol.registration and new_protocol.genesis_record == self.app.protocol.genesis_record
            and new_protocol.installation_id == self.app.protocol.installation_id,
            "Recovery cannot replace scope, signed genesis or original administrator pin")
        require(current_state["scope"] == new_protocol.scope and current_state["genesis_hash"] == new_protocol.genesis_hash,
            "Recovery input canonical scope mismatch")
        keys = self._keys(new_protocol)
        input_path = directory / "input.json"
        if input_path.exists():
            saved = _saved(input_path, lambda: None)
            require(saved["generation"] == generation and saved["state"] == current_state and saved["keys"] == keys
                and saved["image"] == self.image and saved["nodeName"] == self.node_name,
                "Recovery callback input changed after preparation")
        else:
            old_pin = self.app.created.get(("Secret", self.app.state_name))
            require(old_pin is not None and generation > self.app.generation, "Previous state creation pin and older generation required")
            saved = {"generation": generation, "previousGeneration": self.app.generation, "previousStateUID": old_pin["uid"],
                "keys": keys, "image": self.image, "nodeName": self.node_name, "state": copy.deepcopy(current_state),
                "expectedValues": json.loads(self.expected_values_path.read_bytes()),
                "baseline": self._baseline()}
            write_private(input_path, canonical(saved))
        if self.app.generation == generation:
            # An interrupted call may already have persisted the NEW ref set.
            # Restore only the explicitly supplied, fingerprint-matched version;
            # a receipt from an older generation never downgrades current keys.
            self.app.protocol = new_protocol
            self.panel.protocol = new_protocol
            self.coordinator.protocol = new_protocol
        done_file = directory / "done.json"
        if done_file.exists():
            # Receipt replay is a no-op, including after later normal publishes.
            return _saved(done_file, lambda: None)
        expected = saved["expectedValues"]
        require(expected["installation"]["bootstrapGeneration"] == saved["previousGeneration"]
            and expected["ha"]["config"]["journal"] == new_protocol.registration, "Reviewed previous values or genesis pin changed")
        job = Reconfiguration(self.app, self.helm, self.chart, expected, "adapter-g" + str(generation))
        completed_recovery = directory / "recovery-complete.json"
        if not completed_recovery.exists():
            job.stop_operator()
            _saved(directory / "stopped-status.json", lambda: {"lastSuccessfulSyncTime":
                self.app.get("SekvyrSecret", RESOURCE).get("status", {}).get("lastSuccessfulSyncTime")})
            trust = _saved(directory / "trust.json", lambda: next_trust_bundle(self.app, new_protocol, generation, current_state["snapshot"]))
            enrollment = job.prepare(generation, new_protocol, new_protocol.node, trust, new_protocol.fencer)
            # Both API transport and CLI now use only explicitly prepared keys.
            self.panel.protocol = new_protocol
            transition = _saved(directory / "enrollment.json", lambda: new_protocol.transition("enroll-installation", current_state, enrollment=enrollment))
            require(transition["body"]["expected"] == current_state["cursor"] and transition["body"]["enrollment"] == enrollment,
                "Saved enrollment candidate differs from prepared bootstrap")
            after_enrollment = self._enroll(new_protocol, transition, current_state)
            who = json.loads(self.coordinator.cluster.kube("auth", "whoami", "-o", "json").stdout)["status"]["userInfo"]
            subject = {"username": who["username"], "uid": who.get("uid", "")}
            require(expected["ha"]["fencer"]["bootstrapSubjects"] == [subject], "Recovery bootstrap subject changed")
            values = _saved(directory / "next-values.json", lambda: self.app.chart_values(self.image, subject,
                self.coordinator.gateway_origin, self.app.materials["journal_ca"], self.node_name,
                expected["ha"]["webhook"].get("serviceName", "")))
            installation = job.apply(values, after_enrollment)
            plan = _saved(directory / "plan.json", lambda: self.app.recovery_plan(after_enrollment,
                previous_generation=saved["previousGeneration"], previous_state_uid=saved["previousStateUID"], allow_rollout=False))
            require(plan["body"]["cursor"] == after_enrollment["cursor"] and plan["body"]["snapshot"] == current_state["snapshot"]
                and not plan["body"]["allow_rollout"], "Recovery plan differs from exact reviewed checkpoint")

            def exported():
                envelope, wrapper = self.panel.offline_export()
                return {"envelope": json.loads(envelope), "wrapper": json.loads(wrapper)}
            export = _saved(directory / "encrypted-export.json", exported)
            self.panel.recover(plan, canonical(export["envelope"]), canonical(export["wrapper"]), installation)
            state = self.app.get("Secret", self.app.state_name)
            restored = json.loads(base64.b64decode(state["data"]["state.json"]))
            require(restored["recovery"] == {"id": plan["body"]["recovery_id"],
                "planHash": hashlib.sha256(canonical(plan)).hexdigest(), "phase": "complete"}
                and restored["installationID"] == new_protocol.installation_id and restored["bootstrapGeneration"] == generation
                and restored["nodeFingerprint"] == node_fingerprint(new_protocol)
                and restored["trustBundleUID"] == installation["trustBundleSecret"]["uid"]
                and len(restored["bindings"]) == 1
                and all(not value["rollout"]["intent"]["eligible"] for value in restored["bindings"].values()),
                "Recovery CLI completion lacks exact durable checkpoint or invalidated intent")
            self._unchanged(saved["baseline"])
            write_private(completed_recovery, canonical({"generation": generation, "snapshot": current_state["snapshot"]}))
        values = _saved(directory / "next-values.json", lambda: None)
        stopped_status = _saved(directory / "stopped-status.json", lambda: None)
        job.resume_operator()
        self.app.poke()
        wait(lambda: self._fresh_current(current_state["snapshot"], stopped_status), timeout=240)
        self._unchanged(saved["baseline"])
        active = self.private / ("active-values-generation-" + str(generation) + ".json")
        write_values_once(active, canonical(values))
        self._mark_active(active, generation)
        self.coordinator.protocol = new_protocol
        result = {"signedRecoveryComplete": True, "bootstrapGeneration": generation,
            "twoOperatorReplicas": True, "twoFencerReplicas": True, "sameDataNoHistoricalRollout": True, "production": False}
        write_private(done_file, canonical(result))
        return result
