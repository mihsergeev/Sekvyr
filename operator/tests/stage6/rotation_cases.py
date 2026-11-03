"""Actual isolated-service key rotation cases, run only by the live coordinator.

Inputs, keys and exact signed CAS candidates live in exclusive private versioned
files. A response loss may resolve that exact journal slot; it never rebases an
old reviewed transition onto a different authority or cursor.
"""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import uuid

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from application import APP, RELEASE, REVISION, SA, TARGET, wait
from fixture import canonical, pem, write_private
from journal_client import JournalClient
from protocol import ProtocolAuthority, b64, domain, key_descriptor, signed


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def saved_candidate(path, factory):
    if not path.exists():
        write_private(path, canonical(factory()))
    return json.loads(path.read_bytes())


def binary(value):
    require(isinstance(value, str) and len(value) <= 16 << 20, "Rotation binary bounds invalid")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def envelope_hash(envelope):
    return hashlib.sha256(domain("sekvyr-e2e2/envelope-hash/v1") + canonical(envelope)).hexdigest()


def decrypt_snapshot(protocol, envelope, read_key):
    body, header = envelope["body"], envelope["body"]["header"]
    protocol.publisher.public_key().verify(binary(envelope["signature"]), domain("sekvyr-e2e2/publish/v1") + canonical(body))
    require(all(header[name] == value for name, value in protocol.scope.items()), "Snapshot escaped rotation scope")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=binary(header["snapshot_salt"]),
        info=domain("sekvyr-e2e2/snapshot-key/v1") + canonical(header)).derive(read_key)
    plain = AESGCM(key).decrypt(binary(body["nonce"]), binary(body["ciphertext"]), domain("sekvyr-e2e2/snapshot-aad/v1") + canonical(header))
    result = json.loads(plain)
    require(result["context"] == protocol.scope and result["format"] == "sekvyr-e2e2-values-v1", "Snapshot plaintext context invalid")
    return result


def unwrap(protocol, wrapper, private):
    body, context = wrapper["body"], wrapper["body"]["context"]
    protocol.publisher.public_key().verify(binary(wrapper["signature"]), domain("sekvyr-e2e2/reader-wrap-sign/v1") + canonical(body))
    require(all(context[name] == value for name, value in protocol.scope.items()), "Wrap escaped rotation scope")
    shared = private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), binary(body["ephemeral_public"])))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=binary(body["salt"]),
        info=domain("sekvyr-e2e2/reader-wrap-key/v1") + canonical(context)).derive(shared)
    raw = AESGCM(key).decrypt(binary(body["nonce"]), binary(body["ciphertext"]), domain("sekvyr-e2e2/reader-wrap-aad/v1") + canonical(context))
    result = json.loads(raw)
    require(set(result) == {"format", "context", "read_key"} and result["format"] == "sekvyr-e2e2-read-key-v1"
        and result["context"] == context, "Wrap payload context invalid")
    return binary(result["read_key"])


def save_protocol_version(path, parent, role):
    """An incomplete exclusive directory is a repair condition, never new keys."""
    path = Path(path)
    require(not path.exists(), "Rotation version already exists")
    path.mkdir(mode=0o700)
    value = copy.copy(parent)
    value.authority = copy.deepcopy(parent.authority)
    value.root = path
    if role in ("publisher", "witness", "admin", "fencer"):
        setattr(value, role, ed25519.Ed25519PrivateKey.generate())
        if role == "publisher":
            value.authority["publisher_keys"] = [key_descriptor(value.publisher)]
            value.authority["publisher_policy_epoch"] = str(int(value.authority["publisher_policy_epoch"]) + 1)
        elif role == "witness":
            value.authority["witness_key"] = key_descriptor(value.witness)
            value.authority["witness_epoch"] = str(int(value.authority["witness_epoch"]) + 1)
        elif role == "fencer":
            value.authority["fencer_keys"] = [key_descriptor(value.fencer)]
            value.authority["fencer_epoch"] = str(int(value.authority["fencer_epoch"]) + 1)
        else:
            value.authority["admin_key"] = key_descriptor(value.admin)
    elif role == "read":
        value.read_key = os.urandom(32)
        value.authority["read_key_epoch"] = str(int(value.authority["read_key_epoch"]) + 1)
    elif role == "node":
        value.node = ec.generate_private_key(ec.SECP256R1())
    else:
        raise RuntimeError("Unsupported rotation role")
    if role != "node":
        value.authority["revision"] = str(int(value.authority["revision"]) + 1)
    for name in ("admin", "publisher", "witness", "fencer", "node"):
        write_private(path / (name + ".key"), pem(getattr(value, name)))
    context = {"scope": value.scope, "installation_id": value.installation_id, "binding_id": value.binding_id,
        "read_key": b64(value.read_key), "panel_origin": value.panel_origin, "authority": value.authority}
    write_private(path / "context.json", canonical(context))
    write_private(path / "registration.json", canonical(parent.registration))
    write_private(path / "genesis-record.json", canonical(parent.genesis_record))
    return value


def load_protocol_version(path, original):
    path = Path(path)
    value = copy.copy(original)
    context = json.loads((path / "context.json").read_bytes())
    require(context["scope"] == original.scope and context["installation_id"] == original.installation_id
        and context["binding_id"] == original.binding_id and context["panel_origin"] == original.panel_origin,
        "Rotation version changed immutable context")
    require(json.loads((path / "registration.json").read_bytes()) == original.registration
        and json.loads((path / "genesis-record.json").read_bytes()) == original.genesis_record,
        "Rotation may not replace original genesis or administrator pin")
    value.root = path
    value.authority, value.read_key = context["authority"], binary(context["read_key"])
    for name in ("admin", "publisher", "witness", "fencer", "node"):
        setattr(value, name, serialization.load_pem_private_key((path / (name + ".key")).read_bytes(), password=None))
    require(value.authority["admin_key"] == key_descriptor(value.admin)
        and value.authority["witness_key"] == key_descriptor(value.witness)
        and value.authority["publisher_keys"] == [key_descriptor(value.publisher)]
        and value.authority["fencer_keys"] == [key_descriptor(value.fencer)] and len(value.read_key) == 32,
        "Rotation private material does not match reviewed authority")
    return value


class RotationCases:
    """Callbacks own lifecycle, UID-pinned reconfiguration and final recovery.

    on_witness_rotated(new_protocol, current_state): install BOTH new witness
    signers, explicitly update the panel's independent pin, restart/unseal panel.
    Do not update operator pins. Diagnostic logs may still need the old signer.

    on_reconfigure(new_protocol, current_state, generation): frontend helper
    stops operators, installs explicit new node/trust/state/fencer references,
    commits signed enrollment, performs signed checkpoint recovery, resumes 2+2.
    Callbacks must persist their own exact receipts and safely resume same input.
    """
    def __init__(self, app, panel, protocol, on_witness_rotated, on_reconfigure, generation=3, reviewed_initial_authority=None):
        require(callable(on_witness_rotated) and callable(on_reconfigure) and type(generation) is int and generation >= 2,
            "Explicit rotation lifecycle callbacks and generation required")
        reviewed = copy.copy(protocol)
        reviewed.authority = copy.deepcopy(protocol.authority)
        initial_authority = reviewed_initial_authority
        if initial_authority is not None:
            require(isinstance(initial_authority, dict) and isinstance(initial_authority.get("revision"), str)
                and initial_authority["revision"].isascii() and initial_authority["revision"].isdigit()
                and str(int(initial_authority["revision"])) == initial_authority["revision"]
                and int(protocol.authority["revision"]) <= int(initial_authority["revision"]) <= 18446744073709551615,
                "Reviewed initial enrollment revision invalid")
            expected = copy.deepcopy(protocol.authority)
            expected["revision"] = initial_authority["revision"]
            require(initial_authority == expected, "Enrollment revision may not introduce unreviewed keys or epochs")
            reviewed.authority = copy.deepcopy(initial_authority)
        self.app, self.panel, self.original = app, panel, reviewed
        self.protocol = reviewed
        self.on_witness_rotated, self.on_reconfigure = on_witness_rotated, on_reconfigure
        self.generation = generation
        self.root = panel.private / "rotation-cases"
        self.root.mkdir(mode=0o700, exist_ok=True)

    def __repr__(self):
        return "<isolated live rotation cases [redacted]>"

    def current(self):
        state = self.panel.current()
        require(state["scope"] == self.protocol.scope and state["genesis_hash"] == self.protocol.genesis_hash,
            "Live rotation state escaped original journal scope")
        return state

    def same_application(self, baseline):
        target = self.app.get("Secret", TARGET)
        require(target["metadata"]["uid"] == baseline["target_uid"] and target["data"] == baseline["data"]
            and target["metadata"]["annotations"][REVISION] == baseline["revision"], "Rotation changed selected data or opaque revision")
        self.app.frozen(baseline["footprint"], seconds=1)
        current = wait(self.app.status)
        require(current["pod_uid"] == baseline["status"]["pod_uid"] and current["boot_id"] == baseline["status"]["boot_id"],
            "Equal-value rotation restarted the application")

    def frozen_stale_operator(self, baseline):
        self.app.poke()
        wait(self.app.unavailable)
        self.same_application(baseline)

    def rejected(self, label, call, reasons):
        before = self.current()
        result = call()
        if len(result) == 3:
            code, raw, _ = result
            body = json.loads(raw)
        else:
            code, body = result
        require(code in (400, 403, 409, 503) and isinstance(body, dict)
            and (body.get("reason") or body.get("detail")) in reasons, "Retired key was not rejected for its cryptographic authority")
        after = self.current()
        require(after["cursor"] == before["cursor"] and after["authority"] == before["authority"]
            and after["snapshot"] == before["snapshot"], "Rejected key unexpectedly advanced canonical state")
        return {"case": label, "rejected": True, "cursor": before["cursor"]}

    def witness_request(self, suffix, body, expected=(200,)):
        return self.panel.witness_client.request("POST", "/v2/logs/" + self.protocol.scope["log_id"] + suffix,
            canonical(body), {"Content-Type": "application/json"}, expected)

    def stage_rotation(self, envelope, wrapper):
        meta = json.loads((self.panel.private / "panel-bootstrap.json").read_bytes())
        return self.panel.owner_request("POST", "/api/e2e2/views/" + self.protocol.scope["view_id"] + "/rotation-stage",
            {"envelope": envelope, "readers": [{"machine_id": meta["machine_id"], "wrapper": wrapper}]}, (201,))

    def project(self):
        return self.panel.owner_request("POST", "/api/e2e2/views/" + self.protocol.scope["view_id"] + "/rotation-project", {})

    def head_challenge(self, expected=(200,), request=None):
        state = self.current()
        request = request or {"request_nonce": b64(os.urandom(32)), "floor_sequence": state["snapshot"]["sequence"],
            "floor_hash": state["snapshot"]["envelope_hash"]}
        return request, self.panel.witness_client.request("POST", "/v1/logs/" + self.protocol.scope["log_id"] + "/head-challenge",
            canonical(request), {"Content-Type": "application/json"}, expected, maximum=16 << 10)

    def step(self, label, role, generation, demo, baseline):
        directory = self.root / label
        if (directory / "done.json").exists():
            self.protocol = load_protocol_version(directory, self.original)
            self.panel.protocol = self.protocol
            return json.loads((directory / "done.json").read_bytes())
        old = self.protocol
        if directory.exists():
            new = load_protocol_version(directory, self.original)
            require((directory / "plan.json").is_file(), "Incomplete rotation preparation requires explicit repair")
            plan = json.loads((directory / "plan.json").read_bytes())
        else:
            current = self.current()
            require(current["authority"] == old.authority, "Live authority differs from reviewed rotation parent")
            new = save_protocol_version(directory, old, role)
            kind = {"publisher": "rotate-publisher", "read": "rotate-read-key", "witness": "rotate-witness",
                "admin": "rotate-admin", "fencer": "rotate-fencer"}[role]
            envelope, wrapper = None, None
            if role in ("publisher", "read"):
                envelope, _ = new.snapshot(int(current["snapshot"]["sequence"]) + 1,
                    current["snapshot"]["envelope_hash"], generation, demo,
                    action="rotate-read-key" if role == "read" else "update")
                wrapper = new.reader_wrap()
                require(unwrap(new, wrapper, new.node) == new.read_key, "New wrap did not round trip")
                decrypt_snapshot(new, envelope, new.read_key)
            transition = old.transition(kind, current, authority=new.authority, activating_envelope=envelope)
            plan = {"parent_authority": old.authority, "expected": current["cursor"], "transition": transition,
                "envelope": envelope, "wrapper": wrapper}
            write_private(directory / "plan.json", canonical(plan))
        require(plan["parent_authority"] == old.authority and plan["transition"]["body"]["authority"] == new.authority,
            "Persisted rotation parent or candidate changed")
        current = self.current()
        if current["cursor"] == plan["expected"]:
            require(current["authority"] == old.authority, "Rotation cursor has different authority")
            if plan["envelope"] is not None:
                self.stage_rotation(plan["envelope"], plan["wrapper"])
            self.witness_request("/transitions", plan["transition"])
        else:
            # Resolve only the exact already-reviewed next slot, never rebase.
            sequence = str(int(plan["expected"]["journal_sequence"]) + 1)
            _, raw, _ = self.panel.witness_client.request("GET", "/v2/logs/" + old.scope["log_id"] + "/records/" + sequence)
            record = json.loads(raw)
            require(record.get("kind") == "transition" and record.get("transition") == plan["transition"],
                "Rotation cursor conflict requires explicit review")
        current = self.current()
        require(current["authority"] == new.authority, "Committed authority differs from signed rotation")
        if plan["envelope"] is not None:
            require(current["snapshot"]["envelope_hash"] == envelope_hash(plan["envelope"]), "Rotation activated another snapshot")
        self.protocol, self.panel.protocol = new, new
        evidence = []
        if role == "witness":
            if not (directory / "witness-updated.json").exists():
                if not (directory / "old-process-rejected.json").exists():
                    _, result = self.head_challenge(expected=(503,))
                    require(json.loads(result[1]).get("reason") == "SigningKeyUnavailable", "Old witness process still signed current authority")
                    write_private(directory / "old-process-rejected.json", canonical({"rejected": True, "authority": new.authority}))
                self.on_witness_rotated(new, current)
                write_private(directory / "witness-updated.json", canonical({"authority": new.authority, "cursor": current["cursor"]}))
            request, result = self.head_challenge()
            proof = json.loads(result[1])
            new.witness.public_key().verify(binary(proof["signature"]), domain("sekvyr-e2e2/head/v1") + canonical(proof["body"]))
            require(proof["body"]["request_nonce"] == request["request_nonce"] and proof["body"]["witness_epoch"] == new.authority["witness_epoch"]
                and proof["body"]["witness_key_id"] == key_descriptor(new.witness)["key_id"]
                and all(proof["body"][name] == value for name, value in new.scope.items())
                and proof["body"]["sequence"] == current["snapshot"]["sequence"]
                and proof["body"]["envelope_hash"] == current["snapshot"]["envelope_hash"], "New witness proof context differs")
            try:
                old.witness.public_key().verify(binary(proof["signature"]), domain("sekvyr-e2e2/head/v1") + canonical(proof["body"]))
            except InvalidSignature:
                pass
            else:
                raise RuntimeError("Retired witness key verified the new proof")
            evidence.append("old-witness-process-no-signing-fallback")
        self.project()
        current = self.current()
        if role == "publisher":
            retired = copy.copy(new)
            retired.publisher = old.publisher
            candidate = saved_candidate(directory / "old-publisher-envelope.json", lambda: retired.snapshot(
                int(current["snapshot"]["sequence"]) + 1, current["snapshot"]["envelope_hash"], generation, demo)[0])
            evidence.append(self.rejected("old-publisher", lambda: self.panel.owner_request("POST",
                "/api/e2e2/views/" + new.scope["view_id"] + "/envelopes", candidate, (400, 403, 409)), {"SignatureInvalid"})["case"])
        elif role == "read":
            try:
                decrypt_snapshot(new, plan["envelope"], old.read_key)
            except InvalidTag:
                pass
            else:
                raise RuntimeError("Retired AES read key decrypted the new snapshot")
            evidence.append("old-read-key-cannot-decrypt")
        elif role == "admin":
            authority = copy.deepcopy(current["authority"])
            authority["revision"] = str(int(authority["revision"]) + 1)
            authority["admin_key"] = key_descriptor(old.admin)
            bad = saved_candidate(directory / "old-admin-transition.json", lambda: old.transition("rotate-admin", current, authority=authority))
            require(bad["body"]["expected"] == current["cursor"], "Retired administrator test cursor changed")
            evidence.append(self.rejected("old-admin", lambda: self.witness_request("/transitions", bad, (400, 403, 409, 503)), {"TransitionInvalid"})["case"])
        elif role == "fencer":
            previous = current["grants"].get(new.installation_id)
            require(previous is not None, "Fencer rotation needs a previously exercised live grant")
            body = copy.deepcopy(previous["body"])
            body.update(term=str(int(body["term"]) + 1), previous_grant_hash=hashlib.sha256(
                domain("sekvyr-e2e2/fence-grant-hash/v1") + canonical(previous["body"])).hexdigest(),
                authority_digest=current["authority_digest"], snapshot=current["snapshot"])
            request = saved_candidate(directory / "old-fencer-grant.json", lambda: {"expected": current["cursor"],
                "grant": signed("sekvyr-e2e2/fence-grant/v1", body, old.fencer)})
            require(request["expected"] == current["cursor"], "Retired fencer test cursor changed")
            # The normal owner/admin mTLS identity has no grant-write rights.
            # Use the separately registered fencer transport identity so a 403
            # cannot be mistaken for retired signing-key rejection.
            client = JournalClient(self.panel.witness_client.origin, self.panel.private / "journal-ca.crt",
                self.panel.private / "fencer.crt", self.panel.private / "fencer.key")
            evidence.append(self.rejected("old-fencer", lambda: client.request("POST", "/v2/logs/" + new.scope["log_id"] + "/fence-grants",
                canonical(request), {"Content-Type": "application/json"}, (400, 403, 409, 503)), {"GrantInvalid"})["case"])
        self.frozen_stale_operator(baseline)
        receipt = {"case": label, "cursor": current["cursor"], "snapshot": current["snapshot"], "passed": evidence}
        write_private(directory / "done.json", canonical(receipt))
        return receipt

    def node(self, baseline):
        directory = self.root / "06-node"
        if (directory / "done.json").exists():
            self.protocol = load_protocol_version(directory, self.original)
            self.panel.protocol = self.protocol
            return
        old = self.protocol
        new = load_protocol_version(directory, self.original) if directory.exists() else save_protocol_version(directory, old, "node")
        meta = json.loads((self.panel.private / "panel-bootstrap.json").read_bytes())
        projected = self.panel.cluster.kube("create", "token", SA, "-n", self.app.namespace, "--audience=sekvyr", "--duration=10m").stdout.strip()
        _, session = self.panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": projected})
        self.panel.request("POST", "/api/v1/machine/report", {"public_key": base64.b64encode(new.node_public).decode()}, session["access_token"])
        old_wrap_file = directory / "old-node-wrap.json"
        if not old_wrap_file.exists():
            write_private(old_wrap_file, canonical(old.reader_wrap()))
        old_wrap = json.loads(old_wrap_file.read_bytes())
        self.rejected("old-node-fingerprint", lambda: self.panel.owner_request("POST", "/api/e2e2/views/" + old.scope["view_id"] + "/readers",
            {"machine_id": meta["machine_id"], "wrapper": old_wrap}, (400, 403, 409)), {"AwaitingProjectKey", "ContextMismatch"})
        self.protocol, self.panel.protocol = new, new
        # Deliberately NO current-epoch wrap for the new node. The next signed
        # read-key rotation makes the old node unable to access future values.
        self.frozen_stale_operator(baseline)
        write_private(directory / "done.json", canonical({"nodeFingerprint": new.node_fingerprint, "newNodeWrapGranted": False}))

    def run(self, generation, demo_value):
        require(isinstance(generation, str) and isinstance(demo_value, str) and len(generation) <= 200 and len(demo_value) <= 200,
            "Bounded explicit current selected values required")
        final = self.root / "complete.json"
        manifest = self.root / "baseline.json"
        if manifest.exists():
            baseline = json.loads(manifest.read_bytes())
            require(baseline["generation"] == generation and baseline["demo_value"] == demo_value
                and baseline["scope"] == self.original.scope and baseline["genesis_hash"] == self.original.genesis_hash
                and baseline["initial_authority"] == self.original.authority,
                "Rotation resume differs from original reviewed input")
            if final.exists():
                self.protocol = load_protocol_version(self.root / "07-final-read", self.original)
                self.panel.protocol = self.protocol
                result = json.loads(final.read_bytes())
                require(result["bootstrapGeneration"] == self.generation, "Completed rotation bootstrap generation differs")
                return result
        else:
            require(not final.exists(), "Completed rotation lacks its reviewed baseline")
            current = self.current()
            wait(lambda: self.app.current(current["snapshot"], True))
            target = self.app.get("Secret", TARGET)
            require(target["data"] == {"GENERATION": base64.b64encode(generation.encode()).decode(),
                "DEMO_VALUE": base64.b64encode(demo_value.encode()).decode()}, "Rotation values do not match current selected bytes")
            baseline = {"generation": generation, "demo_value": demo_value, "scope": self.original.scope,
                "genesis_hash": self.original.genesis_hash, "initial_authority": self.original.authority,
                "initial_state": current,
                "target_uid": target["metadata"]["uid"], "data": target["data"],
                "revision": target["metadata"]["annotations"][REVISION], "footprint": self.app.footprint(), "status": wait(self.app.status)}
            write_private(manifest, canonical(baseline))
        receipts = []
        for label, role in (("01-publisher", "publisher"), ("02-read", "read"), ("03-witness", "witness"), ("04-admin", "admin"), ("05-fencer", "fencer")):
            receipts.append(self.step(label, role, generation, demo_value, baseline))
        old_node = self.protocol.node
        self.node(baseline)
        receipts.append(self.step("07-final-read", "read", generation, demo_value, baseline))
        final_plan = json.loads((self.root / "07-final-read" / "plan.json").read_bytes())
        require(unwrap(self.protocol, final_plan["wrapper"], self.protocol.node) == self.protocol.read_key, "New node cannot unwrap final read key")
        try:
            unwrap(self.protocol, final_plan["wrapper"], old_node)
        except InvalidTag:
            pass
        else:
            raise RuntimeError("Retired node decrypted the fresh final read key")
        current = self.current()
        recovered = self.root / "reconfigured.json"
        if not recovered.exists():
            recovery_input = saved_candidate(self.root / "reconfigure-input.json", lambda: {
                "generation": self.generation, "state": current})
            require(recovery_input["generation"] == self.generation
                and recovery_input["state"]["authority"] == self.protocol.authority
                and recovery_input["state"]["scope"] == self.protocol.scope, "Reconfiguration input differs from reviewed final rotation")
            self.on_reconfigure(self.protocol, recovery_input["state"], self.generation)
            wait(lambda: self.app.current(recovery_input["state"]["snapshot"], True))
            self.same_application(baseline)
            for name in (RELEASE + "-operator", RELEASE + "-fencer"):
                value = self.app.get("Deployment", name)
                require(value["spec"]["replicas"] == 2 and value.get("status", {}).get("readyReplicas") == 2,
                    "Recovered HA deployment does not have two ready replicas")
            write_private(recovered, canonical({"bootstrapGeneration": self.generation,
                "snapshot": recovery_input["state"]["snapshot"], "inputCursor": recovery_input["state"]["cursor"]}))
        else:
            require(json.loads(recovered.read_bytes())["bootstrapGeneration"] == self.generation, "Recovered generation changed")
        # The normal post-rotation data path must still produce exactly one RS.
        after = self.root / "post-rotation-publish.json"
        if not after.exists():
            next_generation, next_value = "post-rotation-" + uuid.uuid4().hex, uuid.uuid4().hex
            envelope, digest = self.protocol.snapshot(int(current["snapshot"]["sequence"]) + 1,
                current["snapshot"]["envelope_hash"], next_generation, next_value)
            write_private(after, canonical({"generation": next_generation, "value": next_value, "envelope": envelope, "hash": digest}))
        candidate = json.loads(after.read_bytes())
        current = self.current()
        if current["snapshot"]["envelope_hash"] != candidate["hash"]:
            require(int(current["snapshot"]["sequence"]) + 1 == int(candidate["envelope"]["body"]["header"]["sequence"])
                and current["snapshot"]["envelope_hash"] == candidate["envelope"]["body"]["header"]["previous_hash"], "Post-rotation publish cursor changed")
            self.panel.publish_sealed(candidate["envelope"], candidate["hash"])
        wait(lambda: self.app.current(self.current()["snapshot"], True))
        status = wait(lambda: value if (value := self.app.status()) and value["generation"] == candidate["generation"] else False)
        require(status["value_digest"] == hashlib.sha256(candidate["value"].encode()).hexdigest()
            and status["pod_uid"] != baseline["status"]["pod_uid"] and status["boot_id"] != baseline["status"]["boot_id"],
            "New current keys did not deliver new selected values")
        footprint = self.app.footprint()
        require(len(set(footprint["replica_sets"]) - set(baseline["footprint"]["replica_sets"])) == 1,
            "Post-rotation update did not create exactly one new ReplicaSet")
        target = self.app.get("Secret", TARGET)
        revision = target["metadata"]["annotations"][REVISION]
        require(revision != baseline["revision"], "New selected data did not change opaque revision")
        expected_template = copy.deepcopy(baseline["footprint"]["template"])
        expected_template["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/restart-" + baseline["target_uid"]] = revision
        require(footprint["template"] == expected_template, "Post-rotation rollout changed unrelated pod-template fields")
        result = {"production": False, "passed": [item["case"] for item in receipts]
            + [label for item in receipts for label in item["passed"]]
            + ["old-node-cannot-unwrap-final-key", "explicit-generation-recovery-no-historical-rollout", "new-current-keys-one-normal-rollout"],
            "bootstrapGeneration": self.generation, "snapshot": self.current()["snapshot"],
            "oldPublisherBoundary": "actual-panel-signature-validation",
            "storageProfile": "isolated-trial", "productionIndependentStorageClaim": False}
        write_private(final, canonical(result))
        return result
