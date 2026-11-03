"""Deterministic PUBLIC authority-proof v2 interop cases, never installation keys."""

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


HERE = Path(__file__).resolve().parent
PATH = HERE / "public-authority-proof-corpus.json"


def material(label):
    return hashlib.sha256(("sekvyr-stage7-PUBLIC-authority-vector/" + label).encode()).digest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def domain(name):
    return ("sekvyr-e2e2/" + name + "\0").encode()


def key(label):
    private = ed25519.Ed25519PrivateKey.from_private_bytes(material(label))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, {"key_id": "ed25519-sha256:" + hashlib.sha256(public).hexdigest(), "public_key": b64(public)}


def digest(state):
    return hashlib.sha256(domain("authority-state-hash/v1") + wire({name: state[name]
        for name in ("scope", "genesis_hash", "authority", "enrollments")})).hexdigest()


def make_corpus():
    snapshot = json.loads((HERE.parents[1] / "design" / "e2e2.public-vectors.json").read_bytes())
    scope = snapshot["plaintext"]["context"]
    keys = {role: key(role) for role in ("admin", "publisher", "witness", "fencer", "attacker", "new-publisher")}
    authority = {"revision": "1", "admin_key": keys["admin"][1], "publisher_policy_epoch": "1",
        "publisher_keys": [keys["publisher"][1]], "read_key_epoch": "1", "witness_epoch": "1",
        "witness_key": keys["witness"][1], "fencer_epoch": "1", "fencer_keys": [keys["fencer"][1]]}
    genesis = hashlib.sha256(material("genesis")).hexdigest()
    nonce = b64(material("challenge"))
    floor = {"journal_sequence": "1", "record_hash": hashlib.sha256(material("floor")).hexdigest()}
    state = {"scope": scope, "genesis_hash": genesis,
        "cursor": {"journal_sequence": "8", "record_hash": hashlib.sha256(material("current-slot")).hexdigest()},
        "snapshot": {"sequence": "2", "envelope_hash": hashlib.sha256(material("snapshot")).hexdigest(),
            "read_key_epoch": "1", "publisher_policy_epoch": "1"}, "authority": authority, "enrollments": {}}
    state["authority_digest"] = digest(state)
    body = {"format": "sekvyr-authority-proof-v2", "state": state, "request_nonce": nonce, "floor": floor}
    enrollment = {"installation_id": "10000000-0000-4000-8000-000000000001", "bootstrap_generation": 1,
        "namespace": "public-trial", "namespace_uid": "10000000-0000-4000-8000-000000000002",
        "operator_service_account": "public-reader", "operator_service_account_uid": "10000000-0000-4000-8000-000000000003",
        "fencer_service_account": "public-fencer", "fencer_service_account_uid": "10000000-0000-4000-8000-000000000004",
        "lease": {"api_version": "coordination.k8s.io/v1", "kind": "Lease", "namespace": "public-trial", "name": "public-lease", "uid": "10000000-0000-4000-8000-000000000005"},
        "node_fingerprint": "p256-sha256:" + hashlib.sha256(material("public-node")).hexdigest(),
        "identity_key_secret_uid": "10000000-0000-4000-8000-000000000006", "trust_bundle_secret_uid": "10000000-0000-4000-8000-000000000007",
        "allowed_objects": [{"api_version": "apps/v1", "kind": "Deployment", "namespace": "public-trial", "name": "public-app", "uid": "10000000-0000-4000-8000-000000000008"},
            {"api_version": "v1", "kind": "Secret", "namespace": "public-trial", "name": "public-target", "uid": "10000000-0000-4000-8000-000000000009"}]}
    cases = []

    def add(name, mutate=None, go=False, panel=None, signer="witness", recalc=True, raw=None):
        candidate = copy.deepcopy(body)
        if mutate:
            mutate(candidate)
        if recalc:
            candidate["state"]["authority_digest"] = digest(candidate["state"])
        proof = {"body": candidate, "key_id": keys[signer][1]["key_id"],
            "signature": b64(keys[signer][0].sign(domain("authority-proof/v2") + wire(candidate)))}
        item = {"name": name, "go_valid": go, "panel_valid": go if panel is None else panel}
        if raw:
            item["raw_base64url"] = b64(raw(wire(proof)))
        else:
            item["proof"] = proof
        cases.append(item)

    add("baseline", go=True)
    def enroll(b):
        b["state"]["enrollments"] = {enrollment["installation_id"]: copy.deepcopy(enrollment)}
    add("enrollment", enroll, go=True)
    def maximum(b):
        enroll(b)
        b["state"]["enrollments"][enrollment["installation_id"]]["bootstrap_generation"] = 9007199254740991
    add("maximum-safe-bootstrap-generation", maximum, go=True)
    add("maximum-uint64-cursor", lambda b: b["state"]["cursor"].update(journal_sequence="18446744073709551615"), go=True)
    def rotated(b):
        b["state"]["authority"].update(revision="2", publisher_policy_epoch="2", publisher_keys=[keys["new-publisher"][1]])
        b["state"]["snapshot"]["publisher_policy_epoch"] = "2"
    add("pinned-witness-authorized-current-publisher", rotated, go=True)
    def zero(b):
        b["state"]["snapshot"] = {"sequence": "0", "envelope_hash": "0" * 64, "read_key_epoch": "0", "publisher_policy_epoch": "0"}
    add("genesis-no-published-snapshot", zero, go=True, panel=False)
    add("wrong-scope", lambda b: b["state"]["scope"].update(view_id="20000000-0000-4000-8000-000000000001"))
    add("wrong-genesis", lambda b: b["state"].update(genesis_hash="e" * 64))
    add("wrong-nonce", lambda b: b.update(request_nonce=b64(bytes(32))))
    add("wrong-floor", lambda b: b.update(floor={"journal_sequence": "2", "record_hash": "a" * 64}))
    add("below-floor", lambda b: b["state"]["cursor"].update(journal_sequence="0", record_hash=genesis))
    add("same-floor-fork", lambda b: b["state"]["cursor"].update(journal_sequence="1", record_hash="b" * 64))
    add("wrong-digest", lambda b: b["state"].update(authority_digest="f" * 64), recalc=False)
    add("wrong-snapshot-epoch", lambda b: b["state"]["snapshot"].update(read_key_epoch="2"))
    add("retired-unpinned-signature", signer="attacker")
    add("incoming-witness-is-not-pin", lambda b: b["state"]["authority"].update(witness_key=keys["attacker"][1]), signer="attacker")
    add("role-key-collision", lambda b: b["state"]["authority"].update(admin_key=keys["witness"][1]))
    add("duplicate-publisher-key", lambda b: b["state"]["authority"].update(publisher_keys=[keys["publisher"][1], keys["publisher"][1]]))
    add("empty-publisher-key-set", lambda b: b["state"]["authority"].update(publisher_keys=[]))
    add("zero-authority-read-epoch", lambda b: b["state"]["authority"].update(read_key_epoch="0"))
    add("overflow-cursor", lambda b: b["state"]["cursor"].update(journal_sequence="18446744073709551616"))
    add("leading-zero-cursor", lambda b: b["state"]["cursor"].update(journal_sequence="08"))
    add("unknown-body-field", lambda b: b.update(untrusted=True))
    add("missing-body-floor", lambda b: b.pop("floor"))
    add("null-enrollment-map", lambda b: b["state"].update(enrollments=None))
    def bad_enrollment(b):
        enroll(b)
        b["state"]["enrollments"][enrollment["installation_id"]]["allowed_objects"][0]["namespace"] = "other-public-trial"
    add("cross-namespace-object", bad_enrollment)
    def unsafe(b):
        maximum(b)
        b["state"]["enrollments"][enrollment["installation_id"]]["bootstrap_generation"] = 9007199254740992
    add("unsafe-json-integer", unsafe)
    add("boolean-bootstrap-generation", lambda b: (enroll(b), b["state"]["enrollments"][enrollment["installation_id"]].update(bootstrap_generation=True)))
    add("duplicate-escaped-property", raw=lambda raw: raw.replace(b'"request_nonce":', b'"request_nonce":"PUBLIC", "\\u0072equest_nonce":', 1))
    add("unknown-outer-field", raw=lambda raw: raw[:-1] + b',"untrusted":true}')
    add("case-alias-body", raw=lambda raw: raw.replace(b'"state":', b'"State":', 1))
    add("padded-signature", raw=lambda raw: raw[:-2] + b'="}')
    add("utf8-bom", raw=lambda raw: b'\xef\xbb\xbf' + raw)
    add("invalid-utf8", raw=lambda raw: raw.replace(b'sekvyr-authority-proof-v2', b'\xff', 1))
    add("lone-surrogate", raw=lambda raw: raw.replace(b'sekvyr-authority-proof-v2', b'\\ud800', 1))
    add("floating-point", raw=lambda raw: raw.replace(b'"enrollments":{}', b'"enrollments":{},"unknown":1.0', 1))
    return {"format": "sekvyr-stage7-PUBLIC-authority-corpus-v1",
        "description": "All signing seeds and contexts are deterministic PUBLIC synthetic test data. Never install them. Pin comes from this independent test input, never from incoming proof fields. Genesis-only views are valid Go authority but are not publishable panel projections.",
        "scope": scope, "genesis_hash": genesis, "pinned_witness": keys["witness"][1], "witness_epoch": "1",
        "request_nonce": nonce, "floor": floor, "cases": cases}


def check():
    actual = json.loads(PATH.read_bytes())
    assert actual == make_corpus(), "PUBLIC authority corpus drift"
    print(json.dumps({"scope": "PUBLIC deterministic authority v2", "cases": len(actual["cases"]), "result": "passed"}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--patch", action="store_true")
    args = parser.parse_args()
    if not args.patch:
        return check()
    assert not PATH.exists(), "PUBLIC corpus already exists; review changes explicitly"
    print("*** Begin Patch\n*** Add File: " + PATH.as_posix())
    for line in json.dumps(make_corpus(), ensure_ascii=True, indent=2).splitlines():
        print("+" + line)
    print("*** End Patch")


if __name__ == "__main__":
    main()
