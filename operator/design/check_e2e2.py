"""Design-only reference checks and public synthetic vectors; not a runtime SDK."""
import argparse
import base64
import copy
import hashlib
import json
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "e2e2.schema.json").read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
CTX = {
    "realm_id": "77777777-7777-4777-8777-777777777777",
    "project_id": "88888888-8888-4888-8888-888888888888",
    "environment_id": "99999999-9999-4999-8999-999999999999",
    "view_id": "66666666-6666-4666-8666-666666666666",
    "log_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def domain(name):
    return ("sekvyr-e2e2/" + name + "/v1").encode() + b"\0"


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def unb64(value, length=None):
    require("=" not in value, "noncanonical base64")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(b64(raw) == value, "noncanonical base64")
    require(length is None or len(raw) == length, "decoded length")
    return raw


def scalar_strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            require(key.isascii(), "non-ASCII property")
            scalar_strings(item)
    elif isinstance(value, list):
        for item in value:
            scalar_strings(item)
    elif isinstance(value, str):
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "surrogate")
    elif isinstance(value, (int, bool)) or value is None:
        require(not isinstance(value, int) or isinstance(value, bool) or 0 <= value <= 1024,
                "integer outside fixed-schema profile")
    else:
        raise ValueError("unsupported numeric/type")


def canonical(value):
    # Fixed ASCII property names and bounded integers make this restricted
    # profile equivalent to JCS; this is not a general-purpose JCS library.
    scalar_strings(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict_load(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON property")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def key_id(key):
    return "ed25519-sha256:" + digest(pub(key))


def test_material(label):
    # Explicitly public deterministic test material, never production randomness.
    return hashlib.sha256(("sekvyr-e2e2-public-test-vector/" + label).encode()).digest()


def publisher():
    return Ed25519PrivateKey.from_private_bytes(test_material("publisher"))


def witness_key():
    return Ed25519PrivateKey.from_private_bytes(test_material("witness"))


def read_key():
    return test_material("view-read")


def sign_envelope(envelope):
    envelope["signature"] = b64(publisher().sign(domain("publish") + canonical(envelope["body"])))
    return envelope


def envelope_hash(envelope):
    return digest(domain("envelope-hash") + canonical(envelope))


def snapshot_key(header, key):
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=unb64(header["snapshot_salt"], 32),
                info=domain("snapshot-key") + canonical(header)).derive(key)


def seal_body(header, plaintext, nonce, key):
    return AESGCM(snapshot_key(header, key)).encrypt(
        nonce, canonical(plaintext), domain("snapshot-aad") + canonical(header))


def fixture(sequence="1", previous="0" * 64, value="canary-value-1", salt_label=None):
    label = salt_label or sequence
    header = {
        "protocol": "e2e2", "suite": "HKDF-SHA256+A256GCM+Ed25519", "intent": "publish",
        **CTX, "sequence": sequence, "previous_hash": previous, "read_key_epoch": "1",
        "publisher_policy_epoch": "1", "publisher_key_id": key_id(publisher()),
        "snapshot_salt": b64(test_material("salt-" + label)), "entry_count": 1,
        "action": "initial" if sequence == "1" else "update",
        "restored_from": None, "parents": [],
    }
    plaintext = {"format": "sekvyr-e2e2-values-v1", "context": CTX,
                 "entries": [{"path": "/runtime", "name": "DEMO_VALUE", "value": value}]}
    nonce = test_material("nonce-" + label)[:12]
    envelope = {"body": {"header": header, "nonce": b64(nonce),
                         "ciphertext": b64(seal_body(header, plaintext, nonce, read_key()))}}
    return sign_envelope(envelope), plaintext


def validate_signature(envelope):
    require(not list(VALIDATOR.iter_errors(envelope)), "schema")
    h = envelope["body"]["header"]
    for k in ("sequence", "read_key_epoch", "publisher_policy_epoch"):
        require(1 <= int(h[k]) <= 2**64 - 1, "counter overflow")
    require(h["publisher_key_id"] == key_id(publisher()), "publisher not pinned")
    publisher().public_key().verify(unb64(envelope["signature"], 64),
                                   domain("publish") + canonical(envelope["body"]))
    require(all(h[k] == v for k, v in CTX.items()), "context")
    unb64(h["snapshot_salt"], 32)
    unb64(envelope["body"]["nonce"], 12)
    return h


def verify(envelope, expected_hash, floor=(0, "0" * 64), key=None):
    h = validate_signature(envelope)
    actual = envelope_hash(envelope)
    require(actual == expected_hash, "hash mismatch")
    seq = int(h["sequence"])
    require(seq >= floor[0], "rollback")
    require(seq != floor[0] or actual == floor[1], "fork")
    require(seq != 1 or h["previous_hash"] == "0" * 64, "genesis predecessor")
    ciphertext = unb64(envelope["body"]["ciphertext"])
    require(len(ciphertext) <= 8388608 + 16, "ciphertext limit")
    raw = AESGCM(snapshot_key(h, read_key() if key is None else key)).decrypt(
        unb64(envelope["body"]["nonce"], 12), ciphertext,
        domain("snapshot-aad") + canonical(h))
    require(len(raw) <= 8388608, "plaintext limit")
    decoded = strict_load(raw.decode("utf-8"))
    require(not list(VALIDATOR.iter_errors(decoded)), "plaintext schema")
    require(canonical(decoded) == raw, "noncanonical plaintext")
    require(decoded["context"] == CTX, "plaintext context")
    require(len(decoded["entries"]) == h["entry_count"], "incomplete set")
    positions = []
    for entry in decoded["entries"]:
        for name in ("name", "path"):
            require(unicodedata.normalize("NFC", entry[name]) == entry[name], "metadata NFC")
        path = entry["path"]
        require(path == "/" or (not path.endswith("/") and
                not any(x in ("", ".", "..") for x in path[1:].split("/"))), "path")
        require("\\" not in path, "path characters")
        require(not any(unicodedata.category(c) in ("Cc", "Cf", "Cs")
                        for text in (path, entry["name"]) for c in text), "metadata controls")
        positions.append((path.encode(), entry["name"].encode()))
    require(positions == sorted(set(positions)), "duplicate/order")
    return decoded


class WitnessModel:
    """In-memory linearizable CAS model, NOT a durable or network service."""
    def __init__(self):
        self.ledger = []

    def head(self):
        return (len(self.ledger), self.ledger[-1] if self.ledger else "0" * 64)

    def commit(self, envelope, expected):
        h = validate_signature(envelope)
        require(h["read_key_epoch"] == "1" and h["publisher_policy_epoch"] == "1",
                "rotation is outside this reference model")
        require(self.head() == expected, "publication conflict")
        require(int(h["sequence"]) == expected[0] + 1 and
                h["previous_hash"] == expected[1], "broken chain")
        self.ledger.append(envelope_hash(envelope))

    def proof(self, nonce, floor):
        unb64(nonce, 32)
        seq, head = self.head()
        canonical_floor = self.ledger[floor[0] - 1] if floor[0] else "0" * 64
        require(floor[0] <= seq and canonical_floor == floor[1], "unknown floor")
        body = {"format": "sekvyr-e2e2-head-v1", **CTX, "witness_epoch": "1",
                "sequence": str(seq), "envelope_hash": head,
                "read_key_epoch": "1" if seq else "0",
                "publisher_policy_epoch": "1" if seq else "0",
                "request_nonce": nonce, "witness_key_id": key_id(witness_key()),
                "floor_sequence": str(floor[0]), "floor_hash": floor[1]}
        return {"body": body, "signature": b64(witness_key().sign(domain("head") + canonical(body)))}


def verify_proof(proof, nonce, floor):
    require(not list(VALIDATOR.iter_errors(proof)), "proof schema")
    b = proof["body"]
    for field in ("sequence", "floor_sequence", "read_key_epoch", "publisher_policy_epoch", "witness_epoch"):
        require(0 <= int(b[field]) <= 2**64 - 1, "proof counter overflow")
    witness_key().public_key().verify(unb64(proof["signature"], 64),
                                     domain("head") + canonical(b))
    require(b["witness_key_id"] == key_id(witness_key()) and b["witness_epoch"] == "1", "witness pin")
    require(all(b[k] == v for k, v in CTX.items()), "proof context")
    require(b["request_nonce"] == nonce, "stale receipt/nonce")
    require((int(b["floor_sequence"]), b["floor_hash"]) == floor, "floor proof")
    seq = int(b["sequence"])
    if seq:
        require(int(b["read_key_epoch"]) >= 1 and int(b["publisher_policy_epoch"]) >= 1,
                "non-genesis zero epoch")
    else:
        require(b["envelope_hash"] == "0" * 64 and b["read_key_epoch"] == "0"
                and b["publisher_policy_epoch"] == "0", "invalid genesis")
    require(seq >= floor[0], "witness rollback")
    require(seq != floor[0] or b["envelope_hash"] == floor[1], "witness fork")
    return seq, b["envelope_hash"]


def verify_current(envelope, first, nonce1, floor, second, nonce2):
    first_head = verify_proof(first, nonce1, floor)
    second_head = verify_proof(second, nonce2, first_head)
    require(first_head == second_head, "HeadChanged")
    h = envelope["body"]["header"]
    for proof in (first, second):
        b = proof["body"]
        require(h["sequence"] == b["sequence"] and
                h["read_key_epoch"] == b["read_key_epoch"] and
                h["publisher_policy_epoch"] == b["publisher_policy_epoch"], "head/envelope epochs")
    return verify(envelope, second_head[1], floor)


def run_checks():
    tests = {}
    def passed(name, fn):
        fn()
        tests[name] = "passed"
    def rejected(name, fn):
        try:
            fn()
        except Exception:
            tests[name] = "rejected"
        else:
            raise AssertionError("accepted invalid design case: " + name)
    e1, plain = fixture()
    h1 = envelope_hash(e1)
    passed("full snapshot roundtrip", lambda: require(verify(e1, h1) == plain, "roundtrip"))
    for field in ("nonce", "ciphertext"):
        bad = copy.deepcopy(e1)
        value = bytearray(unb64(bad["body"][field]))
        value[0] ^= 1
        bad["body"][field] = b64(bytes(value))
        rejected(field + " substitution", lambda bad=bad: verify(bad, envelope_hash(bad)))
    for field in ("realm_id", "project_id", "environment_id", "view_id", "log_id"):
        bad = copy.deepcopy(e1)
        bad["body"]["header"][field] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        sign_envelope(bad)
        rejected(field + " misbinding", lambda bad=bad: verify(bad, envelope_hash(bad)))
    for field, value in (("snapshot_salt", b64(test_material("other-salt"))),
                         ("read_key_epoch", "2"), ("entry_count", 0)):
        bad = copy.deepcopy(e1)
        bad["body"]["header"][field] = value
        sign_envelope(bad)
        rejected(field + " AAD change", lambda bad=bad: verify(bad, envelope_hash(bad)))
    bad = copy.deepcopy(e1)
    bad["signature"] = b64(bytes(64))
    rejected("invalid publisher signature", lambda: verify(bad, envelope_hash(bad)))
    rejected("wrong read key", lambda: verify(e1, h1, key=test_material("wrong-view")))
    for field in ("name", "path", "value"):
        forged = copy.deepcopy(e1)
        altered = copy.deepcopy(plain)
        altered["entries"][0][field] += "-forged"
        forged["body"]["ciphertext"] = b64(seal_body(forged["body"]["header"], altered,
                                         unb64(forged["body"]["nonce"]), read_key()))
        rejected("read-key-only " + field + " forgery",
                 lambda forged=forged: verify(forged, envelope_hash(forged)))
    forged = copy.deepcopy(e1)
    altered = copy.deepcopy(plain)
    altered["entries"] = []
    forged["body"]["ciphertext"] = b64(seal_body(forged["body"]["header"], altered,
                                     unb64(forged["body"]["nonce"]), read_key()))
    rejected("hidden removal", lambda: verify(forged, envelope_hash(forged)))
    rejected("duplicate JSON field", lambda: strict_load('{"intent":"publish","intent":"proposal"}'))
    bad = copy.deepcopy(e1)
    bad["body"]["header"]["sequence"] = "01"
    rejected("noncanonical counter", lambda: verify(bad, envelope_hash(bad)))
    bad2 = copy.deepcopy(e1)
    bad2["body"]["header"]["sequence"] = str(2**64)
    sign_envelope(bad2)
    rejected("uint64 overflow", lambda: verify(bad2, envelope_hash(bad2)))
    bad3 = copy.deepcopy(e1)
    bad3["body"]["header"]["intent"] = "proposal"
    sign_envelope(bad3)
    rejected("proposal is not publish", lambda: verify(bad3, envelope_hash(bad3)))
    bad4 = copy.deepcopy(e1)
    bad4["body"]["header"]["protocol"] = "e2e1"
    sign_envelope(bad4)
    rejected("legacy downgrade", lambda: verify(bad4, envelope_hash(bad4)))
    witness = WitnessModel()
    witness.commit(e1, (0, "0" * 64))
    e2, p2 = fixture("2", h1, "canary-value-2")
    e2_other, _ = fixture("2", h1, "competing-value", "other-candidate")
    witness.commit(e2, (1, h1))
    h2 = envelope_hash(e2)
    rejected("two canonical successors", lambda: witness.commit(e2_other, (1, h1)))
    rejected("rollback below watermark", lambda: verify(e1, h1, floor=(2, h2)))
    rejected("same sequence different hash", lambda: verify(e2_other, envelope_hash(e2_other), floor=(2, h2)))
    n1, n2 = b64(test_material("challenge1")), b64(test_material("challenge2"))
    proof = witness.proof(n1, (1, h1))
    passed("fresh nonce+floor proof", lambda: require(verify_proof(proof, n1, (1, h1)) == (2, h2), "head"))
    rejected("old receipt replay", lambda: verify_proof(proof, n2, (1, h1)))
    rejected("fake pinned history floor", lambda: witness.proof(n2, (1, "f" * 64)))
    proof_second = witness.proof(n2, (2, h2))
    passed("two head proofs bind complete snapshot",
           lambda: require(verify_current(e2, proof, n1, (1, h1), proof_second, n2) == p2, "current"))
    bad_proof = copy.deepcopy(proof_second)
    bad_proof["body"]["read_key_epoch"] = "2"
    bad_proof["signature"] = b64(witness_key().sign(domain("head") + canonical(bad_proof["body"])))
    rejected("head/envelope epoch mismatch",
             lambda: verify_current(e2, proof, n1, (1, h1), bad_proof, n2))
    for field, value in (("read_key_epoch", "0"), ("publisher_policy_epoch", "0"),
                         ("sequence", str(2**64))):
        invalid = copy.deepcopy(proof)
        invalid["body"][field] = value
        invalid["signature"] = b64(witness_key().sign(domain("head") + canonical(invalid["body"])))
        rejected("invalid proof " + field, lambda invalid=invalid: verify_proof(invalid, n1, (1, h1)))
    for label, control in (("DEL", "\x7f"), ("C1", "\x85"), ("bidi", "\u202e")):
        altered = copy.deepcopy(plain)
        altered["entries"][0]["path"] += control
        invalid = copy.deepcopy(e1)
        invalid["body"]["ciphertext"] = b64(seal_body(invalid["body"]["header"], altered,
                                           unb64(invalid["body"]["nonce"]), read_key()))
        sign_envelope(invalid)
        rejected("metadata " + label, lambda invalid=invalid: verify(invalid, envelope_hash(invalid)))
    e3, _ = fixture("3", h2, "canary-value-3")
    first = witness.head()
    witness.commit(e3, first)
    proof3 = witness.proof(n2, first)
    second = verify_proof(proof3, n2, first)
    rejected("head advanced during read", lambda: require(first == second, "HeadChanged"))
    restored = witness.proof(n2, (1, h1))
    passed("restored reader sees independent current head",
           lambda: require(verify_proof(restored, n2, (1, h1))[0] == 3, "stale cache"))
    repeated, repeated_plain = fixture("3", h2, "canary-value-2", "same-plaintext-new-salt")
    passed("nonce refresh is not a plaintext change",
           lambda: require(envelope_hash(repeated) != h2 and
                           verify(repeated, envelope_hash(repeated)) == p2, "no-op"))
    passed("retry accepted watermark after crash",
           lambda: require(verify(e2, h2, floor=(2, h2)) == p2, "checkpoint retry"))
    public_vector = {
        "description": "Public deterministic synthetic vector; private keys are derived only inside the check programs.",
        "publisher_public_key": b64(pub(publisher())),
        "witness_public_key": b64(pub(witness_key())),
        "envelope": e1, "plaintext": plain, "envelope_hash": h1,
        "canonical_body_base64url": b64(canonical(e1["body"])),
        "head_proof": proof, "challenge_nonce": n1,
        "unicode_case": {"value": "данные\nкавычка\" и символ \U0001D11E <>& \u2028\u2029", "count": 1},
    }
    public_vector["unicode_canonical_base64url"] = b64(canonical(public_vector["unicode_case"]))
    return tests, public_vector


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", action="store_true")
    args = parser.parse_args()
    checks, vector = run_checks()
    print(json.dumps(vector if args.vectors else {
        "scope": "Design reference crypto and in-memory witness model only; no production SDK/service, durability or browser UI test",
        "checks": len(checks), "results": checks,
    }, ensure_ascii=True, indent=2))
