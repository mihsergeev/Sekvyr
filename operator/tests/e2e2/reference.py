"""Independent Python crypto reference; synthetic public fixtures only.

Fixed ASCII property names, integers 0..1024 and exact Unicode scalar strings
form the reviewed restricted RFC 8785 profile, not a general JCS library.
"""

import argparse
import base64
import copy
import difflib
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = Path(__file__).resolve().parent
DESIGN = HERE.parents[1] / "design"
P256_ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)


def public_material(label):
    return hashlib.sha256(("sekvyr-e2e2-public-test-vector/" + label).encode()).digest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(text):
    raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    if b64(raw) != text:
        raise ValueError("noncanonical Base64url")
    return raw


def canonical(value):
    def validate(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if not key.isascii():
                    raise ValueError("non-ASCII property")
                validate(child)
        elif isinstance(item, list):
            for child in item:
                validate(child)
        elif isinstance(item, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise ValueError("surrogate")
        elif isinstance(item, bool) or item is None:
            pass
        elif type(item) is int and 0 <= item <= 1024:
            pass
        else:
            raise ValueError("number outside restricted profile")
    validate(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def domain(name):
    return ("sekvyr-e2e2/" + name + "/v1").encode("ascii") + b"\0"


def public_point(private):
    return private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def public_scalar(label):
    scalar = int.from_bytes(public_material(label), "big") % (P256_ORDER - 1) + 1
    return scalar.to_bytes(32, "big"), ec.derive_private_key(scalar, ec.SECP256R1())


def make_vector():
    snapshot_vector = json.loads((DESIGN / "e2e2.public-vectors.json").read_text(encoding="utf-8"))
    scope = snapshot_vector["plaintext"]["context"]
    publisher = ed25519.Ed25519PrivateKey.from_private_bytes(public_material("publisher"))
    publisher_public = publisher.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    node_scalar, node = public_scalar("reader-node-PUBLIC-NOT-SECRET")
    _, ephemeral = public_scalar("reader-ephemeral-PUBLIC-NOT-SECRET")
    context = {
        "protocol": "e2e2-reader-key-v1", **scope,
        "read_key_epoch": "1", "publisher_policy_epoch": "1",
        "publisher_key_id": "ed25519-sha256:" + hashlib.sha256(publisher_public).hexdigest(),
        "recipient_fingerprint": "p256-sha256:" + hashlib.sha256(public_point(node)).hexdigest(),
    }
    read_key = public_material("view-read")
    payload = {"format": "sekvyr-e2e2-read-key-v1", "context": context, "read_key": b64(read_key)}
    salt = public_material("reader-wrap-salt-PUBLIC")
    nonce = public_material("reader-wrap-nonce-PUBLIC")[:12]
    shared = node.exchange(ec.ECDH(), ephemeral.public_key())
    wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                        info=domain("reader-wrap-key") + canonical(context)).derive(shared)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, canonical(payload), domain("reader-wrap-aad") + canonical(context))
    body = {"context": context, "ephemeral_public": b64(public_point(ephemeral)),
            "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
    wrapper = {"body": body, "signature": b64(publisher.sign(domain("reader-wrap-sign") + canonical(body)))}
    # Include controls, HTML-sensitive characters, JS line separators, astral
    # scalars and decomposed Unicode. Values MUST stay unchanged, including NFC.
    unicode_case = {
        "a": "\u0000\b\t\n\f\r\u001f\"\\/ <>& \u2028\u2029 \U0001d11e",
        "b": "e\u0301 != \u00e9", "count": 1024, "none": None, "truth": True,
    }
    return {
        "description": "PUBLIC deterministic synthetic reader-wrap fixture. Node scalar and all derived keys are intentionally public test data, never deployable credentials.",
        "publisher_public_key": b64(publisher_public),
        "public_test_node_scalar": b64(node_scalar),
        "node_public_key": b64(public_point(node)),
        "public_test_view_read_key": b64(read_key),
        "wrapper": wrapper,
        "canonical_wrapper_body_base64url": b64(canonical(body)),
        "canonical_wrapper_payload_base64url": b64(canonical(payload)),
        "public_test_ecdh_shared_base64url": b64(shared),
        "public_test_wrap_key_base64url": b64(wrapping_key),
        "unicode_case": unicode_case,
        "unicode_canonical_base64url": b64(canonical(unicode_case)),
    }


def make_snapshot_corpus():
    """Independently seal/sign invalid semantics, so signatures really verify."""
    original = json.loads((DESIGN / "e2e2.public-vectors.json").read_text(encoding="utf-8"))
    publisher = ed25519.Ed25519PrivateKey.from_private_bytes(public_material("publisher"))
    read_key = public_material("view-read")
    cases = []

    def append(name, mutate_plain=None, mutate_header=None, raw_plain=None, valid=False):
        plaintext = copy.deepcopy(original["plaintext"])
        header = copy.deepcopy(original["envelope"]["body"]["header"])
        if mutate_plain:
            mutate_plain(plaintext)
            if isinstance(plaintext.get("entries"), list):
                header["entry_count"] = len(plaintext["entries"])
        if mutate_header:
            mutate_header(header)
        header["snapshot_salt"] = b64(public_material("corpus-salt-" + name))
        nonce = public_material("corpus-nonce-" + name)[:12]
        # All generated integer literals are already exact decimal integers.
        # This serializer also permits deliberately invalid negative test counts.
        wire = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=unb64(header["snapshot_salt"]),
                   info=domain("snapshot-key") + wire(header)).derive(read_key)
        plaintext_bytes = raw_plain(plaintext) if raw_plain else wire(plaintext)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext_bytes, domain("snapshot-aad") + wire(header))
        body = {"header": header, "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        body_bytes = wire(body)
        envelope = {"body": body, "signature": b64(publisher.sign(domain("publish") + body_bytes))}
        digest = hashlib.sha256(domain("envelope-hash") + wire(envelope)).hexdigest()
        cases.append({"name": name, "valid": valid, "envelope": envelope, "envelope_hash": digest,
                      "canonical_signed_body_base64url": b64(body_bytes),
                      "expected_plaintext": plaintext if valid else None})

    append("baseline", valid=True)
    append("unicode-values-unchanged", lambda p: p["entries"][0].update(value="\u0000\b\t\n\f\r\u001f\"\\/ <>& \u2028\u2029 \U0001d11e e\u0301"), valid=True)
    append("utf8-order-not-utf16", lambda p: p.update(entries=[
        {"path": "/runtime", "name": "\ue000", "value": "public-one"},
        {"path": "/runtime", "name": "\U00010000", "value": "public-two"},
    ]), valid=True)
    append("utf16-order-rejected", lambda p: p.update(entries=[
        {"path": "/runtime", "name": "\U00010000", "value": "public-two"},
        {"path": "/runtime", "name": "\ue000", "value": "public-one"},
    ]))
    for name, field, value in [
        ("name-nfd", "name", "Cafe\u0301"), ("path-nfd", "path", "/cafe\u0301"),
        ("name-del", "name", "VALUE\x7f"), ("name-c1", "name", "VALUE\x85"),
        ("name-bidi", "name", "VALUE\u202e"), ("name-zero-width", "name", "VALUE\u200b"),
        ("path-dotdot", "path", "/runtime/../hidden"), ("path-repeated-slash", "path", "/runtime//hidden"),
        ("path-backslash", "path", "/runtime\\hidden"), ("path-trailing-slash", "path", "/runtime/"),
        ("value-null", "value", None),
    ]:
        append(name, lambda p, f=field, v=value: p["entries"][0].update({f: v}))
    append("unknown-entry-field", lambda p: p["entries"][0].update(unsigned_extra="public"))
    append("missing-value", lambda p: p["entries"][0].pop("value"))
    append("null-entries", lambda p: p.update(entries=None))
    append("null-context", lambda p: p.update(context=None))
    append("unknown-plaintext-field", lambda p: p.update(untrusted=True))
    append("plaintext-context-substitution", lambda p: p["context"].update(view_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
    append("duplicate-tuple", lambda p: p["entries"].append(copy.deepcopy(p["entries"][0])))
    append("incomplete-set", lambda p: p.update(entries=[]), lambda h: h.update(entry_count=1))
    append("noncanonical-plaintext", raw_plain=lambda p: json.dumps(p, ensure_ascii=False, sort_keys=True).encode())
    append("duplicate-escaped-plaintext-property", raw_plain=lambda p: canonical(p).replace(b'"value":', b'"value":"public", "\\u0076alue":', 1))
    append("lone-surrogate-plaintext", raw_plain=lambda p: canonical(p).replace(b'canary-value-1', b'\\ud800'))
    append("malformed-utf8-plaintext", raw_plain=lambda p: canonical(p).replace(b'canary-value-1', b'\xff'))
    for name, field, value in [
        ("counter-overflow", "sequence", "18446744073709551616"),
        ("counter-leading-zero", "sequence", "01"), ("counter-number", "sequence", 1),
        ("epoch-zero", "read_key_epoch", "0"), ("policy-overflow", "publisher_policy_epoch", "18446744073709551616"),
        ("null-parents", "parents", None), ("null-count", "entry_count", None),
        ("negative-count", "entry_count", -1), ("boolean-count", "entry_count", True),
        ("proposal-intent", "intent", "proposal"), ("wrong-suite", "suite", "AES-GCM"),
        ("initial-bad-predecessor", "previous_hash", "1" * 64),
        ("restore-without-reference", "action", "restore"),
        ("unknown-header-field", "untrusted", True),
    ]:
        append(name, mutate_header=lambda h, f=field, v=value: h.update({f: v}))
    parent = {**original["plaintext"]["context"], "environment_id": "11111111-1111-4111-8111-111111111111",
              "sequence": "1", "envelope_hash": "1" * 64}
    second_parent = {**parent, "environment_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
    append("sorted-distinct-parents", mutate_header=lambda h: h.update(parents=[parent, second_parent]), valid=True)
    maximum_parents = [{**parent, "environment_id": f"{index:08x}-0000-4000-8000-000000000000"} for index in range(1, 17)]
    append("maximum-sixteen-parents", mutate_header=lambda h: h.update(parents=maximum_parents), valid=True)
    append("duplicate-parent-context", mutate_header=lambda h: h.update(parents=[parent, {**parent, "sequence": "2", "envelope_hash": "2" * 64}]))
    append("unsorted-parent-context", mutate_header=lambda h: h.update(parents=[second_parent, parent]))
    return {"description": "PUBLIC independently Python-encrypted and Ed25519-signed semantic attack corpus. Invalid cases have valid publisher signatures, not merely corrupted signatures.",
            "publisher_public_key": original["publisher_public_key"], "public_test_view_read_key": b64(read_key), "cases": cases}


def make_wrap_corpus():
    vector = make_vector()
    publisher = ed25519.Ed25519PrivateKey.from_private_bytes(public_material("publisher"))
    cases = []

    def append(name, mutate_payload=None, raw_payload=None, mutate_body=None, valid=False):
        context = copy.deepcopy(vector["wrapper"]["body"]["context"])
        payload = {"format": "sekvyr-e2e2-read-key-v1", "context": copy.deepcopy(context),
                   "read_key": vector["public_test_view_read_key"]}
        if mutate_payload:
            mutate_payload(payload)
        plaintext = raw_payload(payload) if raw_payload else canonical(payload)
        salt = public_material("wrap-corpus-salt-" + name)
        nonce = public_material("wrap-corpus-nonce-" + name)[:12]
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                   info=domain("reader-wrap-key") + canonical(context)).derive(unb64(vector["public_test_ecdh_shared_base64url"]))
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, domain("reader-wrap-aad") + canonical(context))
        body = {"context": context, "ephemeral_public": vector["wrapper"]["body"]["ephemeral_public"],
                "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        if mutate_body:
            mutate_body(body)
        body_bytes = canonical(body)
        wrapper = {"body": body, "signature": b64(publisher.sign(domain("reader-wrap-sign") + body_bytes))}
        cases.append({"name": name, "valid": valid, "wrapper": wrapper,
                      "canonical_signed_body_base64url": b64(body_bytes)})

    append("baseline", valid=True)
    append("payload-format", lambda p: p.update(format="e2e1"))
    append("payload-context", lambda p: p["context"].update(view_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
    append("payload-null-context", lambda p: p.update(context=None))
    append("payload-unknown-field", lambda p: p.update(publish_key="public-not-a-real-key"))
    append("payload-missing-read-key", lambda p: p.pop("read_key"))
    append("payload-null-read-key", lambda p: p.update(read_key=None))
    append("payload-short-read-key", lambda p: p.update(read_key=b64(bytes(31))))
    append("payload-long-read-key", lambda p: p.update(read_key=b64(bytes(33))))
    append("payload-padded-read-key", lambda p: p.update(read_key=p["read_key"] + "="))
    append("payload-noncanonical", raw_payload=lambda p: json.dumps(p, sort_keys=True).encode())
    append("payload-duplicate-alias", raw_payload=lambda p: canonical(p).replace(b'"read_key":', b'"read_key":"public", "\\u0072ead_key":', 1))
    append("payload-surrogate", raw_payload=lambda p: canonical(p).replace(vector["public_test_view_read_key"].encode(), b'\\udfff'))
    append("payload-invalid-utf8", raw_payload=lambda p: canonical(p).replace(vector["public_test_view_read_key"].encode(), b'\xff'))
    append("unknown-body-field", mutate_body=lambda b: b.update(extra="public"))
    append("invalid-p256-point", mutate_body=lambda b: b.update(ephemeral_public=b64(bytes(65))))
    append("compressed-p256-point", mutate_body=lambda b: b.update(ephemeral_public=b64(bytes(33))))
    append("wrong-recipient", mutate_body=lambda b: b["context"].update(recipient_fingerprint="p256-sha256:" + "1" * 64))
    append("wrong-read-epoch", mutate_body=lambda b: b["context"].update(read_key_epoch="2"))
    append("wrong-policy-epoch", mutate_body=lambda b: b["context"].update(publisher_policy_epoch="2"))
    return {"description": "PUBLIC independently signed reader-wrap attacks. Synthetic scalar/read keys only; every signature is valid, payloads deliberately invalid.",
            "publisher_public_key": vector["publisher_public_key"], "cases": cases}


def check(vector):
    assert vector == make_vector(), "public fixture drift"
    wrapper = vector["wrapper"]
    body = wrapper["body"]
    public = ed25519.Ed25519PublicKey.from_public_bytes(unb64(vector["publisher_public_key"]))
    public.verify(unb64(wrapper["signature"]), domain("reader-wrap-sign") + canonical(body))
    key = ec.derive_private_key(int.from_bytes(unb64(vector["public_test_node_scalar"]), "big"), ec.SECP256R1())
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(body["ephemeral_public"]))
    shared = key.exchange(ec.ECDH(), peer)
    wrapped_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=unb64(body["salt"]),
                       info=domain("reader-wrap-key") + canonical(body["context"])).derive(shared)
    plaintext = AESGCM(wrapped_key).decrypt(unb64(body["nonce"]), unb64(body["ciphertext"]),
                                          domain("reader-wrap-aad") + canonical(body["context"]))
    assert plaintext == unb64(vector["canonical_wrapper_payload_base64url"])
    assert json.loads(plaintext)["read_key"] == vector["public_test_view_read_key"]
    assert canonical(vector["unicode_case"]) == unb64(vector["unicode_canonical_base64url"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--patch", action="store_true")
    args = parser.parse_args()
    path = HERE / "public-reader-wrap-vector.json"
    if args.patch:
        print("*** Begin Patch")
        for path, vector in [(path, make_vector()), (HERE / "public-snapshot-corpus.json", make_snapshot_corpus()),
                             (HERE / "public-reader-wrap-corpus.json", make_wrap_corpus())]:
            content = json.dumps(vector, ensure_ascii=True, indent=2) + "\n"
            if path.exists() and path.read_text(encoding="utf-8") == content:
                continue
            if path.exists():
                print("*** Update File: " + path.as_posix())
                diff = list(difflib.unified_diff(path.read_text(encoding="utf-8").splitlines(), content.splitlines(), n=5))
                for line in diff[2:]:
                    print("@@" if line.startswith("@@") else line)
            else:
                print("*** Add File: " + path.as_posix())
                for line in content.splitlines():
                    print("+" + line)
        print("*** End Patch")
    else:
        check(json.loads(path.read_text(encoding="utf-8")))
        corpus = json.loads((HERE / "public-snapshot-corpus.json").read_text(encoding="utf-8"))
        assert corpus == make_snapshot_corpus(), "snapshot corpus drift"
        publisher = ed25519.Ed25519PublicKey.from_public_bytes(unb64(corpus["publisher_public_key"]))
        for case in corpus["cases"]:
            publisher.verify(unb64(case["envelope"]["signature"]), domain("publish") + unb64(case["canonical_signed_body_base64url"]))
        wraps = json.loads((HERE / "public-reader-wrap-corpus.json").read_text(encoding="utf-8"))
        assert wraps == make_wrap_corpus(), "reader-wrap corpus drift"
        for case in wraps["cases"]:
            publisher.verify(unb64(case["wrapper"]["signature"]), domain("reader-wrap-sign") + unb64(case["canonical_signed_body_base64url"]))
        from authority_reference import check as check_authority
        check_authority()
        print(json.dumps({"scope": "public synthetic Python crypto reference", "signed_snapshot_cases": len(corpus["cases"]), "signed_wrap_cases": len(wraps["cases"]), "result": "passed"}))


if __name__ == "__main__":
    main()
