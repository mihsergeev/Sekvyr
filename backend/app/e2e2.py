"""Opaque E2E2 signed-envelope validation and independent witness checks.

This module never receives a read key or publisher private key and performs no
plaintext encryption/decryption. Witness configuration is administrative input.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

MAX_ENVELOPE = 16 * 1024 * 1024
MAX_WRAP = 16 * 1024
MAX_PROOF = 16 * 1024
ZERO = "0" * 64
SCOPE = {"realm_id", "project_id", "environment_id", "view_id", "log_id"}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
HEADER = SCOPE | {"protocol", "suite", "intent", "sequence", "previous_hash", "read_key_epoch", "publisher_policy_epoch", "publisher_key_id", "snapshot_salt", "entry_count", "action", "restored_from", "parents"}
WRAP_CONTEXT = SCOPE | {"protocol", "read_key_epoch", "publisher_policy_epoch", "publisher_key_id", "recipient_fingerprint"}
HEAD = SCOPE | {"format", "witness_epoch", "sequence", "envelope_hash", "read_key_epoch", "publisher_policy_epoch", "request_nonce", "witness_key_id", "floor_sequence", "floor_hash"}


class Rejected(Exception):
    def __init__(self, reason: str, status: int = 400):
        self.reason, self.status = reason, status
        super().__init__(reason)


def require(ok: bool, reason: str = "InvalidResponse", status: int = 400) -> None:
    if not ok:
        raise Rejected(reason, status)


def counter(value, zero: bool = False) -> int:
    require(type(value) is str and bool(re.fullmatch(r"0|[1-9][0-9]{0,19}", value)), "InvalidCounter")
    result = int(value)
    require(result <= 18446744073709551615 and (zero or result > 0), "InvalidCounter")
    return result


def binary(value, size: int | None = None, maximum: int = MAX_ENVELOPE) -> bytes:
    require(type(value) is str and len(value) <= maximum and bool(re.fullmatch(r"[A-Za-z0-9_-]*", value)), "InvalidEncoding")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        raise Rejected("InvalidEncoding") from None
    require(base64.urlsafe_b64encode(result).decode().rstrip("=") == value and (size is None or len(result) == size), "InvalidEncoding")
    return result


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def key_id(value: bytes) -> str:
    return "ed25519-sha256:" + hashlib.sha256(value).hexdigest()


def public_key(value: str) -> bytes:
    raw = binary(value, 32)
    require(raw not in (bytes(32), b"\x01" + bytes(31)), "InvalidPublicKey")
    return raw


def exact(value, fields: set[str]) -> dict:
    require(type(value) is dict and set(value) == fields, "InvalidShape")
    return value


def context(value: dict) -> dict:
    require(type(value) is dict and SCOPE <= value.keys(), "ContextMismatch")
    result = {field: value[field] for field in SCOPE}
    require(all(type(v) is str and UUID.fullmatch(v) for v in result.values()), "ContextMismatch")
    return result


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "InvalidJSON")
        result[key] = value
    return result


def _number(value):
    require(bool(re.fullmatch(r"0|[1-9][0-9]*", value)), "InvalidJSON")
    result = int(value)
    require(result <= 9007199254740991, "InvalidJSON")
    return result


def _no_float(_value):
    raise Rejected("InvalidJSON")


def load(raw: bytes, maximum: int):
    require(type(raw) is bytes and 0 < len(raw) <= maximum and not raw.startswith(b"\xef\xbb\xbf"), "ResponseTooLarge")
    try:
        text = raw.decode("utf-8", "strict")
        # Bound nesting and node expansion before json.loads can allocate a large tree.
        quoted, escaped, depth, separators = False, False, 0, 0
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                require(depth <= 16, "InvalidJSON")
            elif char in "]}":
                depth -= 1
            elif char in ",:":
                separators += 1
                require(separators <= 32768, "InvalidJSON")
        result = json.loads(text, object_pairs_hook=_pairs, parse_int=_number, parse_float=_no_float, parse_constant=_no_float)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise Rejected("InvalidJSON") from None
    nodes = 0

    def walk(value, depth=0):
        nonlocal nodes
        nodes += 1
        require(nodes <= 16384 and depth <= 16, "InvalidJSON")
        if type(value) is str:
            require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "InvalidJSON")
        elif type(value) is dict:
            require(len(value) <= 64 and all(type(k) is str and k.isascii() and all(32 <= ord(c) <= 126 for c in k) for k in value), "InvalidJSON")
            for item in value.values():
                walk(item, depth + 1)
        elif type(value) is list:
            require(len(value) <= 4096, "InvalidJSON")
            for item in value:
                walk(item, depth + 1)
        else:
            require(value is None or type(value) in (int, bool), "InvalidJSON")
    walk(result)
    return result


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _signature(body: dict, signature: str, keys: dict[str, str], identifier: str, domain: str) -> None:
    require(type(identifier) is str and identifier in keys, "SignatureInvalid")
    public = public_key(keys[identifier])
    require(key_id(public) == identifier, "SignatureInvalid")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(binary(signature, 64), domain.encode() + b"\0" + canonical(body))
    except (InvalidSignature, ValueError):
        raise Rejected("SignatureInvalid") from None


def publisher_keys(value) -> dict[str, str]:
    require(type(value) is dict and 1 <= len(value) <= 16, "InvalidPublicKey")
    for identifier, encoded in value.items():
        require(type(identifier) is str and key_id(public_key(encoded)) == identifier, "InvalidPublicKey")
    return value


def _envelope_shape(raw: bytes, expected_scope: dict) -> tuple[dict, dict]:
    envelope = exact(load(raw, MAX_ENVELOPE), {"body", "signature"})
    body = exact(envelope["body"], {"header", "nonce", "ciphertext"})
    h = exact(body["header"], HEADER)
    require(context(h) == expected_scope, "ContextMismatch")
    require(h["protocol"] == "e2e2" and h["suite"] == "HKDF-SHA256+A256GCM+Ed25519" and h["intent"] == "publish", "InvalidHeader")
    sequence = counter(h["sequence"])
    counter(h["read_key_epoch"])
    counter(h["publisher_policy_epoch"])
    if sequence == 1:
        require(h["previous_hash"] == ZERO and h["action"] in ("initial", "migrate"), "InvalidHeader")
    else:
        require(type(h["previous_hash"]) is str and bool(HASH.fullmatch(h["previous_hash"])) and h["previous_hash"] != ZERO and h["action"] in ("update", "restore", "rotate-read-key"), "InvalidHeader")
    if h["action"] == "restore":
        require(type(h["restored_from"]) is str and bool(HASH.fullmatch(h["restored_from"])) and h["restored_from"] != ZERO, "InvalidHeader")
    else:
        require(h["restored_from"] is None, "InvalidHeader")
    require(type(h["entry_count"]) is int and 0 <= h["entry_count"] <= 1024, "InvalidHeader")
    require(type(h["parents"]) is list and len(h["parents"]) <= 16, "InvalidHeader")
    previous = None
    for parent in h["parents"]:
        exact(parent, SCOPE | {"sequence", "envelope_hash"})
        source = context(parent)
        order = tuple(source[field] for field in ("realm_id", "project_id", "environment_id", "view_id", "log_id"))
        require(source != expected_scope and (previous is None or order > previous), "InvalidHeader")
        counter(parent["sequence"])
        require(type(parent["envelope_hash"]) is str and bool(HASH.fullmatch(parent["envelope_hash"])) and parent["envelope_hash"] != ZERO, "InvalidHeader")
        previous = order
    binary(h["snapshot_salt"], 32)
    binary(body["nonce"], 12)
    require(type(body["ciphertext"]) is str and len(body["ciphertext"]) <= 12000000, "ResponseTooLarge")
    ciphertext = binary(body["ciphertext"])
    require(16 <= len(ciphertext) <= 8 * 1024 * 1024 + 16, "CiphertextInvalid")
    require(type(h["publisher_key_id"]) is str and bool(re.fullmatch(r"ed25519-sha256:[0-9a-f]{64}", h["publisher_key_id"])), "InvalidPublicKey")
    binary(envelope["signature"], 64)
    return envelope, h


def staged_envelope(raw: bytes, expected_scope: dict) -> tuple[dict, bytes, str]:
    """Shape-only opaque candidate. This result is never a grant or authority."""
    envelope, h = _envelope_shape(raw, expected_scope)
    encoded = canonical(envelope)
    digest = hashlib.sha256(b"sekvyr-e2e2/envelope-hash/v1\0" + encoded).hexdigest()
    return h, encoded, digest


def validate_envelope(raw: bytes, expected_scope: dict, keys: dict[str, str], read_epoch="1", policy_epoch="1") -> tuple[dict, bytes, str]:
    envelope, h = _envelope_shape(raw, expected_scope)
    require(h["read_key_epoch"] == read_epoch and h["publisher_policy_epoch"] == policy_epoch, "UnsupportedEpoch")
    _signature(envelope["body"], envelope["signature"], keys, h["publisher_key_id"], "sekvyr-e2e2/publish/v1")
    encoded = canonical(envelope)
    digest = hashlib.sha256(b"sekvyr-e2e2/envelope-hash/v1\0" + encoded).hexdigest()
    return h, encoded, digest


def node_fingerprint(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded, validate=True)
        require(len(raw) == 65 and base64.b64encode(raw).decode() == encoded, "InvalidNodeKey")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except (ValueError, TypeError):
        raise Rejected("InvalidNodeKey") from None
    return "p256-sha256:" + hashlib.sha256(raw).hexdigest()


def _wrapper_shape(raw: bytes, expected_scope: dict, fingerprint: str) -> tuple[dict, dict]:
    wrapper = exact(load(raw, MAX_WRAP), {"body", "signature"})
    body = exact(wrapper["body"], {"context", "ephemeral_public", "salt", "nonce", "ciphertext"})
    c = exact(body["context"], WRAP_CONTEXT)
    require(context(c) == expected_scope and c["protocol"] == "e2e2-reader-key-v1" and c["recipient_fingerprint"] == fingerprint, "ContextMismatch")
    counter(c["read_key_epoch"])
    counter(c["publisher_policy_epoch"])
    require(type(c["publisher_key_id"]) is str and bool(re.fullmatch(r"ed25519-sha256:[0-9a-f]{64}", c["publisher_key_id"])), "InvalidPublicKey")
    binary(wrapper["signature"], 64)
    raw_point = binary(body["ephemeral_public"], 65)
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_point)
    except ValueError:
        raise Rejected("InvalidReaderWrap") from None
    binary(body["salt"], 32)
    binary(body["nonce"], 12)
    require(16 <= len(binary(body["ciphertext"], maximum=2752)) <= 2064, "InvalidReaderWrap")
    return wrapper, c


def staged_wrapper(raw: bytes, expected_scope: dict, fingerprint: str) -> bytes:
    """Untrusted candidate only. Reader endpoints never consume this result."""
    wrapper, _ = _wrapper_shape(raw, expected_scope, fingerprint)
    return canonical(wrapper)


def validate_wrapper(raw: bytes, expected_scope: dict, fingerprint: str, keys: dict[str, str], read_epoch="1", policy_epoch="1") -> bytes:
    wrapper, c = _wrapper_shape(raw, expected_scope, fingerprint)
    require(c["read_key_epoch"] == read_epoch and c["publisher_policy_epoch"] == policy_epoch, "UnsupportedEpoch")
    _signature(wrapper["body"], wrapper["signature"], keys, c["publisher_key_id"], "sekvyr-e2e2/reader-wrap-sign/v1")
    return canonical(wrapper)


def witness_config() -> dict:
    origin = os.environ.get("SEKVYR_E2E2_WITNESS_ORIGIN", "")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError:
        raise Rejected("WitnessUnavailable", 503) from None
    require(parsed.scheme == "https" and parsed.hostname is not None and parsed.netloc.isascii() and parsed.username is None and parsed.password is None and parsed.path in ("", "/") and not parsed.query and not parsed.fragment and not any(c in origin for c in "?#%\\\r\n\t ") and not origin.rstrip("/").endswith(":") and not parsed.hostname.endswith(".") and port != 0, "WitnessUnavailable", 503)
    if parsed.netloc.rsplit(":", 1)[-1].isdigit() and ":" in parsed.netloc and not parsed.netloc.endswith("]"):
        require(not parsed.netloc.rsplit(":", 1)[-1].startswith("0"), "WitnessUnavailable", 503)
    encoded = os.environ.get("SEKVYR_E2E2_WITNESS_PUBLIC_KEY", "")
    public = public_key(encoded)
    epoch = os.environ.get("SEKVYR_E2E2_WITNESS_EPOCH", "1")
    counter(epoch)
    ca = os.environ.get("SEKVYR_E2E2_WITNESS_CA_FILE", "")
    try:
        tls = ssl.create_default_context(cafile=ca or None)
    except (OSError, ssl.SSLError):
        raise Rejected("WitnessUnavailable", 503) from None
    return {"origin": origin.rstrip("/"), "public": encoded, "key_id": key_id(public), "epoch": epoch, "tls": tls}


def configured() -> bool:
    try:
        witness_config()
        return True
    except (Rejected, ValueError):
        return False


def validate_head(raw: bytes, scope: dict, nonce: str, sequence: str, digest: str, config: dict) -> dict:
    proof = exact(load(raw, MAX_PROOF), {"body", "signature"})
    body = exact(proof["body"], HEAD)
    require(context(body) == scope and body["format"] == "sekvyr-e2e2-head-v1" and body["witness_epoch"] == config["epoch"] and body["witness_key_id"] == config["key_id"], "WitnessEpochMismatch", 409)
    require(body["request_nonce"] == nonce and body["floor_sequence"] == sequence and body["floor_hash"] == digest, "WitnessCheckpointMismatch", 409)
    current, floor = counter(body["sequence"], True), counter(sequence, True)
    require(current >= floor and type(body["envelope_hash"]) is str and bool(HASH.fullmatch(body["envelope_hash"])), "RollbackDetected", 409)
    require((floor == 0 and digest == ZERO) or (floor > 0 and bool(HASH.fullmatch(digest)) and digest != ZERO), "WitnessCheckpointMismatch", 409)
    require(current != floor or body["envelope_hash"] == digest, "ForkDetected", 409)
    read, policy = counter(body["read_key_epoch"], True), counter(body["publisher_policy_epoch"], True)
    require((current == 0 and body["envelope_hash"] == ZERO and read == 0 and policy == 0) or (current > 0 and body["envelope_hash"] != ZERO and read > 0 and policy > 0), "WitnessCheckpointMismatch", 409)
    binary(body["request_nonce"], 32)
    _signature(body, proof["signature"], {config["key_id"]: config["public"]}, config["key_id"], "sekvyr-e2e2/head/v1")
    return body


async def fresh_head(scope: dict, sequence: str, digest: str) -> dict:
    config = witness_config()
    nonce = b64(os.urandom(32))
    url = config["origin"] + "/v1/logs/" + scope["log_id"] + "/head-challenge"
    try:
        async with httpx.AsyncClient(verify=config["tls"], timeout=10, follow_redirects=False, trust_env=False) as client:
            async with client.stream("POST", url, json={"request_nonce": nonce, "floor_sequence": sequence, "floor_hash": digest}) as response:
                require(response.status_code == 200, "WitnessUnavailable", 503)
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    require(size <= MAX_PROOF, "ResponseTooLarge", 503)
                    chunks.append(chunk)
    except httpx.HTTPError:
        raise Rejected("WitnessUnavailable", 503) from None
    return validate_head(b"".join(chunks), scope, nonce, sequence, digest, config)


def witness_fetch_allowed(view_id: str, authorization: str) -> bool:
    allowed = os.environ.get("SEKVYR_E2E2_WITNESS_FETCH_VIEWS", "").split(",")
    if view_id not in allowed:
        return False
    try:
        path = os.environ.get("SEKVYR_E2E2_WITNESS_FETCH_TOKEN_FILE", "")
        with Path(path).open("rb") as source:
            raw = source.read(4097)
        require(len(raw) <= 4096, "AuthRejected", 401)
        token = raw.decode("ascii").strip()
    except (OSError, UnicodeError, Rejected):
        return False
    try:
        supplied = authorization.encode("ascii")
    except UnicodeError:
        return False
    return len(token) >= 32 and hmac.compare_digest(supplied, ("Bearer " + token).encode("ascii"))
