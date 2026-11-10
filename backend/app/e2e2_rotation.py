"""Untrusted rotation staging and nonce-bound witness authority projection.

No caller-supplied key set is authoritative. The current witness key, genesis
and journal floor come only from independent read-only administrative config.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

import httpx

from app import e2e2

MAX_AUTHORITY_PROOF = 1024 * 1024 + 64 * 1024
CURSOR = {"journal_sequence", "record_hash"}
SNAPSHOT = {"sequence", "envelope_hash", "read_key_epoch", "publisher_policy_epoch"}
AUTHORITY = {"revision", "admin_key", "publisher_policy_epoch", "publisher_keys", "read_key_epoch", "witness_epoch", "witness_key", "fencer_epoch", "fencer_keys"}
ENROLLMENT = {"installation_id", "bootstrap_generation", "namespace", "namespace_uid", "operator_service_account", "operator_service_account_uid", "fencer_service_account", "fencer_service_account_uid", "lease", "node_fingerprint", "identity_key_secret_uid", "trust_bundle_secret_uid", "allowed_objects"}
OBJECT = {"api_version", "kind", "namespace", "name", "uid"}
STATE = {"scope", "genesis_hash", "cursor", "snapshot", "authority", "authority_digest", "enrollments"}
REGISTRATION = {"scope", "genesis_hash", "minimum_cursor", "witness_public_key", "witness_epoch", "witness_origin", "ca_file", "client_cert_file", "client_key_file"}


def _hash(value, zero=False):
    e2e2.require(type(value) is str and bool(e2e2.HASH.fullmatch(value)) and (zero or value != e2e2.ZERO), "AuthorityProofInvalid")
    return value


def cursor(value):
    e2e2.exact(value, CURSOR)
    e2e2.counter(value["journal_sequence"], True)
    _hash(value["record_hash"])
    return value


def _key(value):
    e2e2.exact(value, {"key_id", "public_key"})
    raw = e2e2.public_key(value["public_key"])
    e2e2.require(value["key_id"] == e2e2.key_id(raw), "AuthorityProofInvalid")
    return value


def _keys(value):
    e2e2.require(type(value) is list and 1 <= len(value) <= 16, "AuthorityProofInvalid")
    previous = ""
    for key in value:
        _key(key)
        e2e2.require(key["key_id"] > previous, "AuthorityProofInvalid")
        previous = key["key_id"]
    return value


def _authority(value):
    e2e2.exact(value, AUTHORITY)
    for field in ("revision", "publisher_policy_epoch", "read_key_epoch", "witness_epoch", "fencer_epoch"):
        e2e2.counter(value[field])
    identifiers = []
    for field in ("admin_key", "witness_key"):
        identifiers.append(_key(value[field])["key_id"])
    for field in ("publisher_keys", "fencer_keys"):
        identifiers.extend(key["key_id"] for key in _keys(value[field]))
    e2e2.require(len(set(identifiers)) == len(identifiers), "AuthorityProofInvalid")
    return value


def _enrollments(value):
    e2e2.require(type(value) is dict and len(value) <= 64, "AuthorityProofInvalid")
    for identifier, enrollment in value.items():
        e2e2.exact(enrollment, ENROLLMENT)
        e2e2.require(identifier == enrollment["installation_id"], "AuthorityProofInvalid")
        for field in ("installation_id", "namespace_uid", "operator_service_account_uid", "fencer_service_account_uid", "identity_key_secret_uid", "trust_bundle_secret_uid"):
            e2e2.require(type(enrollment[field]) is str and bool(e2e2.UUID.fullmatch(enrollment[field])), "AuthorityProofInvalid")
        e2e2.require(type(enrollment["bootstrap_generation"]) is int and 1 <= enrollment["bootstrap_generation"] <= 9007199254740991, "AuthorityProofInvalid")
        for field in ("namespace", "operator_service_account", "fencer_service_account"):
            e2e2.require(type(enrollment[field]) is str and 1 <= len(enrollment[field]) <= 253 and bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", enrollment[field])), "AuthorityProofInvalid")
        e2e2.require(type(enrollment["node_fingerprint"]) is str and bool(re.fullmatch(r"p256-sha256:[0-9a-f]{64}", enrollment["node_fingerprint"])), "AuthorityProofInvalid")
        lease = e2e2.exact(enrollment["lease"], OBJECT)
        e2e2.require(lease["api_version"] == "coordination.k8s.io/v1" and lease["kind"] == "Lease" and lease["namespace"] == enrollment["namespace"], "AuthorityProofInvalid")
        e2e2.require(type(enrollment["allowed_objects"]) is list and 1 <= len(enrollment["allowed_objects"]) <= 64, "AuthorityProofInvalid")
        previous = None
        for obj in enrollment["allowed_objects"]:
            e2e2.exact(obj, OBJECT)
            e2e2.require(all(type(v) is str for v in obj.values()) and obj["namespace"] == enrollment["namespace"] and bool(e2e2.UUID.fullmatch(obj["uid"])) and (obj["api_version"], obj["kind"]) in (("v1", "Secret"), ("apps/v1", "Deployment")), "AuthorityProofInvalid")
            order = tuple(obj[field] for field in ("api_version", "kind", "namespace", "name"))
            e2e2.require(previous is None or order > previous, "AuthorityProofInvalid")
            previous = order
    return value


def registrations() -> list[dict]:
    path = os.environ.get("SEKVYR_E2E2_AUTHORITY_CONFIG_FILE", "")
    try:
        with Path(path).open("rb") as source:
            config = e2e2.exact(e2e2.load(source.read(128 * 1024 + 1), 128 * 1024), {"format", "registrations"})
    except (OSError, ValueError):
        raise e2e2.Rejected("AuthorityUnavailable", 503) from None
    e2e2.require(config["format"] == "sekvyr-panel-authority-config-v1" and type(config["registrations"]) is list and 1 <= len(config["registrations"]) <= 64, "AuthorityUnavailable", 503)
    seen = set()
    for entry in config["registrations"]:
        e2e2.exact(entry, REGISTRATION)
        scope = e2e2.exact(entry["scope"], e2e2.SCOPE)
        e2e2.context(scope)
        e2e2.require(scope["log_id"] not in seen, "AuthorityUnavailable", 503)
        seen.add(scope["log_id"])
        _hash(entry["genesis_hash"])
        cursor(entry["minimum_cursor"])
        if entry["minimum_cursor"]["journal_sequence"] == "0":
            e2e2.require(entry["minimum_cursor"]["record_hash"] == entry["genesis_hash"], "AuthorityUnavailable", 503)
        e2e2.public_key(entry["witness_public_key"])
        e2e2.counter(entry["witness_epoch"])
        e2e2.require(all(type(entry[field]) is str and 1 <= len(entry[field]) <= 4096 for field in ("witness_origin", "ca_file", "client_cert_file", "client_key_file")), "AuthorityUnavailable", 503)
    return config["registrations"]


def registration(expected_scope: dict) -> dict:
    for entry in registrations():
        if entry["scope"] == expected_scope:
            return entry
    raise e2e2.Rejected("AuthorityUnavailable", 503)


def tls_configured(entry: dict) -> bool:
    try:
        _tls(entry)
        return True
    except e2e2.Rejected:
        return False


def select_floor(config: dict, projection) -> dict:
    floor = dict(config["minimum_cursor"])
    if projection is None:
        return floor
    e2e2.require(projection.genesis_hash == config["genesis_hash"] and e2e2.counter(config["witness_epoch"]) >= e2e2.counter(projection.witness_epoch), "AuthorityDowngrade", 409)
    stored = {"journal_sequence": projection.journal_sequence, "record_hash": projection.record_hash}
    cursor(stored)
    old, pinned = e2e2.counter(stored["journal_sequence"], True), e2e2.counter(floor["journal_sequence"], True)
    e2e2.require(old != pinned or stored["record_hash"] == floor["record_hash"], "AuthorityFork", 409)
    return stored if old >= pinned else floor


def validate_proof(raw: bytes, expected_scope: dict, nonce: str, floor: dict, config: dict) -> dict:
    proof = e2e2.exact(e2e2.load(raw, MAX_AUTHORITY_PROOF), {"body", "key_id", "signature"})
    body = e2e2.exact(proof["body"], {"format", "state", "request_nonce", "floor"})
    e2e2.require(body["format"] == "sekvyr-authority-proof-v2" and body["request_nonce"] == nonce and body["floor"] == floor, "AuthorityProofInvalid", 409)
    e2e2.binary(body["request_nonce"], 32)
    cursor(body["floor"])
    state = e2e2.exact(body["state"], STATE)
    e2e2.require(e2e2.exact(state["scope"], e2e2.SCOPE) == expected_scope and state["genesis_hash"] == config["genesis_hash"], "ContextMismatch", 409)
    current = cursor(state["cursor"])
    seq, minimum = e2e2.counter(current["journal_sequence"], True), e2e2.counter(floor["journal_sequence"], True)
    e2e2.require(seq >= minimum and (seq != minimum or current["record_hash"] == floor["record_hash"]), "AuthorityDowngrade", 409)
    authority = _authority(state["authority"])
    witness = authority["witness_key"]
    e2e2.require(witness["public_key"] == config["witness_public_key"] and authority["witness_epoch"] == config["witness_epoch"] and proof["key_id"] == witness["key_id"], "WitnessEpochMismatch", 409)
    _enrollments(state["enrollments"])
    digest_body = {field: state[field] for field in ("scope", "genesis_hash", "authority", "enrollments")}
    digest = hashlib.sha256(b"sekvyr-e2e2/authority-state-hash/v1\0" + e2e2.canonical(digest_body)).hexdigest()
    e2e2.require(_hash(state["authority_digest"]) == digest, "AuthorityProofInvalid", 409)
    snapshot = e2e2.exact(state["snapshot"], SNAPSHOT)
    e2e2.counter(snapshot["sequence"])
    _hash(snapshot["envelope_hash"])
    e2e2.require(snapshot["read_key_epoch"] == authority["read_key_epoch"] and snapshot["publisher_policy_epoch"] == authority["publisher_policy_epoch"], "AuthorityProofInvalid", 409)
    e2e2._signature(body, proof["signature"], {witness["key_id"]: config["witness_public_key"]}, proof["key_id"], "sekvyr-e2e2/authority-proof/v2")
    return state


def _tls(config):
    origin = config["witness_origin"]
    try:
        parsed = urlsplit(origin)
        port = parsed.port
        e2e2.require(parsed.scheme == "https" and parsed.hostname is not None and parsed.netloc.isascii() and parsed.username is None and parsed.password is None and parsed.path in ("", "/") and not any(c in origin for c in "?#%\\\r\n\t ") and not origin.rstrip("/").endswith(":") and not parsed.hostname.endswith(".") and port != 0, "AuthorityUnavailable", 503)
        if ":" in parsed.netloc and parsed.netloc.rsplit(":", 1)[-1].isdigit():
            e2e2.require(not parsed.netloc.rsplit(":", 1)[-1].startswith("0"), "AuthorityUnavailable", 503)
        tls = ssl.create_default_context(cafile=config["ca_file"])
        tls.load_cert_chain(config["client_cert_file"], config["client_key_file"])
    except (ValueError, TypeError, OSError, ssl.SSLError):
        raise e2e2.Rejected("AuthorityUnavailable", 503) from None
    return origin.rstrip("/"), tls


async def fresh_authority(expected_scope: dict, projection) -> dict:
    config = registration(expected_scope)
    floor = select_floor(config, projection)
    origin, tls = _tls(config)
    nonce = e2e2.b64(os.urandom(32))
    try:
        async with httpx.AsyncClient(verify=tls, timeout=15, follow_redirects=False, trust_env=False) as client:
            async with client.stream("POST", origin + "/v2/logs/" + expected_scope["log_id"] + "/authority-challenge", json={"request_nonce": nonce, "floor": floor}) as response:
                e2e2.require(response.status_code == 200, "AuthorityUnavailable", 503)
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    e2e2.require(size <= MAX_AUTHORITY_PROOF, "ResponseTooLarge", 503)
                    chunks.append(chunk)
    except httpx.HTTPError:
        raise e2e2.Rejected("AuthorityUnavailable", 503) from None
    return validate_proof(b"".join(chunks), expected_scope, nonce, floor, config)
