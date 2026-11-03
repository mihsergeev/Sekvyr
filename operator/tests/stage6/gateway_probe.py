"""Actual gateway checks; storage-admin faults affect dedicated auxiliary logs."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json

from fixture import canonical, safe_task
from journal_client import JournalClient
from protocol import ProtocolAuthority, record_hash
from storage_probe import client as storage_client


def clients(task, origin):
    private = safe_task(task) / "private"
    return {role: JournalClient(origin, private / "journal-ca.crt", private / (role + ".crt"), private / (role + ".key"))
            for role in ("admin", "witness-a", "witness-b", "fencer", "operator", "unregistered")}


def framed(raw, nonce, expected_record_hash):
    # Diagnostic framing checks only. Actual journal authentication and replay
    # take place independently inside the Go gateway/witness, never this helper.
    lines = raw.splitlines()
    if len(lines) < 2:
        raise RuntimeError("Truncated journal diagnostics")
    begin, end = json.loads(lines[0]), json.loads(lines[-1])
    if (begin.get("format") != "sekvyr-journal-stream-begin-v1" or end.get("format") != "sekvyr-journal-stream-end-v1"
        or begin.get("nonce") != nonce or end.get("nonce") != nonce or begin.get("count") != end.get("count")
        or len(lines) != begin["count"] + 2 or begin.get("last_record_hash") != expected_record_hash
        or end.get("last_record_hash") != expected_record_hash):
        raise RuntimeError("Journal diagnostics do not match exact accepted cursor")
    return [json.loads(line) for line in lines[1:-1]]


def bootstrap_and_authorize(task, origin):
    task = safe_task(task)
    authority = ProtocolAuthority.load(task)
    identities = clients(task, origin)
    logs = [{"record": authority.genesis_record, "registration": authority.registration}, *authority.fault_logs.values()]
    for entry in logs:
        raw = canonical(entry["record"])
        status, response, _ = identities["admin"].append(entry["registration"]["log_id"], "0", raw)
        receipt = json.loads(response)
        if status != 200 or receipt.get("mode") != "COMPLIANCE" or not receipt.get("version_id"):
            raise RuntimeError("Gateway did not acknowledge a retained genesis")
        reader = identities["witness-a"] if entry["registration"]["log_id"] == authority.scope["log_id"] else identities["admin"]
        nonce, (_, stream, _) = reader.journal(entry["registration"]["log_id"])
        slots = framed(stream, nonce, entry["registration"]["genesis_hash"])
        if len(slots) != 1 or record_hash(slots[0]["record"]) != entry["registration"]["genesis_hash"]:
            raise RuntimeError("Gateway returned different genesis")
    log_id = authority.scope["log_id"]
    path = JournalClient.path(log_id, "0")
    payload = canonical(authority.genesis_record)
    for role in ("witness-a", "witness-b", "fencer", "operator"):
        identities[role].append(log_id, "0", payload, expected=(403,))
    identities["unregistered"].request("GET", JournalClient.path(log_id),
        headers={"X-Sekvyr-Journal-Nonce": base64.urlsafe_b64encode(bytes(32)).decode().rstrip("=")}, expected=(403,))
    admin = identities["admin"]
    admin.request("PUT", path, payload, {"Content-Type": "application/json"}, expected=(400,))
    for method, suffix in (("DELETE", ""), ("DELETE", "?versionId=not-authorized"), ("POST", "?uploads")):
        admin.request(method, path + suffix, b"{}" if method == "POST" else None,
                      {"Content-Type": "application/json"}, expected=(400, 403, 405))
    admin.request("GET", "/" + "canonical-trial-ledger", expected=(403,))
    return {"retainedGenesisLogsInitialized": len(logs), "freshNonceJournalRoundTrip": True,
        "runtimeProfilesCannotInitialize": 4, "unregisteredClientDenied": True,
        "unconditionalPutDenied": True, "deleteVersionMultipartAndS3ProxyRoutesDenied": True,
        "production": False}


def inject_storage_fault(task, storage_origin, gateway_origin, label):
    """Offline admin only; never use the main application log for these faults."""
    if label not in ("duplicate-version", "delete-marker"):
        raise ValueError("Unknown dedicated trial fault")
    task = safe_task(task)
    authority = ProtocolAuthority.load(task)
    entry = authority.fault_logs[label]
    log_id = entry["registration"]["log_id"]
    if log_id == authority.scope["log_id"]:
        raise ValueError("Primary log must not be poisoned")
    fixture = json.loads((task / "private" / "fixture.json").read_text(encoding="utf-8"))
    upstream = storage_client(storage_origin, task / "private", "admin")
    key = "canonical/" + log_id + "/00000000000000000000.json"
    if label == "duplicate-version":
        raw = canonical(entry["record"])
        upstream.put_object(Bucket=fixture["bucket"], Key=key, Body=raw, ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=datetime.now(timezone.utc) + timedelta(days=1),
            ChecksumSHA256=base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii"))
    else:
        upstream.delete_object(Bucket=fixture["bucket"], Key=key)
    admin = clients(task, gateway_origin)["admin"]
    status, body, _ = admin.request("GET", JournalClient.path(log_id), headers={
        "X-Sekvyr-Journal-Nonce": base64.urlsafe_b64encode(bytes(32)).decode().rstrip("=")}, expected=(503,))
    if status != 503 or json.loads(body).get("reason") != "StorageVersionConflict":
        raise RuntimeError("Unsafe storage versions did not fail closed")
    # The independent normal log must remain usable after poisoning the auxiliary.
    nonce, (_, raw, _) = admin.journal(authority.scope["log_id"])
    framed(raw, nonce, authority.genesis_hash)
    return {"fault": label, "gatewayFailClosed": True, "primaryLogUnaffected": True}
