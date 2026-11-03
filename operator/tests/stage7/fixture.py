"""Persistent private trial fixtures; shared crypto primitives, new lifecycle."""

import importlib.util
import json
import os
from pathlib import Path
import re

_source = Path(__file__).resolve().parents[1] / "stage6" / "fixture.py"
_spec = importlib.util.spec_from_file_location("sekvyr_stage6_fixture_primitives", _source)
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
canonical, write_private, token, pem = _base.canonical, _base.write_private, _base.token, _base.pem
ROLES = ("apps", "isolation", "panel", "witness", "gateway", "storage")


def safe_task(value):
    path = Path(value).absolute()
    local = path.parent == Path("/var/tmp") and re.fullmatch(r"sekvyr-stage7\.[A-Za-z0-9_-]+", path.name)
    remote = path.parent == Path("/opt/sekvyr-trial") and re.fullmatch(r"sekvyr-stage7-[0-9]{8}-[0-9a-f]{8}", path.name)
    if path.resolve() != path or not (local or remote):
        raise ValueError("Unapproved persistent stage7 private directory")
    return path


def issue_leaf(task, authority, label, usage, hostnames=()):
    # The original helper checks stage6 paths; use the same reviewed operation
    # with this module's strict stage7 path validator, without mutating it.
    import types
    scope = dict(_base.issue_leaf.__globals__, safe_task=safe_task)
    return types.FunctionType(_base.issue_leaf.__code__, scope)(task, authority, label, usage, hostnames)


class TrialFixture:
    def __init__(self, task):
        self.task = safe_task(task)
        self.private = self.task / "private"
        if not self.private.is_dir() or self.private.is_symlink():
            raise ValueError("Stage7 private directory must be reserved first")
        path = self.private / "fixture.json"
        raw = path.read_bytes()
        value = json.loads(raw)
        self.prefix = self.task.name.replace(".", "-").replace("_", "-").lower()
        self.namespaces = value["namespaces"]
        if value.get("format") != "sekvyr-stage7-fixture-v1" or value.get("production") is not False or set(self.namespaces) != set(ROLES):
            raise ValueError("Stage7 reserved fixture shape mismatch")
        if any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name) for name in self.namespaces.values()) or len(set(self.namespaces.values())) != len(ROLES):
            raise ValueError("Stage7 namespace reservations invalid")
        self.bucket = "canonical-trial-ledger"
        if value.get("bucket", self.bucket) != self.bucket:
            raise ValueError("Trial bucket reservation changed")
        marker = self.private / "crypto-ready.json"
        if marker.exists():
            if marker.is_symlink() or json.loads(marker.read_bytes()) != {"complete": True, "production": False}:
                raise ValueError("Crypto readiness marker changed")
            self.storage_credentials = json.loads((self.private / "storage-credentials.json").read_bytes())
            return
        if any((self.private / name).exists() for name in ("storage-credentials.json", "storage-ca.key", "journal-ca.key", "s3-identities.json")):
            raise ValueError("Incomplete crypto preparation requires explicit repair; no regeneration")
        self.storage_credentials = {role: {"access_key": token(18), "secret_key": token(36)} for role in ("admin", "gateway")}
        _base.TrialFixture._tls(self)
        write_private(self.private / "storage-credentials.json", canonical(self.storage_credentials))
        identities = []
        for role, actions in (("admin", ["Admin"]), ("gateway", [action + ":" + self.bucket for action in (
                "Read", "Write", "List", "GetObjectRetention", "PutObjectRetention", "GetBucketVersioning", "GetBucketObjectLockConfiguration")])):
            credential = self.storage_credentials[role]
            identities.append({"name": "trial-storage-" + role, "credentials": [{"accessKey": credential["access_key"],
                "secretKey": credential["secret_key"]}], "actions": actions})
        write_private(self.private / "s3-identities.json", canonical({"identities": identities}))
        if "bucket" not in value:
            write_private(self.private / "fixture-reservation.json", raw)
            value["bucket"] = self.bucket
            temporary = self.private / "fixture-crypto-ready.json"
            write_private(temporary, canonical(value))
            if path.read_bytes() != raw or path.is_symlink():
                raise ValueError("Fixture reservation changed during crypto preparation")
            os.replace(temporary, path)
        write_private(marker, canonical({"complete": True, "production": False}))

    def __repr__(self):
        return "<persistent stage7 trial fixture [redacted]>"
