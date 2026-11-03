"""Real owner/pod-JWT panel provider for the isolated stage7 Plain cases.

No action runs on import. The coordinator owns Kubernetes lifecycle and any
control-plane signing-key rotation. This provider never discovers trust from
incoming JWT headers or changes a shared cluster's signing files.
"""

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlencode
import uuid


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def write_once(path, value):
    raw = canonical(value)
    require(not path.is_symlink(), "Stage7 private input path changed")
    if path.exists():
        require(path.read_bytes() == raw, "Stage7 reviewed input differs")
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


class Session:
    def __init__(self, token, expires):
        require(isinstance(token, str) and 0 < len(token) <= 16384 and type(expires) is int and 0 < expires <= 3600,
            "Stage7 machine session shape invalid")
        self.token, self.expires = token, expires

    def __repr__(self):
        return "<stage7 in-memory machine session [redacted]>"


def observe_jwt(token):
    """Observation after server authentication only; claims never grant trust."""
    require(isinstance(token, str) and 0 < len(token) <= 8000 and token.count(".") == 2, "Stage7 projected JWT observation invalid")
    try:
        def part(raw):
            return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        header, claims = (part(raw) for raw in token.split(".")[:2])
        kube = claims["kubernetes.io"]
        pod = kube["pod"]
        account = kube["serviceaccount"]
        require(type(claims["iat"]) is int and type(claims["exp"]) is int and claims["exp"] > claims["iat"]
            and all(isinstance(value, str) and 0 < len(value) <= 253 for value in
                (header["kid"], pod["uid"], pod["name"], account["name"], account["uid"], kube["namespace"])), "Stage7 projected JWT observation invalid")
        return {"hash": hashlib.sha256(token.encode()).hexdigest(), "kid": header["kid"], "iat": claims["iat"], "exp": claims["exp"],
            "pod_uid": pod["uid"], "pod_name": pod["name"], "namespace": kube["namespace"], "service_account": account["name"],
            "service_account_uid": account["uid"]}
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise RuntimeError("Stage7 projected JWT observation invalid") from None


def public_jwks(value):
    require(isinstance(value, dict) and set(value) == {"keys"} and isinstance(value["keys"], list) and 1 <= len(value["keys"]) <= 16,
        "Stage7 explicit public JWKS invalid")
    kids = []
    for key in value["keys"]:
        require(isinstance(key, dict) and key.get("kty") in ("RSA", "EC", "OKP") and isinstance(key.get("kid"), str)
            and 0 < len(key["kid"]) <= 200 and not ({"d", "p", "q", "dp", "dq", "qi", "oth", "k"} & set(key)),
            "Stage7 explicit public JWKS invalid")
        kids.append(key["kid"])
    require(len(set(kids)) == len(kids), "Stage7 duplicate public JWKS kid")
    return sorted(kids)


class PanelCases:
    def __init__(self, coordinator, operation_id="plain"):
        require(isinstance(operation_id, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,39}", operation_id), "Stage7 operation identifier invalid")
        self.c, self.panel, self.operation = coordinator, coordinator.panel, operation_id
        self.root = coordinator.private / "stage7" / ("panel-" + operation_id)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self.root / "metadata.json"
        self.meta = json.loads(metadata.read_bytes()) if metadata.exists() else None

    def __repr__(self):
        return "<isolated stage7 Plain panel provider [redacted]>"

    def identity(self, namespace, service_account):
        cluster = self.c.cluster
        pins = cluster.namespace_pins()
        require(namespace in pins and namespace in cluster.fixture["namespaces"].values(), "Stage7 source namespace is not owned")
        ns = json.loads(cluster.kube("get", "namespace", namespace, "-o", "json").stdout)
        require(ns["metadata"]["uid"] == pins[namespace] and not ns["metadata"].get("deletionTimestamp"), "Stage7 source namespace replaced")
        records = [json.loads(path.read_bytes()) for path in cluster.pins.glob("*.json")]
        matches = [item for item in records if item["kind"] == "ServiceAccount" and item["namespace"] == namespace and item["name"] == service_account]
        require(len(matches) == 1, "Stage7 source ServiceAccount lacks creation UID")
        account = json.loads(cluster.kube("get", "ServiceAccount", service_account, "-n", namespace, "-o", "json").stdout)
        require(account["metadata"]["uid"] == matches[0]["uid"] and not account["metadata"].get("deletionTimestamp"), "Stage7 source ServiceAccount replaced")
        return {"namespace": namespace, "namespace_uid": pins[namespace], "service_account": service_account, "service_account_uid": matches[0]["uid"]}

    def ready(self):
        require(isinstance(self.meta, dict), "Stage7 Plain source is not prepared")
        require(self.identity(self.meta["namespace"], self.meta["service_account"]) == self.meta["identity"], "Stage7 Plain source identity changed")
        return self.meta

    def prepare_plain(self, service_account, namespace=None):
        namespace = namespace or self.c.app.namespace
        require(isinstance(service_account, str) and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?", service_account)
            and service_account not in ("sekvyr-operator", "sekvyr-fencer"), "Stage7 needs a separate Plain source ServiceAccount")
        identity = self.identity(namespace, service_account)
        if self.meta is not None:
            require(self.meta["identity"] == identity and self.meta["panel_origin"] == self.c.panel_origin, "Stage7 prepared source differs")
            return self.routing()
        prepared = self.root / "prepared.json"
        require(not prepared.exists(), "Incomplete Stage7 Plain bootstrap needs explicit review")
        slug = "public-s7-" + uuid.uuid4().hex[:16]
        plan = {"identity": identity, "project": slug, "environment": "trial", "path": "/runtime", "panel_origin": self.c.panel_origin}
        write_once(prepared, plan)
        self.panel.unseal()
        _, project = self.panel.owner_request("POST", "/api/projects", {"slug": slug, "title": "Public isolated Plain trial", "environments": ["trial", "denied"]}, (201,))
        require(project.get("e2e") is False, "Stage7 Plain source unexpectedly encrypted")
        _, environments = self.panel.owner_request("GET", "/api/projects/" + str(project["id"]) + "/environments")
        envs = {item["name"]: item["id"] for item in environments}
        require(set(envs) == {"trial", "denied"}, "Stage7 Plain environment set differs")
        jwks = json.loads(self.c.cluster.kube("get", "--raw", "/openid/v1/jwks").stdout)
        issuer = json.loads(self.c.cluster.kube("get", "--raw", "/.well-known/openid-configuration").stdout)["issuer"]
        public_jwks(jwks)
        require(isinstance(issuer, str) and 0 < len(issuer) <= 300, "Stage7 explicit issuer invalid")
        _, cluster = self.panel.owner_request("POST", "/api/machines/clusters", {"name": slug + "-cluster", "issuer": issuer,
            "audience": "sekvyr", "jwks": json.dumps(jwks)}, (201,))
        _, machine = self.panel.owner_request("POST", "/api/machines", {"name": slug + "-reader", "cluster_id": cluster["id"],
            "k8s_namespace": namespace, "k8s_service_account": service_account}, (201,))
        _, policy = self.panel.owner_request("POST", "/api/policies", {"subject_type": "machine", "subject_id": machine["id"],
            "project_id": project["id"], "environment_id": envs["trial"], "path_prefix": "/runtime", "actions": ["list", "read"], "effect": "allow"}, (201,))
        self.meta = {**plan, **identity, "identity": identity, "project_id": project["id"], "environment_id": envs["trial"],
            "denied_environment_id": envs["denied"], "cluster_id": cluster["id"], "machine_id": machine["id"], "policy_id": policy["id"],
            "machine_name": slug + "-reader", "group": "", "issuer": issuer, "initial_jwks": jwks}
        write_once(self.root / "metadata.json", self.meta)
        return self.routing()

    def routing(self):
        meta = self.ready()
        return {key: meta[key] for key in ("project_id", "environment_id", "machine_id", "cluster_id", "group", "project", "environment", "path")} | {
            "source_config": {"SEKVYR_URL": meta["panel_origin"], "SEKVYR_PROJECT": meta["project"], "SEKVYR_ENV": meta["environment"]}}

    def publish(self, generation, demo_value):
        meta = self.ready()
        require(all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", value) for value in (generation, demo_value)),
            "Stage7 publish requires bounded public canary values")
        values = {"GENERATION": generation, "DEMO_VALUE": demo_value}
        write_once(self.root / ("publish-" + hashlib.sha256(canonical(values)).hexdigest() + ".json"), {"generation": generation, "demo_value": demo_value})
        # Existing import API commits both values in one transaction. Two PUTs
        # could expose an unintended mixed pair to a concurrent plain reader.
        text = "".join(name + "=" + json.dumps(value) + "\n" for name, value in sorted(values.items()))
        _, result = self.panel.owner_request("POST", "/api/environments/" + str(meta["environment_id"]) + "/import",
            {"path": meta["path"], "text": text, "overwrite": True})
        require(result.get("created", 0) + result.get("updated", 0) == 2 and result.get("skipped") == [], "Stage7 Plain atomic import differs")
        return {"plainValuesPublished": True, "valueCount": 2, "valuesDigest": hashlib.sha256(canonical(values)).hexdigest()}

    def exchange(self, projected_jwt, expected=200):
        self.ready()
        require(isinstance(projected_jwt, str) and 0 < len(projected_jwt) <= 8000 and expected in (200, 401), "Stage7 exchange input invalid")
        code, body = self.panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": projected_jwt}, expected=(expected,))
        require(code == expected, "Stage7 machine exchange result differs")
        if code == 200:
            require(body.get("name") == self.meta["machine_name"], "Stage7 machine exchange authenticated another source identity")
        return Session(body["access_token"], body["expires_in"]) if code == 200 else None

    def read(self, session, values=None, expected=200, source=None):
        meta = self.ready()
        require(isinstance(session, Session) and expected in (200, 401, 403, 503), "Stage7 read input invalid")
        source = source or {"project": meta["project"], "env": meta["environment"], "group": meta["group"]}
        require(set(source) == {"project", "env", "group"} and all(isinstance(value, str) and len(value) <= 64
            and not any(ord(char) < 32 for char in value) for value in source.values()), "Stage7 exact source routing invalid")
        code, body = self.panel.request("GET", "/api/v1/machine/secrets?" + urlencode(source), access_token=session.token, expected=(expected,))
        if code != 200:
            return {"http": code, "sourceAllowed": False}
        require(body.get("project") == source["project"] and body.get("environment") == source["env"] and body.get("e2e") is False
            and body.get("project_key") is None and isinstance(body.get("values"), list), "Stage7 Plain response source or encryption differs")
        rows = body["values"]
        require(all(set(row) == {"name", "path", "value"} and row["path"] == meta["path"] and type(row["value"]) is str for row in rows),
            "Stage7 Plain response escaped allowed path")
        actual = {row["name"]: row["value"] for row in rows}
        require(len(actual) == len(rows), "Stage7 Plain response has duplicate names")
        if values is not None:
            require(actual == values, "Stage7 Plain selected values differ")
        return {"http": code, "sourceAllowed": True, "valueCount": len(rows), "valuesDigest": hashlib.sha256(canonical(actual)).hexdigest()}

    def assert_denied_source(self, session, project, environment, group=""):
        return self.read(session, expected=403, source={"project": project, "env": environment, "group": group})

    @contextmanager
    def sealed(self):
        self.ready()
        _, status = self.panel.owner_request("GET", "/api/vault/status")
        require(status.get("initialized") is True and status.get("sealed") is False, "Stage7 sealed case needs current initialized unsealed vault")
        self.panel.owner_request("POST", "/api/vault/seal", {})
        try:
            yield
        finally:
            self.panel.unseal()

    def revoke(self):
        meta = self.ready()
        _, machine = self.panel.owner_request("PATCH", "/api/machines/" + str(meta["machine_id"]), {"disabled": True})
        require(machine.get("id") == meta["machine_id"] and machine.get("disabled") is True, "Stage7 owned machine revoke differs")

    def restore(self):
        meta = self.ready()
        _, machine = self.panel.owner_request("PATCH", "/api/machines/" + str(meta["machine_id"]), {"disabled": False})
        require(machine.get("id") == meta["machine_id"] and machine.get("disabled") is False, "Stage7 owned machine restore differs")

    def assert_revoke_restore(self, session, projected_jwt, values):
        self.read(session, values)
        try:
            self.revoke()
            self.read(session, expected=401)
            self.exchange(projected_jwt, expected=401)
        finally:
            self.restore()
        self.read(session, expected=401)
        fresh = self.exchange(projected_jwt)
        self.read(fresh, values)
        return {"immediateMachineRevoke": True, "oldSessionNotRevived": True, "freshAuthenticationRestored": True}

    def assert_token_refresh(self, old_jwt, new_jwt):
        self.exchange(old_jwt)
        self.exchange(new_jwt)
        old, new = observe_jwt(old_jwt), observe_jwt(new_jwt)
        meta = self.ready()
        require(all(old[field] == new[field] for field in ("pod_uid", "pod_name", "namespace", "service_account", "service_account_uid"))
            and old["namespace"] == meta["namespace"] and old["service_account"] == meta["service_account"]
            and old["service_account_uid"] == meta["service_account_uid"] and old["hash"] != new["hash"]
            and new["iat"] > old["iat"] and new["exp"] > old["exp"], "Stage7 same-Pod projected token did not refresh")
        require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", new["pod_name"]), "Stage7 observed Pod name invalid")
        pod = json.loads(self.c.cluster.kube("get", "pod", new["pod_name"], "-n", meta["namespace"], "-o", "json").stdout)
        require(pod["metadata"]["uid"] == new["pod_uid"] and not pod["metadata"].get("deletionTimestamp")
            and pod["spec"].get("serviceAccountName") == meta["service_account"], "Stage7 refreshed JWT Pod was replaced")
        return {"samePodProjectedJWTRefreshed": True, "newAuthenticationAccepted": True, "signingKeyChanged": old["kid"] != new["kid"]}

    def update_jwks(self, public_keys):
        meta = self.ready()
        public_jwks(public_keys)
        write_once(self.root / ("jwks-" + hashlib.sha256(canonical(public_keys)).hexdigest() + ".json"), public_keys)
        _, result = self.panel.owner_request("PATCH", "/api/machines/clusters/" + str(meta["cluster_id"]),
            {"issuer": meta["issuer"], "audience": "sekvyr", "jwks": json.dumps(public_keys)})
        require(result.get("id") == meta["cluster_id"] and result.get("issuer") == meta["issuer"] and result.get("audience") == "sekvyr",
            "Stage7 owned cluster JWKS update differs")

    def assert_manual_jwks_rollover(self, old_jwt, new_jwt, overlap, new_only):
        old, new = observe_jwt(old_jwt), observe_jwt(new_jwt)
        overlap_kids, new_kids = public_jwks(overlap), public_jwks(new_only)
        require(old["kid"] != new["kid"] and old["kid"] in overlap_kids and new["kid"] in overlap_kids
            and old["kid"] not in new_kids and new["kid"] in new_kids, "Stage7 real signing-key rotation inputs differ")
        def unexpired_pair():
            # Observed claims grant no trust; both tokens are authenticated in
            # overlap below. Keep retirement distinguishable from token expiry.
            now = time.time()
            require(all(value["iat"] <= now and value["exp"] > now + 30 for value in (old, new)),
                "Stage7 JWKS retirement requires both JWTs valid beyond safety margin")
        unexpired_pair()  # Refuse stale inputs before any owner JWKS mutation.
        self.update_jwks(overlap)
        self.exchange(old_jwt)
        self.exchange(new_jwt)
        unexpired_pair()  # Do not retire a signer after slow overlap exchanges.
        self.update_jwks(new_only)
        self.exchange(old_jwt, expected=401)
        self.exchange(new_jwt)
        unexpired_pair()  # A 401 after expiry cannot prove signer retirement.
        return {"manualOutOfBandJWKSOverlapAccepted": True, "retiredKidNewExchangeDenied": True,
            "newKidExchangeAccepted": True, "bothJWTsUnexpiredDuringRetirement": True,
            "existingMachineSessionImmediateRevocationClaimed": False}
