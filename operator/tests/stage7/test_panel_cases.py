"""Local source-provider guards, not proof of live JWT or Kubernetes acceptance."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from panel_cases import PanelCases, Session, canonical, observe_jwt, public_jwks, write_once


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class FakeCluster:
    def __init__(self, task):
        self.task, self.pins = task, task / "pins"
        self.pins.mkdir()
        self.namespace, self.ns_uid = "public-stage7-apps", str(uuid.uuid4())
        self.service_account, self.sa_uid = "public-plain-reader", str(uuid.uuid4())
        self.pod_uid, self.calls = str(uuid.uuid4()), []
        self.fixture = {"namespaces": {"apps": self.namespace}}
        write_once(self.pins / "service-account.json", {"kind": "ServiceAccount", "name": self.service_account,
            "namespace": self.namespace, "uid": self.sa_uid})

    def namespace_pins(self):
        return {self.namespace: self.ns_uid}

    def kube(self, *args):
        self.calls.append(args)
        if args[:2] == ("get", "namespace"):
            value = {"metadata": {"name": self.namespace, "uid": self.ns_uid}}
        elif args[:2] == ("get", "ServiceAccount"):
            value = {"metadata": {"name": self.service_account, "namespace": self.namespace, "uid": self.sa_uid}}
        elif args[:2] == ("get", "pod"):
            value = {"metadata": {"name": "public-reader-pod", "namespace": self.namespace, "uid": self.pod_uid},
                "spec": {"serviceAccountName": self.service_account}}
        elif args[:2] == ("get", "--raw"):
            value = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "public-key-one", "x": b64(b"PUBLIC synthetic reference point!")}]} if args[2] == "/openid/v1/jwks" else {"issuer": "https://issuer.example.test"}
        else:
            raise AssertionError("Unexpected local test Kubernetes call")
        return SimpleNamespace(stdout=json.dumps(value))

    def jwt(self, kid="public-key-one", issued=100):
        header = {"alg": "EdDSA", "kid": kid, "typ": "JWT"}
        claims = {"iat": issued, "exp": issued + 600, "kubernetes.io": {"namespace": self.namespace,
            "serviceaccount": {"name": self.service_account, "uid": self.sa_uid}, "pod": {"name": "public-reader-pod", "uid": self.pod_uid}}}
        return b64(canonical(header)) + "." + b64(canonical(claims)) + "." + b64(b"PUBLIC unsigned fixture signature")


class FakeOwnerAPI:
    """Shape/state double only. JWT cryptography is covered by backend/live tests."""
    def __init__(self):
        self.calls, self.machine, self.project = [], None, None
        self.disabled, self.version, self.sealed_value = False, 0, False
        self.values, self.sessions, self.valid_kids = {}, {}, {"public-key-one"}
        self.created_projects = 0

    def unseal(self):
        self.sealed_value = False

    def owner_request(self, method, path, body=None, expected=(200,)):
        self.calls.append((method, path, copy.deepcopy(body)))
        status = 200
        if path == "/api/projects":
            self.created_projects += 1
            self.project = body["slug"]
            result, status = {"id": 11, "slug": self.project, "e2e": False}, 201
        elif path == "/api/projects/11/environments":
            result = [{"id": 12, "name": "trial"}, {"id": 13, "name": "denied"}]
        elif path == "/api/machines/clusters":
            result, status = {"id": 14}, 201
        elif path == "/api/machines":
            self.machine = body["name"]
            result, status = {"id": 15, "name": self.machine}, 201
        elif path == "/api/policies":
            result, status = {"id": 16}, 201
        elif path == "/api/environments/12/import":
            assert body["path"] == "/runtime" and body["overwrite"] is True
            self.values = {name: json.loads(value) for line in body["text"].splitlines() for name, _, value in [line.partition("=")]}
            result = {"created": 2, "updated": 0, "skipped": []}
        elif path == "/api/vault/status":
            result = {"initialized": True, "sealed": self.sealed_value}
        elif path == "/api/vault/seal":
            self.sealed_value = True
            result = {"sealed": True}
        elif path == "/api/machines/15":
            self.disabled = body["disabled"]
            self.version += 1
            result = {"id": 15, "disabled": self.disabled}
        elif path == "/api/machines/clusters/14":
            self.valid_kids = set(public_jwks(json.loads(body["jwks"])))
            result = {"id": 14, "issuer": body["issuer"], "audience": body["audience"]}
        else:
            raise AssertionError("Unexpected local owner API request")
        assert status in expected
        return status, result

    def request(self, method, path, body=None, access_token=None, expected=(200,)):
        if path == "/api/v1/machine/token":
            kid = observe_jwt(body["kubernetes_token"])["kid"]
            if self.disabled or kid not in self.valid_kids:
                code, result = 401, {"detail": "fixture authentication denied"}
            else:
                token = "public-fixture-machine-session-" + str(len(self.sessions))
                self.sessions[token] = self.version
                code, result = 200, {"name": self.machine, "access_token": token, "expires_in": 900}
        else:
            assert method == "GET" and urlsplit(path).path == "/api/v1/machine/secrets"
            query = parse_qs(urlsplit(path).query, keep_blank_values=True)
            if self.disabled or self.sessions.get(access_token) != self.version:
                code, result = 401, {"detail": "fixture authentication denied"}
            elif self.sealed_value:
                code, result = 503, {"detail": "fixture sealed"}
            elif query != {"project": [self.project], "env": ["trial"], "group": [""]}:
                code, result = 403, {"detail": "fixture scope denied"}
            else:
                code, result = 200, {"project": self.project, "environment": "trial", "e2e": False, "project_key": None,
                    "values": [{"name": name, "path": "/runtime", "value": value} for name, value in self.values.items()]}
        assert code in expected
        return code, result


class PanelCasesGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage7.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name)
        self.private = self.task / "private"
        self.private.mkdir()
        self.cluster, self.panel = FakeCluster(self.task), FakeOwnerAPI()
        self.c = SimpleNamespace(cluster=self.cluster, private=self.private, panel=self.panel,
            app=SimpleNamespace(namespace=self.cluster.namespace), panel_origin="https://panel.example.test")
        self.provider = PanelCases(self.c)
        self.values = {"GENERATION": "public-generation-001", "DEMO_VALUE": "public-canary-value-001"}

    def prepared(self):
        result = self.provider.prepare_plain(self.cluster.service_account)
        self.provider.publish(self.values["GENERATION"], self.values["DEMO_VALUE"])
        return result

    def test_plain_owner_bootstrap_exact_namespace_policy_and_atomic_values(self):
        result = self.prepared()
        self.assertEqual(result["path"], "/runtime")
        self.assertEqual(result["source_config"], {"SEKVYR_URL": self.c.panel_origin, "SEKVYR_PROJECT": self.panel.project, "SEKVYR_ENV": "trial"})
        policy = next(body for method, path, body in self.panel.calls if path == "/api/policies")
        self.assertEqual(policy, {"subject_type": "machine", "subject_id": 15, "project_id": 11, "environment_id": 12,
            "path_prefix": "/runtime", "actions": ["list", "read"], "effect": "allow"})
        self.assertEqual(sum(path.endswith("/import") for _, path, _ in self.panel.calls), 1)
        self.assertFalse(any(path.endswith("/secrets") for _, path, _ in self.panel.calls))
        self.assertEqual(self.provider.prepare_plain(self.cluster.service_account), result)
        self.assertEqual(self.panel.created_projects, 1)
        session = self.provider.exchange(self.cluster.jwt())
        self.assertEqual(self.provider.read(session, self.values)["valueCount"], 2)
        self.assertIn("[redacted]", repr(session))

    def test_foreign_or_replaced_sa_cannot_create_source_and_partial_prepare_is_not_adopted(self):
        with self.assertRaisesRegex(RuntimeError, "not owned"):
            self.provider.prepare_plain(self.cluster.service_account, "foreign")
        self.cluster.sa_uid = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            self.provider.prepare_plain(self.cluster.service_account)
        self.assertEqual(self.panel.calls, [])
        self.cluster.sa_uid = json.loads((self.cluster.pins / "service-account.json").read_bytes())["uid"]
        write_once(self.provider.root / "prepared.json", {"partial": True})
        with self.assertRaisesRegex(RuntimeError, "Incomplete"):
            self.provider.prepare_plain(self.cluster.service_account)
        self.assertEqual(self.panel.calls, [])

    def test_sealed_and_revoke_restore_never_revive_old_machine_session(self):
        self.prepared()
        jwt = self.cluster.jwt()
        session = self.provider.exchange(jwt)
        with self.provider.sealed():
            self.assertEqual(self.provider.read(session, expected=503)["http"], 503)
        self.provider.read(session, self.values)
        result = self.provider.assert_revoke_restore(session, jwt, self.values)
        self.assertTrue(result["immediateMachineRevoke"] and result["oldSessionNotRevived"])
        self.assertFalse(self.panel.disabled)

    def test_forbidden_exact_source_is_403_and_never_accepts_external_url(self):
        self.prepared()
        session = self.provider.exchange(self.cluster.jwt())
        self.assertEqual(self.provider.assert_denied_source(session, self.panel.project, "denied")["http"], 403)
        self.assertEqual(self.provider.assert_denied_source(session, self.panel.project, "trial", "public-unassigned")["http"], 403)
        with self.assertRaisesRegex(RuntimeError, "routing"):
            self.provider.read(session, source={"project": self.panel.project, "env": "trial", "group": "", "origin": "https://other.example.test"})

    def test_token_refresh_requires_actual_current_same_pod_and_does_not_claim_new_kid(self):
        self.prepared()
        result = self.provider.assert_token_refresh(self.cluster.jwt(issued=100), self.cluster.jwt(issued=500))
        self.assertTrue(result["samePodProjectedJWTRefreshed"])
        self.assertFalse(result["signingKeyChanged"])
        with self.assertRaisesRegex(RuntimeError, "did not refresh"):
            self.provider.assert_token_refresh(self.cluster.jwt(), self.cluster.jwt())

    def test_manual_jwks_rollover_is_owner_scoped_and_rejects_private_material(self):
        self.prepared()
        initial = self.provider.meta["initial_jwks"]
        new_key = dict(initial["keys"][0], kid="public-key-two")
        new_only, overlap = {"keys": [new_key]}, {"keys": initial["keys"] + [new_key]}
        with patch("panel_cases.time.time", return_value=200):
            result = self.provider.assert_manual_jwks_rollover(self.cluster.jwt(), self.cluster.jwt(kid="public-key-two"), overlap, new_only)
        self.assertTrue(result["retiredKidNewExchangeDenied"])
        self.assertTrue(result["bothJWTsUnexpiredDuringRetirement"])
        self.assertFalse(result["existingMachineSessionImmediateRevocationClaimed"])
        patch_paths = [path for method, path, _ in self.panel.calls if method == "PATCH"]
        self.assertEqual(patch_paths, ["/api/machines/clusters/14", "/api/machines/clusters/14"])
        with self.assertRaisesRegex(RuntimeError, "public JWKS"):
            self.provider.update_jwks({"keys": [dict(new_key, d="public-private-field-must-reject")]})

    def test_expired_or_near_expiry_old_token_cannot_mutate_jwks(self):
        self.prepared()
        initial = self.provider.meta["initial_jwks"]
        new_key = dict(initial["keys"][0], kid="public-key-two")
        for now in (701, 670):  # expired, or exactly the forbidden 30s margin.
            with self.subTest(now=now), patch("panel_cases.time.time", return_value=now):
                with self.assertRaisesRegex(RuntimeError, "safety margin"):
                    self.provider.assert_manual_jwks_rollover(self.cluster.jwt(), self.cluster.jwt(kid="public-key-two", issued=500),
                        {"keys": initial["keys"] + [new_key]}, {"keys": [new_key]})
        self.assertFalse(any(method == "PATCH" for method, _, _ in self.panel.calls))
        self.assertEqual(list(self.provider.root.glob("jwks-*.json")), [])
        self.assertEqual(self.panel.sessions, {})

    def test_expired_new_token_is_also_refused_before_mutation(self):
        self.prepared()
        initial = self.provider.meta["initial_jwks"]
        new_key = dict(initial["keys"][0], kid="public-key-two")
        with patch("panel_cases.time.time", return_value=701), self.assertRaisesRegex(RuntimeError, "safety margin"):
            self.provider.assert_manual_jwks_rollover(self.cluster.jwt(issued=500), self.cluster.jwt(kid="public-key-two"),
                {"keys": initial["keys"] + [new_key]}, {"keys": [new_key]})
        self.assertFalse(any(method == "PATCH" for method, _, _ in self.panel.calls))

    def test_expiry_after_overlap_does_not_retire_old_key(self):
        self.prepared()
        initial = self.provider.meta["initial_jwks"]
        new_key = dict(initial["keys"][0], kid="public-key-two")
        with patch("panel_cases.time.time", side_effect=[200, 701]), self.assertRaisesRegex(RuntimeError, "safety margin"):
            self.provider.assert_manual_jwks_rollover(self.cluster.jwt(), self.cluster.jwt(kid="public-key-two", issued=200),
                {"keys": initial["keys"] + [new_key]}, {"keys": [new_key]})
        changes = [body for method, _, body in self.panel.calls if method == "PATCH"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(set(public_jwks(json.loads(changes[0]["jwks"]))), {"public-key-one", "public-key-two"})

    def test_expiry_after_retirement_401_cannot_be_credited_as_kid_proof(self):
        self.prepared()
        initial = self.provider.meta["initial_jwks"]
        new_key = dict(initial["keys"][0], kid="public-key-two")
        with patch("panel_cases.time.time", side_effect=[200, 200, 701]), self.assertRaisesRegex(RuntimeError, "safety margin"):
            self.provider.assert_manual_jwks_rollover(self.cluster.jwt(), self.cluster.jwt(kid="public-key-two", issued=200),
                {"keys": initial["keys"] + [new_key]}, {"keys": [new_key]})
        # The fake panel deliberately ignores expiration. Its old-kid 401 and
        # new-kid 200 still cannot produce PASS after old token expiration.
        self.assertEqual(self.panel.valid_kids, {"public-key-two"})
        self.assertEqual(len(self.panel.sessions), 3)

    def test_no_projected_or_machine_bearer_is_persisted_or_put_in_kube_argv(self):
        self.prepared()
        jwt = self.cluster.jwt()
        session = self.provider.exchange(jwt)
        self.provider.read(session, self.values)
        private_bytes = b"".join(path.read_bytes() for path in self.provider.root.rglob("*.json"))
        self.assertNotIn(jwt.encode(), private_bytes)
        self.assertNotIn(session.token.encode(), private_bytes)
        argv = json.dumps(self.cluster.calls)
        self.assertNotIn(jwt, argv)
        self.assertNotIn(session.token, argv)
        self.assertNotIn(session.token, repr(session))


if __name__ == "__main__":
    unittest.main()
