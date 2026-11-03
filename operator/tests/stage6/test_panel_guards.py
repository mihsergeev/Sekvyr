"""Panel fixture ownership and wire checks; these are not live E2E evidence."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import TrialFixture, canonical, write_private
from journal_client import JournalClient, NoRedirect
from panel import Panel
from panel_database import EMPTY_SQL, OWNER_SQL, ensure_trial_database
from protocol import ProtocolAuthority, key_descriptor


class FakeCluster:
    def __init__(self, task, fixture):
        self.task, self.fixture = task, {"namespaces": fixture.namespaces}
        self.pins = task / "pins"
        self.pins.mkdir()
        self.uid = str(uuid.uuid4())
        self.objects, self.calls, self.created_manifests = {}, [], []
        self.password = "public-fixture:/@?#%+password"
        self.pg_exists, self.pg_owner, self.pg_objects = True, "trial_admin", 0
        self.pg_user = "trial_admin"
        self.seed("Deployment", "database", {"spec": {"template": {"spec": {
            "containers": [{"name": "database", "env": [
                {"name": "POSTGRES_USER", "value": "trial_admin"},
                {"name": "POSTGRES_DB", "value": "trial_panel"},
                {"name": "PGDATA", "value": "/data/pgdata"}],
                "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "trial-database"}}]}}}})
        self.seed("PersistentVolumeClaim", "trial-database", {})
        self.seed("Secret", "database-access", {"data": {
            "password": base64.b64encode(self.password.encode()).decode()}})
        self.seed("ServiceAccount", "sekvyr-operator", {}, role="apps")

    def seed(self, kind, name, body, role="panel"):
        namespace = self.fixture["namespaces"][role]
        value = {"kind": kind, "apiVersion": "apps/v1" if kind == "Deployment" else "v1",
            "metadata": {"namespace": namespace, "name": name, "uid": str(uuid.uuid4()), "resourceVersion": "7"}, **copy.deepcopy(body)}
        self.objects[(kind, name)] = value
        write_private(self.pins / (name + ".json"), canonical({"kind": kind, "namespace": namespace,
            "name": name, "uid": value["metadata"]["uid"]}))
        return value

    def namespace_pins(self):
        return {self.fixture["namespaces"]["panel"]: self.uid}

    def kube(self, *args, data=None, check=True):
        self.calls.append((args, data))
        if args[:2] == ("get", "namespace"):
            value = {"metadata": {"uid": self.uid}}
        elif args[:2] == ("get", "--raw"):
            value = {"keys": [{"kty": "RSA", "kid": "public-fixture"}]} if args[2] == "/openid/v1/jwks" else {"issuer": "https://issuer.example.test"}
        elif args[0] == "get":
            kind = "ServiceAccount" if args[1] == "serviceaccount" else args[1]
            value = self.objects[(kind, args[2])]
        elif args[:2] == ("create", "token"):
            return SimpleNamespace(stdout="public-fixture-projected-token\n", returncode=0)
        elif args[0] == "exec":
            statement = args[-1]
            if statement == OWNER_SQL:
                value = {"current_user": self.pg_user, "exists": self.pg_exists,
                    "owner": self.pg_owner if self.pg_exists else None,
                    "template": False if self.pg_exists else None,
                    "allow_connections": True if self.pg_exists else None}
                return SimpleNamespace(stdout=json.dumps(value), returncode=0)
            if statement == EMPTY_SQL:
                value = {"database": "trial_panel", "current_user": self.pg_user,
                    "owner": self.pg_owner, "objects": self.pg_objects}
                return SimpleNamespace(stdout=json.dumps(value), returncode=0)
            if statement == "CREATE DATABASE trial_panel OWNER trial_admin;":
                if self.pg_exists:
                    raise RuntimeError("Database already exists")
                self.pg_exists, self.pg_owner = True, "trial_admin"
                return SimpleNamespace(stdout="CREATE DATABASE\n", returncode=0)
            raise AssertionError("Unexpected SQL operation")
        elif args[0] == "patch":
            value = self.objects[(args[1], args[2])]
        else:
            raise AssertionError("Unexpected local test operation")
        return SimpleNamespace(stdout=json.dumps(copy.deepcopy(value)), returncode=0)

    def create(self, value):
        key = (value["kind"], value["metadata"]["name"])
        if key in self.objects:
            raise RuntimeError("Fixture cannot adopt an existing object")
        self.created_manifests.append(copy.deepcopy(value))
        value = copy.deepcopy(value)
        value["metadata"].update(uid=str(uuid.uuid4()), resourceVersion="7")
        self.objects[key] = value
        return value


class OwnerAPI:
    """Exact backend request and response shapes, without starting a server."""
    def __init__(self, protocol):
        self.protocol, self.calls = protocol, []
        self.initialized, self.sealed = False, True

    def request(self, method, path, raw=None, headers=None, expected=(200,), maximum=None):
        body = json.loads(raw) if raw is not None else None
        self.calls.append((method, path, body, headers, tuple(expected)))
        status = 200
        if path == "/api/auth/login":
            assert set(body) == {"username", "password"} and body["username"] == "admin"
            result = {"access_token": "public-fixture-owner-session", "token_type": "bearer"}
        elif path == "/api/vault/status":
            result = {"initialized": self.initialized, "sealed": self.sealed}
        elif path == "/api/vault/init":
            assert body == {"mode": "env"} and not self.initialized
            self.initialized, self.sealed = True, False
            result = {"mode": "env", "shares": [], "root_key": "public-fixture-root", "warning": ""}
        elif path == "/api/vault/unseal":
            assert body == {"root_key": "public-fixture-root"} and self.initialized
            self.sealed = False
            result = {"sealed": False, "pending_shares": 0, "threshold": 0, "detail": ""}
        elif path == "/api/projects":
            assert body == {"slug": "trial", "title": "Isolated trial", "environments": ["trial"]}
            result, status = {"id": 11}, 201
        elif path == "/api/projects/11/environments":
            result = [{"id": 12, "name": "trial"}]
        elif path == "/api/machines/clusters":
            assert set(body) == {"name", "issuer", "audience", "jwks"}
            assert body["audience"] == "sekvyr" and isinstance(json.loads(body["jwks"])["keys"], list)
            result, status = {"id": 13}, 201
        elif path == "/api/machines":
            assert body["cluster_id"] == 13 and body["k8s_service_account"] == "sekvyr-operator"
            result, status = {"id": 14}, 201
        elif path == "/api/policies":
            assert body == {"subject_type": "machine", "subject_id": 14, "project_id": 11,
                "environment_id": 12, "path_prefix": "/", "actions": ["list", "read"], "effect": "allow"}
            result, status = {"id": 15}, 201
        elif path == "/api/v1/machine/token":
            assert body == {"kubernetes_token": "public-fixture-projected-token"}
            result = {"access_token": "public-fixture-machine-session", "token_type": "bearer", "expires_in": 900, "name": "reader"}
        elif path == "/api/v1/machine/report":
            assert set(body) == {"public_key"}
            assert base64.b64decode(body["public_key"], validate=True) == self.protocol.node_public
            assert headers["Authorization"] == "Bearer public-fixture-machine-session"
            result = {"ok": True}
        elif path == "/api/e2e2/views":
            assert body == {"project_id": 11, "environment_id": 12, "context": self.protocol.scope,
                "publisher_keys": {key_descriptor(self.protocol.publisher)["key_id"]: key_descriptor(self.protocol.publisher)["public_key"]},
                "read_key_epoch": "1", "publisher_policy_epoch": "1"}
            result, status = {"id": self.protocol.scope["view_id"]}, 201
        else:
            raise AssertionError("Unexpected owner fixture request")
        assert status in expected
        if path not in ("/api/auth/login", "/api/v1/machine/token", "/api/v1/machine/report"):
            assert headers["Authorization"] == "Bearer public-fixture-owner-session"
        return status, canonical(result), {}


class PanelGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        fixture = TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)
        self.cluster = FakeCluster(self.task, fixture)
        write_private(self.task / "private" / "fetch-token", b"public-fixture-fetch-token")
        self.panel = Panel(self.cluster, self.protocol, None)

    def prepare(self):
        return self.panel.prepare("example/panel@sha256:" + "a" * 64, "trial-storage", "https://witness.example.test")

    def test_prepare_pins_scope_and_versions_and_keeps_credentials_out_of_argv(self):
        self.prepare()
        resources = {value["kind"]: value for value in self.cluster.created_manifests}
        self.assertEqual(resources["Deployment"]["apiVersion"], "apps/v1")
        for kind, value in resources.items():
            self.assertEqual(value["metadata"]["namespace"], self.panel.namespace)
            if kind != "Deployment":
                self.assertEqual(value["apiVersion"], "v1")
        access = json.loads((self.task / "private" / "panel-access.json").read_text())
        argv = json.dumps([args for args, _ in self.cluster.calls])
        for value in (*access.values(), self.cluster.password, "public-fixture-fetch-token"):
            self.assertNotIn(value, argv)
        self.assertIn("public-fixture%3A%2F%40%3F%23%25%2Bpassword", access["SEKVYR_DB_URL"])
        self.assertTrue(access["SEKVYR_DB_URL"].endswith("@database:5432/trial_panel"))
        container = resources["Deployment"]["spec"]["template"]["spec"]["containers"][0]
        for entry in container["env"]:
            if entry["name"] in access:
                self.assertEqual(entry["valueFrom"]["secretKeyRef"], {"name": "panel-access", "key": entry["name"]})
        self.assertNotIn("SEKVYR_ADMIN_PASSWORD_RESET", json.dumps(container))
        self.assertIn("[redacted]", repr(self.panel))
        sql = [args[-1] for args, _ in self.cluster.calls if args[0] == "exec"]
        self.assertEqual(sql, [OWNER_SQL, EMPTY_SQL])

    def test_foreign_namespace_or_namespace_replacement_prevents_mutation(self):
        with self.assertRaisesRegex(RuntimeError, "outside owned namespace"):
            self.panel.create({"kind": "Secret", "metadata": {"name": "x", "namespace": "foreign"}})
        self.cluster.uid = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "namespace replaced"):
            self.prepare()
        self.assertFalse(self.cluster.created_manifests)
        self.assertFalse(any(args[0] == "exec" for args, _ in self.cluster.calls))

    def test_replaced_database_uid_and_unpinned_secret_prevent_sql(self):
        self.cluster.objects[("Deployment", "database")]["metadata"]["uid"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            self.prepare()
        del self.panel.created[("Secret", "database-access")]
        with self.assertRaisesRegex(RuntimeError, "creation UID"):
            self.panel.get("Secret", "database-access")
        self.assertFalse(any(args[0] == "exec" for args, _ in self.cluster.calls))

    def test_second_prepare_does_not_reset_sql_or_credentials(self):
        self.prepare()
        before = (self.task / "private" / "panel-access.json").read_bytes()
        calls = len(self.cluster.calls)
        with self.assertRaisesRegex(RuntimeError, "reset"):
            self.prepare()
        self.assertEqual(before, (self.task / "private" / "panel-access.json").read_bytes())
        self.assertEqual(len(self.cluster.calls), calls)

    def test_owner_bootstrap_uses_pinned_sa_and_exact_backend_wire(self):
        self.prepare()
        client = OwnerAPI(self.protocol)
        self.panel.client = client
        metadata = self.panel.bootstrap()
        self.assertEqual(metadata, {"project_id": 11, "environment_id": 12, "cluster_id": 13, "machine_id": 14})
        paths = [path for _, path, *_ in client.calls]
        self.assertLess(paths.index("/api/policies"), paths.index("/api/v1/machine/token"))
        self.assertLess(paths.index("/api/v1/machine/report"), paths.index("/api/e2e2/views"))
        self.assertEqual(paths.count("/api/vault/init"), 1)
        before = len(client.calls)
        with self.assertRaisesRegex(RuntimeError, "reset"):
            self.panel.bootstrap()
        self.assertEqual(before, len(client.calls))
        argv = json.dumps([args for args, _ in self.cluster.calls])
        for credential in ("public-fixture-projected-token", "public-fixture-owner-session", "public-fixture-root"):
            self.assertNotIn(credential, argv)

    def test_bootstrap_refuses_replaced_or_foreign_sa_before_machine_registration(self):
        self.prepare()
        client = OwnerAPI(self.protocol)
        self.panel.client = client
        self.cluster.objects[("ServiceAccount", "sekvyr-operator")]["metadata"]["uid"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "pinned ServiceAccount"):
            self.panel.bootstrap()
        self.assertNotIn("/api/machines", [path for _, path, *_ in client.calls])
        self.assertFalse(any(args[:2] == ("create", "token") for args, _ in self.cluster.calls))

    def test_existing_vault_unseals_saved_key_without_init_and_never_overwrites_recovery(self):
        self.prepare()
        client = OwnerAPI(self.protocol)
        client.initialized = True
        self.panel.client = client
        self.panel.login()
        key = self.task / "private" / "panel-vault-key.json"
        write_private(key, canonical({"root_key": "public-fixture-root"}))
        before = key.read_bytes()
        self.panel.unseal()
        self.assertFalse(client.sealed)
        self.assertNotIn("/api/vault/init", [path for _, path, *_ in client.calls])
        self.assertEqual(before, key.read_bytes())
        client.initialized = False
        with self.assertRaisesRegex(RuntimeError, "reset saved"):
            self.panel.unseal()
        self.assertEqual(before, key.read_bytes())

    def test_independent_authority_json_and_https_client_disable_proxy_redirect(self):
        cfg = json.loads(canonical(self.panel.authority_config("https://witness.example.test")))
        registration = cfg["registrations"][0]
        self.assertEqual(registration["scope"], self.protocol.scope)
        self.assertEqual(registration["genesis_hash"], self.protocol.genesis_hash)
        self.assertEqual(registration["witness_public_key"], key_descriptor(self.protocol.witness)["public_key"])
        self.assertEqual(registration["minimum_cursor"], self.protocol.registration["minimum_cursor"])
        with patch("journal_client.urllib.request.build_opener") as build:
            JournalClient("https://localhost:8443", self.task / "private" / "journal-ca.crt")
            handlers = build.call_args.args
            self.assertEqual(next(h.proxies for h in handlers if isinstance(h, urllib.request.ProxyHandler)), {})
            redirect = next(h for h in handlers if isinstance(h, NoRedirect))
            self.assertIsNone(redirect.redirect_request(None, None, 302, "", {}, "https://foreign.example.test"))
        for origin in ("http://localhost", "https://user:password@localhost", "https://localhost/path", "https://localhost?x=1", "https://localhost#x"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                JournalClient(origin, self.task / "private" / "journal-ca.crt")

    def test_patch_uid_rv_cas_and_no_identity_replacement(self):
        self.prepare()
        self.panel.scale(0)
        args, _ = next(call for call in reversed(self.cluster.calls) if call[0][0] == "patch")
        operations = json.loads(args[args.index("-p") + 1])
        self.assertEqual(operations[0], {"op": "test", "path": "/metadata/uid", "value": self.panel.created[("Deployment", "panel")]["uid"]})
        self.assertEqual(operations[1], {"op": "test", "path": "/metadata/resourceVersion", "value": "7"})
        with self.assertRaisesRegex(RuntimeError, "Unsafe"):
            self.panel.patch("Deployment", "panel", [{"op": "replace", "path": "/metadata/uid", "value": "foreign"}])
        self.cluster.objects[("Deployment", "panel")]["metadata"]["uid"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            self.panel.scale(1)

    def test_reserved_empty_database_reuse_requires_owner_and_never_runs_create_or_reset(self):
        result = ensure_trial_database(self.panel)
        self.assertTrue(result["reservedDatabaseReused"])
        self.assertFalse(result["databaseCreated"])
        statements = [args[-1] for args, _ in self.cluster.calls if args[0] == "exec"]
        self.assertEqual(statements, [OWNER_SQL, EMPTY_SQL])
        for args, _ in self.cluster.calls:
            if args[0] == "exec":
                self.assertIn("-X", args)
                self.assertIn("-w", args)
                self.assertNotIn(self.cluster.password, json.dumps(args))

    def test_nonreserved_configuration_can_create_only_a_new_database(self):
        env = self.cluster.objects[("Deployment", "database")]["spec"]["template"]["spec"]["containers"][0]["env"]
        next(item for item in env if item["name"] == "POSTGRES_DB")["value"] = "postgres"
        with self.assertRaisesRegex(RuntimeError, "explicitly reserved"):
            ensure_trial_database(self.panel)
        self.cluster.pg_exists = False
        result = ensure_trial_database(self.panel)
        self.assertTrue(result["databaseCreated"])
        self.assertFalse(result["reservedDatabaseReused"])
        statements = [args[-1] for args, _ in self.cluster.calls if args[0] == "exec"]
        self.assertEqual(statements.count("CREATE DATABASE trial_panel OWNER trial_admin;"), 1)

    def test_nonempty_or_foreign_owner_or_wrong_login_cannot_be_reused(self):
        for owner, login, objects in (("foreign", "trial_admin", 0), ("trial_admin", "foreign", 0),
                                      ("trial_admin", "trial_admin", 1)):
            with self.subTest(owner=owner, login=login, objects=objects):
                self.cluster.pg_owner, self.cluster.pg_user, self.cluster.pg_objects = owner, login, objects
                self.cluster.calls.clear()
                with self.assertRaises(RuntimeError):
                    ensure_trial_database(self.panel)
                self.assertFalse(any(args[0] == "exec" and args[-1].startswith("CREATE") for args, _ in self.cluster.calls))

    def test_database_pvc_uid_or_reference_replacement_blocks_sql(self):
        pvc = self.cluster.objects[("PersistentVolumeClaim", "trial-database")]
        original = pvc["metadata"]["uid"]
        pvc["metadata"]["uid"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            ensure_trial_database(self.panel)
        pvc["metadata"]["uid"] = original
        pod = self.cluster.objects[("Deployment", "database")]["spec"]["template"]["spec"]
        pod["volumes"][0]["persistentVolumeClaim"]["claimName"] = "foreign"
        with self.assertRaisesRegex(RuntimeError, "PVC binding"):
            ensure_trial_database(self.panel)
        self.assertFalse(any(args[0] == "exec" for args, _ in self.cluster.calls))

    def test_wrong_initializer_or_ambiguous_environment_and_missing_reserved_db_fail_closed(self):
        env = self.cluster.objects[("Deployment", "database")]["spec"]["template"]["spec"]["containers"][0]["env"]
        user = next(item for item in env if item["name"] == "POSTGRES_USER")
        user["value"] = "foreign"
        with self.assertRaisesRegex(RuntimeError, "initialization identity"):
            ensure_trial_database(self.panel)
        user["value"] = "trial_admin"
        env.append(copy.deepcopy(user))
        with self.assertRaisesRegex(RuntimeError, "Ambiguous"):
            ensure_trial_database(self.panel)
        env.pop()
        self.cluster.pg_exists = False
        with self.assertRaisesRegex(RuntimeError, "Reserved fixture database is missing"):
            ensure_trial_database(self.panel)
        self.assertFalse(any(args[0] == "exec" and args[-1].startswith("CREATE") for args, _ in self.cluster.calls))

    def test_uid_change_between_sql_checks_stops_before_connecting_to_target(self):
        original = self.cluster.kube

        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[0] == "exec":
                self.cluster.objects[("PersistentVolumeClaim", "trial-database")]["metadata"]["uid"] = str(uuid.uuid4())
            return result

        with patch.object(self.cluster, "kube", side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, "replaced"):
                ensure_trial_database(self.panel)
        statements = [args[-1] for args, _ in self.cluster.calls if args[0] == "exec"]
        self.assertEqual(statements, [OWNER_SQL])

    def test_sql_failure_or_malformed_output_does_not_disclose_response(self):
        original = self.cluster.kube
        sensitive = "public-fixture-private-response-marker"
        for failure in (False, True):
            def invalid(*args, **kwargs):
                if args[0] == "exec":
                    if failure:
                        raise RuntimeError(sensitive)
                    return SimpleNamespace(stdout=sensitive, returncode=0)
                return original(*args, **kwargs)

            with self.subTest(failure=failure), patch.object(self.cluster, "kube", side_effect=invalid):
                with self.assertRaises(RuntimeError) as caught:
                    ensure_trial_database(self.panel)
                self.assertNotIn(sensitive, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
