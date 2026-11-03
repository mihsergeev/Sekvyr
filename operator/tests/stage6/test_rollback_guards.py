"""Source boundary tests, independent from actual coordinator rollback evidence."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import TrialFixture, canonical, write_private
from protocol import ProtocolAuthority
from rollback_cases import CAS_SQL, READ_SQL, RollbackCases, pointer, sql_input


class FakeApp:
    def __init__(self):
        self.state_name = "operator-state"
        self.value = {"metadata": {"uid": "public-fixture-state-uid", "resourceVersion": "7"}, "data": {
            "state.json": base64.b64encode(b'{"checkpoint":"new"}').decode(), "installation.json": "public-fixture-marker"}}
        self.calls = []

    def get(self, kind, name):
        return copy.deepcopy(self.value)

    def patch(self, kind, name, operations):
        self.calls.append((kind, name, operations))
        self.value["data"]["state.json"] = operations[0]["value"]
        self.value["metadata"]["resourceVersion"] = str(int(self.value["metadata"]["resourceVersion"]) + 1)


class RollbackGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        self.fixture = TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)
        self.private = self.task / "private"
        self.meta = {"project_id": 11, "environment_id": 12}
        write_private(self.private / "panel-bootstrap.json", canonical(self.meta))
        self.namespace = self.fixture.namespaces["panel"]
        write_private(self.private / "database-metadata.json", canonical({"namespace": self.namespace, "service": "database",
            "panel_database_reserved": "trial_panel", "superuser": "trial_admin", "production": False}))
        self.app = FakeApp()
        self.app.namespace = self.fixture.namespaces["apps"]
        self.cluster = SimpleNamespace(kube=Mock())
        self.panel = SimpleNamespace(namespace=self.namespace)
        self.c = SimpleNamespace(private=self.private, app=self.app, panel=self.panel, protocol=self.protocol, cluster=self.cluster)
        self.cases = RollbackCases(self.c)

    def row(self, sequence="3", digest="a" * 64):
        return dict(self.protocol.scope, numeric_project_id=11, numeric_environment_id=12, sequence=sequence, hash=digest)

    def test_sql_uses_fixed_own_table_exact_scope_and_cas_in_stdin(self):
        values = {"expected": pointer("3", "a" * 64), "new": pointer("2", "b" * 64)}
        sql = sql_input(self.protocol.scope, self.meta, CAS_SQL, values)
        self.assertIn("UPDATE e2e2_views SET indexed_sequence", sql)
        self.assertIn("indexed_hash=:'expected_hash'", sql)
        self.assertIn("current_database()='trial_panel'", sql)
        for name in ("view", "realm", "project", "environment", "log"):
            self.assertIn("\\set " + name + " '" + self.protocol.scope[name + "_id"] + "'", sql)
        self.assertNotIn("DELETE", sql)
        self.assertNotIn("DROP", sql)
        self.assertNotIn("TRUNCATE", sql)
        with self.assertRaisesRegex(RuntimeError, "Unapproved"):
            sql_input(self.protocol.scope, self.meta, "UPDATE other_table SET value=1")

    def test_injection_wrong_numeric_owner_and_counter_ambiguity_are_rejected(self):
        for value in ("x'; DROP DATABASE trial_panel; --", "", "https://foreign.example.test"):
            scope = dict(self.protocol.scope, view_id=value)
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "scope"):
                sql_input(scope, self.meta, READ_SQL)
        for sequence in ("01", "-1", "1.0", "18446744073709551616", True):
            with self.subTest(sequence=sequence), self.assertRaises(RuntimeError):
                pointer(sequence, "a" * 64)
        with self.assertRaisesRegex(RuntimeError, "numeric"):
            sql_input(self.protocol.scope, {"project_id": True, "environment_id": 12}, READ_SQL)

    def test_psql_credentials_not_in_argv_and_no_foreign_database(self):
        deployment = {"metadata": {"uid": "database-uid"}, "spec": {"public": "fixture"}}
        pvc = {"metadata": {"uid": "pvc-uid"}}
        self.cluster.kube.return_value = SimpleNamespace(stdout=json.dumps({"database": "trial_panel", "current_user": "trial_admin",
            "owner": "trial_admin", "row": self.row()}))
        with patch("rollback_cases.database_resources", return_value=("trial_panel", deployment, pvc)):
            self.assertEqual(self.cases.read_index(), pointer("3", "a" * 64))
        args, kwargs = self.cluster.kube.call_args
        self.assertEqual(args[args.index("-d") + 1], "trial_panel")
        self.assertEqual(args[args.index("-U") + 1], "trial_admin")
        self.assertEqual(args[args.index("-h") + 1], "/var/run/postgresql")
        self.assertIn("-w", args)
        self.assertNotIn("-c", args[args.index("--") + 1:])
        self.assertIn(self.protocol.scope["view_id"], kwargs["data"])
        self.assertNotIn(self.protocol.scope["view_id"], json.dumps(args))
        self.assertNotIn("password", json.dumps(args).lower())
        self.assertIn("[redacted]", repr(self.cases))
        self.cluster.kube.reset_mock()
        with patch("rollback_cases.database_resources", return_value=("foreign", deployment, pvc)):
            with self.assertRaisesRegex(RuntimeError, "reserved"):
                self.cases.read_index()
        self.cluster.kube.assert_not_called()

    def test_db_replacement_is_rejected_before_sql(self):
        first = {"metadata": {"uid": "own"}, "spec": {}}
        replacement = {"metadata": {"uid": "foreign"}, "spec": {}}
        pvc = {"metadata": {"uid": "own-pvc"}}
        with patch("rollback_cases.database_resources", side_effect=[("trial_panel", first, pvc), ("trial_panel", replacement, pvc)]):
            with self.assertRaisesRegex(RuntimeError, "changed before"):
                self.cases.sql(READ_SQL)
        self.cluster.kube.assert_not_called()

    def test_row_owner_and_full_uuid_scope_must_match(self):
        for owner, row in (("foreign", self.row()), ("trial_admin", dict(self.row(), realm_id="00000000-0000-4000-8000-000000000001")),
                           ("trial_admin", dict(self.row(), numeric_environment_id=99))):
            with self.subTest(owner=owner, row=row), patch.object(self.cases, "sql", return_value={
                "database": "trial_panel", "current_user": "trial_admin", "owner": owner, "row": row}):
                with self.assertRaises(RuntimeError):
                    self.cases.read_index()

    def test_cas_never_rebases_on_foreign_pointer_and_resolves_only_exact_lost_result(self):
        old, new, foreign = pointer("3", "a" * 64), pointer("2", "b" * 64), pointer("4", "c" * 64)
        with patch.object(self.cases, "read_index", return_value=foreign), patch.object(self.cases, "sql") as sql:
            with self.assertRaisesRegex(RuntimeError, "explicit review"):
                self.cases.set_index(old, new)
            sql.assert_not_called()
        with patch.object(self.cases, "read_index", side_effect=[old, new]), patch.object(self.cases, "sql", side_effect=RuntimeError("LostResponse")):
            self.assertTrue(self.cases.set_index(old, new)["exactResultAlreadyPresent"])
        with patch.object(self.cases, "read_index", side_effect=[old, foreign]), patch.object(self.cases, "sql", side_effect=RuntimeError("LostResponse")):
            with self.assertRaisesRegex(RuntimeError, "LostResponse"):
                self.cases.set_index(old, new)

    def test_old_state_replacement_retains_uid_marker_and_requires_new_resource_version(self):
        captured = {"state_name": self.app.state_name, "state_uid": self.app.value["metadata"]["uid"],
            "installation_marker": self.app.value["data"]["installation.json"],
            "old_state_json": base64.b64encode(b'{"checkpoint":"old"}').decode()}
        def apply(*args, **kwargs):
            operations = json.loads(kwargs["data"])
            self.assertEqual(operations[:2], [{"op": "test", "path": "/metadata/uid", "value": captured["state_uid"]},
                {"op": "test", "path": "/metadata/resourceVersion", "value": "7"}])
            self.app.patch("Secret", self.app.state_name, operations[2:])

        self.cluster.kube.side_effect = apply
        self.cases.restore_old_state(captured)
        args, kwargs = self.cluster.kube.call_args
        self.assertIn("--patch-file", args)
        self.assertEqual(args[args.index("--patch-file") + 1], "/dev/stdin")
        self.assertNotIn(captured["old_state_json"], json.dumps(args))
        self.assertEqual(self.app.value["metadata"]["resourceVersion"], "8")
        self.assertEqual(self.app.value["metadata"]["uid"], captured["state_uid"])
        self.assertEqual(self.app.calls[0][2], [{"op": "replace", "path": "/data/state.json", "value": captured["old_state_json"]}])
        self.app.value["metadata"]["uid"] = "replacement"
        calls = len(self.app.calls)
        with self.assertRaisesRegex(RuntimeError, "UID or bootstrap"):
            self.cases.restore_old_state(captured)
        self.assertEqual(len(self.app.calls), calls)


if __name__ == "__main__":
    unittest.main()
