"""Guard tests exercise privacy, network isolation and destructive-action scope."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import io
import urllib.error
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cluster import Cluster
from fixture import TrialFixture, canonical, safe_task, write_private
from manifests import LABEL, SEAWEED_IMAGE, fsync_command, gateway_manifests, network_policies, storage_manifests
from protocol import ProtocolAuthority, gateway_config, key_descriptor, record_hash
from journal_client import JournalClient


class TrialGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.task = Path(self.directory.name).resolve()
        self.addCleanup(self.directory.cleanup)

    def test_fixture_private_material_never_appears_in_public_manifests(self):
        fixture = TrialFixture(self.task)
        manifests = storage_manifests(fixture.namespaces, "trial-storage") + network_policies(fixture.namespaces)
        rendered = json.dumps(manifests)
        for credentials in fixture.storage_credentials.values():
            for value in credentials.values():
                self.assertNotIn(value, rendered)
        self.assertNotIn("PRIVATE KEY", rendered)
        self.assertNotIn("accessKey", rendered)
        self.assertIn("[redacted]", repr(fixture))

    def test_private_writes_are_exclusive_and_cannot_overwrite_checkpoint(self):
        target = self.task / "checkpoint.json"
        write_private(target, "first")
        with self.assertRaises(FileExistsError):
            write_private(target, "replacement")
        self.assertEqual(target.read_text(), "first")

    def test_gateway_contains_upstream_mounts_and_witness_profiles_do_not(self):
        fixture = TrialFixture(self.task)
        protocol = ProtocolAuthority(self.task)
        config = gateway_config(self.task, protocol)
        for profile in config["clients"]:
            self.assertNotIn("secret", json.dumps(profile).lower())
            if "witness" in profile["common_name"]:
                self.assertNotIn("genesis", profile["write_kinds"])
        deployment = next(item for item in gateway_manifests(fixture.namespaces, "example/gateway@sha256:" + "1" * 64)
                          if item["kind"] == "Deployment")
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        self.assertTrue(container["args"][0].startswith("--config="))
        self.assertIn("--allow-trial-canonical-ledger", container["args"])
        self.assertEqual({item["name"] for item in container["env"]}, {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"})
        self.assertNotIn("PRIVATE KEY", json.dumps(config))

    def test_offline_genesis_signs_complete_authority_and_preserves_hash_on_reload(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519
        fixture = TrialFixture(self.task)
        protocol = ProtocolAuthority(self.task)
        genesis = protocol.genesis_record["genesis"]
        public = key_descriptor(protocol.admin)["public_key"]
        verifier = ed25519.Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(public + "="))
        verifier.verify(base64.urlsafe_b64decode(genesis["signature"] + "=="),
                        b"sekvyr-e2e2/journal-genesis/v1\0" + canonical(genesis["body"]))
        loaded = ProtocolAuthority.load(self.task)
        self.assertEqual(loaded.genesis_hash, protocol.genesis_hash)
        changed = copy.deepcopy(protocol.genesis_record)
        changed["genesis"]["body"]["authority"]["read_key_epoch"] = "2"
        self.assertNotEqual(record_hash(changed), protocol.genesis_hash)

    def test_journal_paths_cannot_escape_registration_or_overflow_counter(self):
        log_id = "11111111-1111-4111-8111-111111111111"
        self.assertTrue(JournalClient.path(log_id, "0").endswith("/slots/0"))
        for invalid in ("01", "-1", "18446744073709551616", "1/../../elsewhere", "1?other=1"):
            with self.subTest(counter=invalid), self.assertRaises(ValueError):
                JournalClient.path(log_id, invalid)
        for invalid in (log_id + "/../../other", "https://elsewhere.test", ""):
            with self.subTest(log_id=invalid), self.assertRaises(ValueError):
                JournalClient.path(invalid)

    def test_journal_error_response_is_bounded_and_does_not_escape_body(self):
        client = JournalClient.__new__(JournalClient)
        client.origin = "https://journal.example.test"
        with patch.object(client, "opener", create=True) as opener:
            opener.open.side_effect = urllib.error.HTTPError(client.origin, 403, "private-response-marker", {}, io.BytesIO(b"denied"))
            status, raw, _ = client.request("DELETE", "/v1/storage/logs/test", expected=(403,))
            self.assertEqual(status, 403)
            self.assertEqual(raw, b"denied")
            opener.open.side_effect = urllib.error.HTTPError(client.origin, 500, "private-response-marker", {}, io.BytesIO(b"private-body-marker"))
            with self.assertRaisesRegex(RuntimeError, "Unexpected journal HTTP status 500") as failure:
                client.request("GET", "/v1/storage/logs/test")
            self.assertNotIn("private", str(failure.exception))

    def test_task_scope_and_fsync_command_reject_arbitrary_inputs(self):
        with self.assertRaises(ValueError):
            safe_task(self.task.parent)
        for invalid in ("bucket/../../outside", "bucket\nfs.rm -r /", "", "bucket;other"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                fsync_command(invalid)
        self.assertEqual(fsync_command("canonical-trial-ledger"),
            "fs.configure -locationPrefix=/buckets/canonical-trial-ledger/ -fsync=true -volumeGrowthCount=1 -apply\n")
        self.assertNotIn("ttl", fsync_command("canonical-trial-ledger").lower())

    def test_storage_is_pinned_nonprivileged_and_has_no_runtime_api_token(self):
        fixture = TrialFixture(self.task)
        resources = storage_manifests(fixture.namespaces, "trial-storage")
        deployment = next(item for item in resources if item["kind"] == "Deployment")
        pod = deployment["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertFalse(pod["enableServiceLinks"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(len(pod["containers"]), 3)
        for container in pod["containers"]:
            self.assertEqual(container["image"], SEAWEED_IMAGE)
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        primary = pod["containers"][1]
        self.assertIn("-cert.file=/tls/storage.crt", primary["args"])
        self.assertIn("-autoCreateBucket=false", primary["args"])

    def test_upstream_network_peer_requires_both_gateway_namespace_and_role(self):
        fixture = TrialFixture(self.task)
        rules = network_policies(fixture.namespaces)
        upstream = next(item for item in rules if item["metadata"]["name"] == "upstream-s3")
        peers = upstream["spec"]["ingress"][0]["from"]
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], fixture.namespaces["gateway"])
        self.assertEqual(peers[0]["podSelector"]["matchLabels"][LABEL], "journal-gateway")

    def cleanup_client(self):
        fixture = TrialFixture(self.task)
        for name in ("kubectl", "kubeconfig"):
            write_private(self.task / name, "public-unit-placeholder")
        cluster = Cluster(self.task)
        for index, name in enumerate(sorted(cluster.namespaces)):
            record = {"apiVersion": "v1", "kind": "Namespace", "name": name, "namespace": "", "uid": "public-unit-uid-" + str(index)}
            write_private(cluster.pins / (str(index) + ".json"), canonical(record))
        return cluster

    def test_cleanup_uid_replacement_and_missing_ack_never_delete(self):
        cluster = self.cleanup_client()
        deleted = []

        def kube(*args, data=None, **kwargs):
            from types import SimpleNamespace
            if args[0] == "get":
                return SimpleNamespace(stdout=json.dumps({"metadata": {"uid": "replacement"}}))
            deleted.append(args)

        with patch.object(cluster, "kube", side_effect=kube), self.assertRaises(RuntimeError):
            cluster.cleanup_namespaces(True, True)
        self.assertEqual(deleted, [])

    def test_cleanup_uses_server_uid_preconditions_and_does_not_claim_completion(self):
        cluster = self.cleanup_client()
        pins = cluster.namespace_pins()
        bodies = []

        def kube(*args, data=None, **kwargs):
            from types import SimpleNamespace
            if args[0] == "get":
                return SimpleNamespace(stdout=json.dumps({"metadata": {"uid": pins[args[2]]}}))
            self.assertEqual(args[0:2], ("delete", "--raw"))
            bodies.append((args[2], json.loads(data)))
            return SimpleNamespace(stdout="")

        with patch.object(cluster, "kube", side_effect=kube):
            with self.assertRaises(ValueError):
                cluster.cleanup_namespaces(True, False)
            self.assertEqual(bodies, [])
            result = cluster.cleanup_namespaces(True, True)
        self.assertFalse(result["completed"])
        self.assertEqual(len(bodies), len(pins))
        for path, body in bodies:
            self.assertEqual(body["preconditions"]["uid"], pins[path.rsplit("/", 1)[1]])

    def test_namespace_cleanup_refuses_to_leave_own_failclosed_webhook_active(self):
        cluster = self.cleanup_client()
        pin = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
               "name": "trial-webhook", "namespace": "", "uid": "public-webhook-uid", "guardHash": "1" * 64}
        write_private(cluster.pins / "webhook.json", canonical(pin))
        from types import SimpleNamespace
        with patch.object(cluster, "kube", return_value=SimpleNamespace(stdout="validatingwebhookconfiguration/trial-webhook")):
            with self.assertRaisesRegex(RuntimeError, "before namespaces"):
                cluster.cleanup_namespaces(True, True)

    def test_cluster_cleanup_never_deletes_replaced_or_structurally_changed_resource(self):
        cluster = self.cleanup_client()
        resource = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
                    "metadata": {"name": "trial-webhook", "uid": "public-webhook-uid"}, "webhooks": []}
        pin = {"apiVersion": resource["apiVersion"], "kind": resource["kind"], "name": "trial-webhook", "namespace": "",
               "uid": resource["metadata"]["uid"], "guardHash": cluster.guard_hash(resource)}
        write_private(cluster.pins / "webhook.json", canonical(pin))
        replaced = copy.deepcopy(resource)
        replaced["metadata"]["uid"] = "replacement"
        from types import SimpleNamespace
        with patch.object(cluster, "kube", return_value=SimpleNamespace(stdout=json.dumps(replaced))) as kube:
            with self.assertRaisesRegex(RuntimeError, "cleanup refused"):
                cluster.cleanup_cluster_resources("before-namespaces", True)
            self.assertEqual(kube.call_count, 1)


if __name__ == "__main__":
    unittest.main()
