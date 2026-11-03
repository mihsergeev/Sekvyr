"""Trial fixture boundaries, independent of real service conformance results."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import TrialFixture
from protocol import ProtocolAuthority
from witness import config, prepare_files
from manifests import LABEL, cilium_trial_policies, product_network_policies


class WitnessGuards(unittest.TestCase):
    def test_new_tls_fixtures_identify_issuer_and_cover_both_admission_dns_forms(self):
        from cryptography import x509
        with tempfile.TemporaryDirectory(prefix="sekvyr-stage6.") as directory:
            task = Path(directory).resolve()
            fixture = TrialFixture(task)
            prepare_files(task, fixture.namespaces)
            ca = x509.load_pem_x509_certificate((task / "private" / "journal-ca.crt").read_bytes())
            leaf = x509.load_pem_x509_certificate((task / "private" / "fencer-server.crt").read_bytes())
            self.assertEqual(leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,
                ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
            names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            short = "stage6-fencer." + fixture.namespaces["apps"] + ".svc"
            self.assertIn(short, names)
            self.assertIn(short + ".cluster.local", names)

    def test_cilium_adapter_is_namespaced_and_never_opens_world_or_cluster(self):
        policies = cilium_trial_policies({"apps": "trial-installation"})
        self.assertEqual({p["metadata"]["namespace"] for p in policies}, {"trial-installation"})
        self.assertEqual({p["kind"] for p in policies}, {"CiliumNetworkPolicy"})
        api = next(p for p in policies if p["metadata"]["name"] == "trial-kube-api")
        self.assertEqual(api["spec"]["egress"][0]["toEntities"], ["kube-apiserver"])
        for policy in policies:
            raw = json.dumps(policy)
            for forbidden in ('"world"', '"all"', '"cluster"', '"remote-node"', '"endpointSelector": {}'):
                self.assertNotIn(forbidden, raw)

    def test_runtime_registration_excludes_permanently_poisoned_diagnostics(self):
        with tempfile.TemporaryDirectory(prefix="sekvyr-stage6.") as directory:
            task = Path(directory).resolve()
            fixture = TrialFixture(task)
            protocol = ProtocolAuthority(task)
            cfg = config(protocol, fixture.namespaces, "witness-a")
            logs = {entry["journal"]["log_id"] for entry in cfg["registrations"]}
            self.assertEqual(logs, {protocol.scope["log_id"],
                protocol.fault_logs["replica-cas"]["registration"]["log_id"]})
            for label in ("duplicate-version", "delete-marker"):
                self.assertNotIn(protocol.fault_logs[label]["registration"]["log_id"], logs)
            panel = next(client for client in cfg["clients"] if client["common_name"] == "isolated-trial-panel")
            self.assertEqual(panel["write_kinds"], [])
            self.assertEqual(cfg["signing_key_files"], ["/files/witness.key"])

    def test_repeated_material_prepare_preserves_shared_fetch_credential(self):
        with tempfile.TemporaryDirectory(prefix="sekvyr-stage6.") as directory:
            task = Path(directory).resolve()
            fixture = TrialFixture(task)
            prepare_files(task, fixture.namespaces)
            before = (task / "private" / "fetch-token").read_bytes()
            prepare_files(task, fixture.namespaces)
            self.assertEqual(before, (task / "private" / "fetch-token").read_bytes())

    def test_actual_apps_fencer_has_gateway_route_and_no_native_s3_route(self):
        namespaces = {role: "trial-" + role for role in ("apps", "gateway", "witness", "panel")}
        policies = product_network_policies(namespaces, ["192.0.2.10"], ["192.0.2.11"])
        fencer = next(p for p in policies if p["metadata"]["name"] == "fencer-exact-paths")
        self.assertEqual(fencer["metadata"]["namespace"], "trial-apps")
        self.assertEqual(fencer["spec"]["podSelector"]["matchLabels"][LABEL], "fencer")
        self.assertNotIn("8333", json.dumps(policies))
        self.assertNotIn("0.0.0.0/0", json.dumps(policies))
        with self.assertRaises(ValueError):
            product_network_policies(namespaces, [], ["192.0.2.11"])


if __name__ == "__main__":
    unittest.main()
