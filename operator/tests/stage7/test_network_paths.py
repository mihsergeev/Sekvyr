"""Bidirectional policy/identity guards. No packet-enforcement claim."""

import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
from manifests import network_policies, peer
from fixture import canonical
import network_paths as paths


def deployment(namespace, release, role, ha=True):
    labels = {paths.NAME: "sekvyr-" + role, paths.INSTANCE: release}
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"namespace": namespace, "name": release + "-" + role},
        "spec": {"selector": {"matchLabels": labels}, "template": {"metadata": {"labels": dict(labels, **({paths.ROLE: role} if ha else {}))}}}}


class NetworkGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        task = Path(self.temp.name)
        (task / "private").mkdir()
        self.ns = {role: "synthetic-" + role for role in paths.ROLES}
        fixture = {"format": "sekvyr-stage7-fixture-v1", "namespaces": self.ns, "production": False}
        (task / "private" / "fixture.json").write_bytes(canonical(fixture))
        self.uids = {namespace: "created-" + namespace for namespace in self.ns.values()}
        self.objects = {}
        for value in network_policies(dict(self.ns, fencer=self.ns["apps"])):
            meta = value["metadata"]
            meta["uid"] = "created-" + meta["namespace"] + "-" + meta["name"]
            self.objects[meta["namespace"], meta["name"]] = value
        # The shared component's actual existing witness policy.
        witness = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {
            "namespace": self.ns["witness"], "name": "witness-canonical", "uid": "created-witness-policy"},
            "spec": {"podSelector": {"matchLabels": {paths.ROLE: "witness"}}, "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"from": [peer(self.ns["apps"], role) for role in ("operator", "fencer")]
                    + [peer(self.ns["panel"], "panel")], "ports": [{"protocol": "TCP", "port": 8443}]}],
                "egress": [{"to": [peer(self.ns["panel"], "panel")], "ports": [{"protocol": "TCP", "port": 8443}]}]}}
        self.objects[self.ns["witness"], "witness-canonical"] = witness
        self.created = []
        self.replace_namespace = None
        self.cluster = SimpleNamespace(task=task, fixture=copy.deepcopy(fixture), namespaces=set(self.ns.values()),
            namespace_pins=lambda: copy.deepcopy(self.uids), kube=self.kube, create=self.create)
        self.plain = deployment(self.ns["isolation"], "stage7-plain", "operator", False)
        self.lifecycle = SimpleNamespace(cluster=self.cluster, namespace=self.ns["isolation"], release="stage7-plain",
            managed={"plain": {"manifest": self.plain, "uid": "plain-created-uid"}},
            _external_guard=Mock(), _retained_guard=Mock(), _get=Mock(return_value={"current": True}),
            _owned=Mock(), _matches=Mock())
        self.cases = SimpleNamespace(c=SimpleNamespace(cluster=self.cluster), agent_name="legacy-agent-app",
            installation=SimpleNamespace(namespace=self.ns["isolation"], release="stage7-plain", lifecycle=self.lifecycle))
        self.render = [deployment(self.ns["apps"], "stage6", role) for role in ("operator", "fencer")]
        self.args = {"ha_rendered": self.render, "reviewed_ha_sha256": paths._sha(self.render),
            "api_endpoints": [("192.0.2.10", 443), ("2001:db8::1", 6443)], "admission_sources": [("192.0.2.11", 9443)]}

    def kube(self, *args):
        if args[:2] == ("get", "namespace"):
            ns = args[2]
            value = {"kind": "Namespace", "metadata": {"name": ns, "uid": self.replace_namespace or self.uids[ns]}}
        elif args[:2] == ("get", "networkpolicies"):
            ns = args[args.index("-n") + 1]
            value = {"items": [copy.deepcopy(item) for (namespace, _), item in self.objects.items() if namespace == ns]}
        elif args[:2] == ("get", "networkpolicy"):
            value = self.objects[args[args.index("-n") + 1], args[2]]
        else:
            raise AssertionError("Unexpected source-test API operation")
        return SimpleNamespace(stdout=json.dumps(value))

    def create(self, value):
        key = value["metadata"]["namespace"], value["metadata"]["name"]
        self.assertNotIn(key, self.objects)
        self.created.append(copy.deepcopy(value))
        result = copy.deepcopy(value)
        result["metadata"]["uid"] = "new-created-" + str(len(self.created))
        self.objects[key] = result
        return result

    def run_install(self):
        return paths.install(self.cases, **self.args)

    def test_exact_bidirectional_paths_and_no_s3_or_default_deny_mutation(self):
        before = copy.deepcopy(self.objects)
        result = self.run_install()
        self.assertEqual(result["createdPolicies"], 7)
        self.assertFalse(result["packetIsolationVerified"])
        for key, value in before.items():
            self.assertEqual(self.objects[key], value)
        byname = {item["metadata"]["name"].removeprefix(paths.PREFIX): item["spec"] for item in self.created}
        plain = byname["plain"]["podSelector"]["matchLabels"]
        self.assertEqual(plain, {paths.NAME: "sekvyr-operator", paths.INSTANCE: "stage7-plain"})
        agent = byname["agent"]["podSelector"]["matchLabels"]
        self.assertEqual(agent, {paths.ROLE: "agent", paths.APP: "legacy-agent-app"})
        expected = paths._peer(self.ns["isolation"], plain)
        self.assertIn(expected, byname["panel"]["ingress"][0]["from"])
        self.assertIn(paths._peer(self.ns["isolation"], agent), byname["panel"]["ingress"][0]["from"])
        self.assertEqual(byname["plain"]["egress"][-1]["to"], [paths._peer(self.ns["panel"], {paths.ROLE: "panel"})])
        self.assertEqual(byname["agent"]["egress"][0]["ports"], [{"protocol": "TCP", "port": 8443}])
        for value in self.created:
            self.assertNotEqual(value["metadata"]["namespace"], self.ns["storage"])
            for direction, peerkey in (("ingress", "from"), ("egress", "to")):
                for rule in value["spec"].get(direction, []):
                    self.assertEqual(set(rule), {peerkey, "ports"})
                    self.assertTrue(rule[peerkey] and rule["ports"])
                    for target in rule[peerkey]:
                        if "ipBlock" in target:
                            self.assertTrue(target["ipBlock"]["cidr"].endswith(("/32", "/128")))
                        else:
                            self.assertEqual(set(target), {"namespaceSelector", "podSelector"})
                            self.assertNotEqual(target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], self.ns["storage"])
                            self.assertTrue(target["podSelector"]["matchLabels"])
                    self.assertTrue(all(port["protocol"] == "TCP" and port["port"] in (443, 6443, 8443, 9443) for port in rule["ports"]))
        root = self.cluster.task / "private" / "stage7-network-paths"
        self.assertEqual(len(list(root.glob("*-created.json"))), 7)
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertEqual(len(self.created), 7)

    def test_foreign_reserved_namespace_mutation_rejected_before_any_write(self):
        self.cluster.fixture["namespaces"]["isolation"] = "foreign-namespace"
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertFalse(self.created)
        self.assertFalse((self.cluster.task / "private" / "stage7-network-paths").exists())

    def test_complete_independent_directional_path_matrix(self):
        self.run_install()
        labels = {"plain": {paths.NAME: "sekvyr-operator", paths.INSTANCE: "stage7-plain"},
            "agent": {paths.ROLE: "agent", paths.APP: "legacy-agent-app"},
            "operator": {paths.NAME: "sekvyr-operator", paths.INSTANCE: "stage6", paths.ROLE: "operator"},
            "fencer": {paths.NAME: "sekvyr-fencer", paths.INSTANCE: "stage6", paths.ROLE: "fencer"},
            "relay": {paths.ROLE: "admission-relay"}, "panel": {paths.ROLE: "panel"},
            "witness": {paths.ROLE: "witness"}, "journal": {paths.ROLE: "journal-gateway"}}
        roles = {"plain": "isolation", "agent": "isolation", "operator": "apps", "fencer": "apps",
            "relay": "apps", "panel": "panel", "witness": "witness", "journal": "gateway"}
        def identify(target):
            if "ipBlock" in target:
                return target["ipBlock"]["cidr"]
            namespace = target["namespaceSelector"]["matchLabels"]
            matches = [name for name, selector in labels.items() if target["podSelector"] == {"matchLabels": selector}
                and namespace == {"kubernetes.io/metadata.name": self.ns[roles[name]]}]
            self.assertEqual(len(matches), 1)
            return matches[0]
        actual = {}
        for value in self.created:
            name = value["metadata"]["name"].removeprefix(paths.PREFIX)
            self.assertEqual(value["spec"]["podSelector"], {"matchLabels": labels[name]})
            for direction, peerkey in (("ingress", "from"), ("egress", "to")):
                if direction in value["spec"]:
                    actual[name, direction] = {(identify(peer), port["port"]) for rule in value["spec"][direction]
                        for peer in rule[peerkey] for port in rule["ports"]}
        api = {("192.0.2.10/32", 443), ("2001:db8::1/128", 6443)}
        self.assertEqual(actual, {
            ("plain", "egress"): api | {("panel", 8443)},
            ("agent", "egress"): {("panel", 8443)},
            ("operator", "egress"): api | {("panel", 8443), ("witness", 8443), ("journal", 8443), ("fencer", 9443)},
            ("fencer", "egress"): api | {("journal", 8443)},
            ("fencer", "ingress"): {("192.0.2.11/32", 9443), ("operator", 9443), ("relay", 9443)},
            ("relay", "egress"): {("fencer", 9443)}, ("relay", "ingress"): {("192.0.2.11/32", 9443)},
            ("panel", "ingress"): {("plain", 8443), ("agent", 8443), ("operator", 8443), ("witness", 8443)},
            ("panel", "egress"): {("witness", 8443)},
            ("journal", "ingress"): {("operator", 8443), ("fencer", 8443)}})

    def test_namespace_replacement_rejected_before_create(self):
        self.replace_namespace = "foreign-uid"
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertFalse(self.created)

    def test_review_hash_and_foreign_ha_selector_rejected(self):
        self.render[0]["spec"]["template"]["metadata"]["labels"][paths.INSTANCE] = "foreign"
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.args["reviewed_ha_sha256"] = paths._sha(self.render)
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertFalse(self.created)

    def test_missing_or_broad_endpoint_lists_rejected_before_create(self):
        for bad in ([], [("0.0.0.0", 443)], [("192.0.2.0/24", 443)], [("192.0.2.10", 8333)], [("192.0.2.10", True)]):
            with self.subTest(bad=bad):
                self.args["api_endpoints"] = bad
                with self.assertRaises(RuntimeError):
                    self.run_install()
                self.assertFalse(self.created)

    def test_existing_policy_or_default_deny_changes_refused(self):
        self.objects[self.ns["isolation"], "default-deny"]["spec"]["egress"] = [{}]
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertFalse(self.created)

    def test_shared_witness_paths_must_match_exact_existing_source(self):
        self.objects[self.ns["witness"], "witness-canonical"]["spec"]["ingress"][0]["from"] = [{}]
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertFalse(self.created)

    def test_empty_deny_lists_omitted_by_api_are_still_deny(self):
        for (_, name), item in self.objects.items():
            if name == "default-deny":
                del item["spec"]["ingress"]
                del item["spec"]["egress"]
        self.assertTrue(self.run_install()["defaultDenyPreserved"])

    def test_changed_plain_capture_and_mid_create_namespace_race_fail_closed(self):
        self.lifecycle._matches.side_effect = RuntimeError("Captured template changed")
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertFalse(self.created)
        self.lifecycle._matches.side_effect = None
        create = self.cluster.create
        def once(value):
            answer = create(value)
            self.replace_namespace = "replacement-after-first-create"
            return answer
        self.cluster.create = once
        with self.assertRaises(RuntimeError):
            self.run_install()
        self.assertEqual(len(self.created), 1)
        self.assertTrue((self.cluster.task / "private" / "stage7-network-paths" / "0-created.json").exists())
        self.assertFalse((self.cluster.task / "private" / "stage7-network-paths" / "complete.json").exists())


if __name__ == "__main__":
    unittest.main()
