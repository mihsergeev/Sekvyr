"""Verify the boundaries of the Stage 8 entry runner without live resources."""

import copy
import io
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stage8 import entry
from stage8.provision_adapter import ProvisionError


class EntryTests(unittest.TestCase):
    def test_schema_is_read_at_plain_relative_path_and_change_blocks_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            root = task / "private" / entry.ENTRY
            chart = root / "charts" / entry.CHART
            chart.mkdir(parents=True)
            chart_file = chart / "Chart.yaml"
            chart_file.write_bytes(b"fixture-chart")
            schema = chart.parents[1] / "design" / "resource.schema.json"
            schema.parent.mkdir()
            schema.write_bytes(b"{}")
            render = b"[]"
            (root / "ha-render.json").write_bytes(render)
            archive = b"fixture-archive"
            (root / "chart.tgz").write_bytes(archive)
            endpoints = {"apiEndpoints": [], "admissionSources": []}
            (root / "endpoints.json").write_bytes(entry.canonical(endpoints))
            actor = Mock()
            with patch.multiple(entry, owned_capability=Mock(return_value=SimpleNamespace(task=task)),
                    owned_file=lambda path, maximum: path.read_bytes(),
                    _chart_files=Mock(return_value={entry.CHART + "/Chart.yaml": chart_file.read_bytes()}),
                    _endpoints=Mock(return_value=endpoints), _helm=Mock(), BudgetCluster=Mock(), run_actor=actor):
                arguments = dict(profile="fixture", chart_sha256=entry.digest(archive),
                    resource_schema_sha256=entry.digest(b"{}"), reviewed_ha_sha256=entry.digest(render))
                entry.run(task, **arguments)
                self.assertEqual(actor.call_args.kwargs["chart"], chart)
                actor.reset_mock()
                schema.write_bytes(b'{"changed":true}')
                with self.assertRaises(ProvisionError):
                    entry.run(task, **arguments)
                actor.assert_not_called()

    def test_chart_archive_rejects_traversal_and_links(self):
        for name, kind in (("sekvyr-operator/../Chart.yaml", tarfile.REGTYPE),
                           ("sekvyr-operator/templates/deployment.yaml", tarfile.SYMTYPE)):
            with self.subTest(name=name, kind=kind):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode="w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    if kind == tarfile.SYMTYPE:
                        member.linkname = "/fixture-outside"
                    archive.addfile(member)
                with self.assertRaises(ProvisionError):
                    entry._chart_files(raw.getvalue())

    def test_api_endpoints_must_agree_with_exact_kind_static_pod(self):
        name = "fixture-control-plane"
        ip = "192.0.2.6"
        ready = {"type": "Ready", "status": "True"}
        values = [
            {"items": [{"metadata": {"name": name}, "status": {
                "addresses": [{"type": "InternalIP", "address": ip}], "conditions": [ready]}}]},
            {"metadata": {"annotations": {"kubernetes.io/config.source": "file"}},
             "spec": {"nodeName": name, "hostNetwork": True},
             "status": {"podIP": ip, "hostIP": ip, "conditions": [ready]}},
            {"metadata": {}, "spec": {"type": "ClusterIP", "clusterIP": "192.0.2.9",
                "clusterIPs": ["192.0.2.9"], "ports": [{"protocol": "TCP", "port": 443, "targetPort": 6443}]}},
            {"items": [{"metadata": {}, "ports": [{"protocol": "TCP", "port": 6443}],
                "endpoints": [{"addresses": [ip], "conditions": {"ready": True}}]}]},
        ]
        owner = SimpleNamespace(guard=Mock(), preflight={"clusterName": "fixture"})
        with patch.object(entry, "_object", side_effect=values):
            self.assertEqual(entry._endpoints(owner, object()), {
                "apiEndpoints": [[ip, 6443], ["192.0.2.9", 443]],
                "admissionSources": [[ip, 9443]],
            })
        self.assertEqual(owner.guard.call_count, 2)
        changed = copy.deepcopy(values)
        changed[-1]["items"][0]["endpoints"][0]["addresses"] = ["192.0.2.7"]
        with patch.object(entry, "_object", side_effect=changed), self.assertRaises(ProvisionError):
            entry._endpoints(owner, object())
