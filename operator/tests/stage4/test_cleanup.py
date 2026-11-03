"""Safety checks for server-enforced deletion identity and creation-time pins."""

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cleanup_cluster
import infrastructure


class CleanupTests(unittest.TestCase):
    def test_failed_forward_constructor_closes_started_process(self):
        with patch.object(cleanup_cluster.common.subprocess, "Popen"), \
             patch.object(cleanup_cluster.common, "wait", side_effect=RuntimeError("forward did not start")), \
             patch.object(cleanup_cluster.common.Forward, "close") as close:
            with self.assertRaisesRegex(RuntimeError, "forward did not start"):
                cleanup_cluster.common.Forward(Path("/isolated"), "isolated", "pod/canary", 8080)
        close.assert_called_once()

    def test_delete_sends_uid_precondition_to_api(self):
        with patch.object(cleanup_cluster.common, "kube") as request:
            cleanup_cluster.delete_uid("/api/v1/namespaces/isolated", "original-uid")
        args, kwargs = request.call_args
        self.assertEqual(args, ("delete", "--raw", "/api/v1/namespaces/isolated", "-f", "-"))
        self.assertEqual(json.loads(kwargs["value"]), {
            "apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": "original-uid"},
            "propagationPolicy": "Background",
        })

    def test_server_uid_conflict_is_not_retried_by_name(self):
        with patch.object(cleanup_cluster.common, "kube", side_effect=RuntimeError("UID conflict")) as request:
            with self.assertRaisesRegex(RuntimeError, "UID conflict"):
                cleanup_cluster.delete_uid("/api/v1/namespaces/isolated", "original-uid")
        self.assertEqual(request.call_count, 1)

    def test_namespace_uids_are_from_create_responses(self):
        created = []

        def create(resource):
            created.append(resource)
            return {"metadata": {"uid": "creation-" + resource["metadata"]["name"]}}

        with patch.object(infrastructure, "create", side_effect=create), \
             patch.object(infrastructure.common, "DRIVER", "k0s"), \
             patch.object(infrastructure.common, "kube", return_value=SimpleNamespace(stdout="")):
            identities = infrastructure.prepare_namespaces()
        self.assertEqual(identities, {resource["metadata"]["name"]: "creation-" + resource["metadata"]["name"]
                                      for resource in created if resource["kind"] == "Namespace"})
        self.assertEqual(len(identities), 4)

    def test_legacy_run_without_creation_uid_pins_refuses_before_api(self):
        metadata = {"store_uid": "original-store"}
        with patch.object(cleanup_cluster.Authority, "safe_task", return_value=Path("/opt/sekvyr-trial/sekvyr-stage4-20260101-abcdef01")), \
             patch.object(cleanup_cluster.common, "configure"), \
             patch.object(Path, "read_text", return_value=json.dumps(metadata)), \
             patch.object(cleanup_cluster.common, "kube") as request, \
             patch("sys.argv", ["cleanup_cluster.py", "--task-dir", "unused", "--chart-path", "unused",
                                "--store-crd-uid", "store-original", "--secret-crd-uid", "secret-original", "--execute"]):
            with self.assertRaisesRegex(RuntimeError, "Creation-time namespace UID pins are missing"):
                cleanup_cluster.main()
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
