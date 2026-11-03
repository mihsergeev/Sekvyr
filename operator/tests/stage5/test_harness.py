"""Check env-only test app semantics and independent template-diff assertions."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HarnessTests(unittest.TestCase):
    def test_app_captures_environment_once_without_exposing_demo(self):
        value = "public-test-only-not-a-secret-\u2603"
        with patch.dict(os.environ, {"GENERATION": "initial", "DEMO_VALUE": value}):
            app = load("stage5_env_app_test", HERE / "app.py")
            os.environ["GENERATION"] = "changed-after-start"
            os.environ["DEMO_VALUE"] = "different-public-test-value"
            self.assertEqual(app.STATUS["generation"], "initial")
            self.assertEqual(app.STATUS["value_digest"], hashlib.sha256(value.encode()).hexdigest())
            self.assertNotIn(value, json.dumps(app.STATUS, ensure_ascii=False))
            self.assertNotIn("DEMO_VALUE", app.STATUS)

    def setUp(self):
        self.runner = load("stage5_runner_unit_test", HERE / "run.py")
        self.annotation = "secrets.sekvyr.ru/restart-public-test-uid"
        self.before = {"template": {"metadata": {"annotations": {"other-owner": "keep"}},
                                    "spec": {"containers": [{"name": "app", "image": "example/image@sha256:" + "1" * 64}]}}}

    def test_only_owned_restart_annotation_is_an_allowed_template_delta(self):
        after = copy.deepcopy(self.before)
        after["template"]["metadata"]["annotations"][self.annotation] = "1" * 32
        self.runner.assert_only_restart_annotation_changed(self.before, after, self.annotation)

    def test_test_deployment_explicitly_opts_out_of_external_secret_reloaders(self):
        with patch.object(self.runner.infrastructure, "config_map"), \
             patch.object(self.runner.infrastructure, "deployment") as create:
            self.runner.create_app("example/python@sha256:" + "1" * 64)
        self.assertEqual(create.call_args.kwargs["annotations"], {
            "reloader.stakater.com/auto": "false", "secret.reloader.stakater.com/auto": "false",
            "configmap.reloader.stakater.com/auto": "false",
        })

    def test_other_owners_annotation_cannot_be_changed(self):
        after = copy.deepcopy(self.before)
        after["template"]["metadata"]["annotations"]["other-owner"] = "changed"
        with self.assertRaises(AssertionError):
            self.runner.assert_only_restart_annotation_changed(self.before, after, self.annotation)

    def test_image_or_secret_reference_delta_is_not_hidden_by_restart_assertion(self):
        for field, changed in (("image", "example/different:public-test"), ("envFrom", [{"secretRef": {"name": "different"}}])):
            with self.subTest(field=field):
                after = copy.deepcopy(self.before)
                after["template"]["spec"]["containers"][0][field] = changed
                with self.assertRaises(AssertionError):
                    self.runner.assert_only_restart_annotation_changed(self.before, after, self.annotation)

    def test_two_creation_uid_checkpoints_never_overwrite_exclusive_private_file(self):
        with tempfile.TemporaryDirectory(prefix="sekvyr-public-test-") as directory:
            task = Path(directory)
            (task / "private").mkdir(mode=0o700)
            identities = {}
            for name, uid in (("sekvyrstores.secrets.sekvyr.ru", "public-store-uid"),
                               ("sekvyrsecrets.secrets.sekvyr.ru", "public-secret-uid")):
                self.runner.base.record_created_crd(task, identities, {"metadata": {"name": name, "uid": uid}})
            self.runner.base.private_json(task, "crd-uids.json", identities)
            self.assertEqual(json.loads((task / "private" / "crd-uids.json").read_text()), identities)
            self.assertEqual(len(list((task / "private").glob("crd-uid-*.json"))), 2)
            with self.assertRaisesRegex(RuntimeError, "repeated"):
                self.runner.base.record_created_crd(task, identities, {
                    "metadata": {"name": "sekvyrstores.secrets.sekvyr.ru", "uid": "replacement-public-uid"}})


if __name__ == "__main__":
    unittest.main()
