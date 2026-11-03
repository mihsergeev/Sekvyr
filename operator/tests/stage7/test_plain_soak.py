import copy
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import plain_soak


class PlainSoakTests(unittest.TestCase):
    def fixture(self):
        self.failed, self.calls = False, []
        self.target = {"metadata": {"name": "target", "uid": "owned-target", "annotations": {"secrets.sekvyr.ru/revision": "opaque"}}, "data": {"value": "private-fixture"}}
        @contextmanager
        def sealed():
            self.failed = True
            try:
                yield
            finally:
                self.failed = False
        def current(**kwargs):
            if self.failed:
                raise AssertionError("Current proof requested while source unavailable")
            return True
        def target_ref(*args, **kwargs):
            current()
            return {"name": "target", "uid": "owned-target"}
        provider = SimpleNamespace(sealed=sealed, revoke=lambda: setattr(self, "failed", True), restore=lambda: setattr(self, "failed", False))
        p = SimpleNamespace(cr_name="secret", current=current, target_ref=target_ref)
        p.owned = SimpleNamespace(get=lambda *args: {"metadata": {"generation": 1}, "status": {"lastSuccessfulSyncTime": "previous", "conditions": [{"type": "DataCurrent", "status": "False" if self.failed else "True", "observedGeneration": 1}]}})
        apps = SimpleNamespace(capture=lambda name: {"baseline": name}, target=lambda ref: copy.deepcopy(self.target), frozen=lambda name, before, seconds: self.calls.append(name))
        return SimpleNamespace(installation=p, apps=apps, env_name="env", volume_name="volume", agent_name="agent", provider=provider,
            agent_provider=object(), token=lambda: None, poke=lambda: None, selected={"generation": "generation", "demo": "demo"}, proof=lambda label, facts: facts)

    def execute(self, cases, mutate=False):
        def token_run(panel, reader, healthy, faults, **kwargs):
            self.assertIs(panel, cases.agent_provider)
            self.assertEqual([name for name, _ in faults], ["sealed", "revoked", "sealed", "revoked"])
            self.assertEqual(kwargs, {"duration": 600, "interval": 5, "operation_id": "plain-real"})
            self.assertTrue(healthy())
            for _, factory in faults:
                with factory():
                    self.assertTrue(self.failed)
                self.assertFalse(self.failed)
                self.assertTrue(healthy())
            if mutate:
                self.target["data"]["value"] = "changed"
                healthy()
            return {"realMonotonicClock": True}
        with patch.object(plain_soak, "token_run", token_run), patch.object(plain_soak, "wait", lambda callback, timeout: self.assertTrue(callback())):
            return plain_soak.run(cases)

    def test_faults_use_last_good_target_without_claiming_current(self):
        result = self.execute(self.fixture())
        self.assertTrue(result["projectedReaderUsesSeparateAgentIdentity"])
        self.assertEqual(set(self.calls), {"env", "volume", "agent"})

    def test_target_mutation_fails_frozen_proof(self):
        with self.assertRaises(RuntimeError):
            self.execute(self.fixture(), mutate=True)


if __name__ == "__main__":
    unittest.main()
