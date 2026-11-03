import copy
from pathlib import Path
import sys
import unittest

sys.path.append(str(Path(__file__).resolve().parents[1] / 'stage6'))
from diagnostic_upgrade import OLD, NEW, review_diff


class ImageOnlyGuards(unittest.TestCase):
    def fixture(self):
        before = [{'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': 'owned'},
            'spec': {'template': {'spec': {'containers': [{'image': OLD, 'args': ['fixed'], 'resources': {'limits': {'memory': '160Mi'}}}]}}}}
            for name in ('stage6-operator', 'stage6-fencer')]
        before.append({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'fixed'}, 'data': {'config': 'pinned'}})
        after = copy.deepcopy(before)
        for v in after[:2]: v['spec']['template']['spec']['containers'][0]['image'] = NEW
        return before, after

    def test_exact_two_images(self): review_diff(*self.fixture())
    def test_config_rejected(self):
        a,b=self.fixture(); b[2]['data']['config']='other'
        with self.assertRaises(RuntimeError): review_diff(a,b)
    def test_resource_change_rejected(self):
        a,b=self.fixture(); b[0]['spec']['template']['spec']['containers'][0]['resources']['limits']['memory']='512Mi'
        with self.assertRaises(RuntimeError): review_diff(a,b)
    def test_missing_deployment_rejected(self):
        a,b=self.fixture(); a.pop(0); b.pop(0)
        with self.assertRaises(RuntimeError): review_diff(a,b)
    def test_duplicate_identity_rejected(self):
        a,b=self.fixture(); a.append(copy.deepcopy(a[0])); b.append(copy.deepcopy(b[0]))
        with self.assertRaises(RuntimeError): review_diff(a,b)


if __name__ == '__main__': unittest.main()
