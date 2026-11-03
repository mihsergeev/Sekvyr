"""Process-fault guards; these are not live split-brain acceptance evidence."""

import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from process_control import CONTROL, ProcessControl


class ProcessCluster:
    def __init__(self, directory):
        self.task = Path(directory)
        self.pins = self.task / 'pins'
        self.pins.mkdir()
        self.fixture = {'namespaces': {'apps': 'trial-apps'}}
        self.namespace_uid = str(uuid.uuid4())
        self.calls, self.exec_result = [], SimpleNamespace(stdout='ProcessRunningAlive\n', returncode=0)
        self.resources = {}
        for kind, name in (('Deployment', 'stage6-operator'), ('ServiceAccount', 'sekvyr-operator'),
                           ('ReplicaSet', 'stage6-operator-rs'), ('Pod', 'stage6-operator-pod')):
            meta = {'name': name, 'namespace': 'trial-apps', 'uid': str(uuid.uuid4()), 'resourceVersion': '11'}
            self.resources[(kind, name)] = {'apiVersion': 'v1', 'kind': kind, 'metadata': meta}
        target = {'name': 'operator', 'image': 'example/operator@sha256:' + 'a' * 64,
            'args': ['--installation-file=/etc/trial/installation.json']}
        spec = {'serviceAccountName': 'sekvyr-operator', 'securityContext': {'runAsUser': 65532},
            'containers': [target]}
        deployment = self.resources[('Deployment', 'stage6-operator')]
        deployment['spec'] = {'template': {'spec': copy.deepcopy(spec)}}
        replica_set = self.resources[('ReplicaSet', 'stage6-operator-rs')]
        replica_set['metadata']['ownerReferences'] = [self.owner(deployment)]
        pod = self.resources[('Pod', 'stage6-operator-pod')]
        pod['metadata']['ownerReferences'] = [self.owner(replica_set)]
        pod['spec'] = spec
        pod['status'] = {'containerStatuses': [{'name': 'operator', 'containerID': 'containerd://trial-operator',
            'state': {'running': {'startedAt': '2026-01-01T00:00:00Z'}}}]}
        for kind, name in (('Deployment', 'stage6-operator'), ('ServiceAccount', 'sekvyr-operator')):
            resource = self.resources[(kind, name)]
            (self.pins / (kind + '.json')).write_text(json.dumps({'kind': kind, 'name': name,
                'namespace': 'trial-apps', 'uid': resource['metadata']['uid']}))

    @staticmethod
    def owner(value):
        return {'apiVersion': 'apps/v1', 'kind': value['kind'], 'name': value['metadata']['name'],
            'uid': value['metadata']['uid'], 'controller': True}

    @property
    def pod(self):
        return self.resources[('Pod', 'stage6-operator-pod')]

    def namespace_pins(self):
        return {'trial-apps': self.namespace_uid}

    def kube(self, *args, data=None, check=True):
        self.calls.append((args, data))
        if args[:2] == ('get', 'namespace'):
            result = {'metadata': {'uid': self.namespace_uid}}
        elif args[0] == 'get':
            result = self.resources[(args[1], args[2])]
        elif args[:2] == ('replace', '--raw'):
            proposed = json.loads(data)
            self.pod['spec']['ephemeralContainers'] = proposed['spec']['ephemeralContainers']
            self.pod['status']['ephemeralContainerStatuses'] = [{'name': self.pod['spec']['ephemeralContainers'][-1]['name'],
                'state': {'running': {'startedAt': '2026-01-01T00:00:00Z'}}}]
            result = self.pod
        elif args[0] == 'exec':
            return self.exec_result
        else:
            raise AssertionError('Unexpected process test command')
        return SimpleNamespace(stdout=json.dumps(copy.deepcopy(result)), returncode=0)


class ProcessGuards(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.cluster = ProcessCluster(directory.name)
        self.image = 'example/python@sha256:' + 'b' * 64

    def control(self):
        return ProcessControl(self.cluster, copy.deepcopy(self.cluster.pod), self.image)

    def mutations(self):
        return [v for v in self.cluster.calls if v[0][0] in ('replace', 'exec')]

    def test_foreign_owner_account_or_host_namespace_rejected_before_mutation(self):
        for mode in ('owner', 'account', 'host'):
            with self.subTest(mode=mode):
                before = copy.deepcopy(self.cluster.pod)
                if mode == 'owner':
                    self.cluster.resources[('ReplicaSet', 'stage6-operator-rs')]['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                elif mode == 'account':
                    self.cluster.pod['spec']['serviceAccountName'] = 'foreign'
                else:
                    self.cluster.pod['spec']['hostPID'] = True
                with self.assertRaises(RuntimeError):
                    self.control()
                self.assertFalse(self.mutations())
                self.cluster.resources[('Pod', 'stage6-operator-pod')] = before
                deployment = self.cluster.resources[('Deployment', 'stage6-operator')]
                self.cluster.resources[('ReplicaSet', 'stage6-operator-rs')]['metadata']['ownerReferences'] = [self.cluster.owner(deployment)]

    def test_replaced_pod_and_container_are_never_adopted(self):
        control = self.control()
        for mode in ('pod', 'container', 'namespace'):
            before = copy.deepcopy(self.cluster.pod)
            if mode == 'pod':
                self.cluster.pod['metadata']['uid'] = str(uuid.uuid4())
            elif mode == 'container':
                self.cluster.pod['status']['containerStatuses'][0]['containerID'] = 'containerd://replacement'
            else:
                self.cluster.namespace_uid = str(uuid.uuid4())
            with self.assertRaises(RuntimeError):
                control.prepare()
            self.assertFalse(self.mutations())
            self.cluster.resources[('Pod', 'stage6-operator-pod')] = before

    def test_helper_uses_exact_uid_rv_only_target_namespace_no_credentials_or_caps(self):
        control = self.control().prepare()
        command, raw = next(v for v in self.cluster.calls if v[0][0] == 'replace')
        proposed = json.loads(raw)
        self.assertEqual(command[2], '/api/v1/namespaces/trial-apps/pods/stage6-operator-pod/ephemeralcontainers')
        self.assertEqual(proposed['metadata']['uid'], control.uid)
        self.assertEqual(proposed['metadata']['resourceVersion'], '11')
        helper = proposed['spec']['ephemeralContainers'][0]
        self.assertEqual(helper['targetContainerName'], 'operator')
        self.assertEqual(helper['image'], self.image)
        self.assertEqual(helper['securityContext']['capabilities'], {'drop': ['ALL']})
        self.assertEqual(helper['securityContext']['runAsUser'], 65532)
        self.assertFalse(helper['securityContext']['allowPrivilegeEscalation'])
        self.assertNotIn('env', helper)
        self.assertNotIn('volumeMounts', helper)
        with self.assertRaises(RuntimeError):
            control.prepare()
        self.assertEqual(sum(v[0][0] == 'replace' for v in self.cluster.calls), 1)

    def test_signal_is_fixed_and_unacknowledged_commands_fail(self):
        control = self.control().prepare()
        for invalid in ('KILL', 'STOP', 'CONT', 'STOP; kill -1', 9):
            with self.assertRaises(RuntimeError):
                control.signal(invalid)
        self.cluster.exec_result = SimpleNamespace(stdout='SignalAccepted\n', returncode=1)
        with self.assertRaises(RuntimeError):
            control.signal('TERM')
        self.cluster.exec_result = SimpleNamespace(stdout='SignalAccepted\n', returncode=0)
        control.signal('TERM')
        self.assertEqual(self.cluster.calls[-1][0][-2], 'TERM')
        self.cluster.exec_result = SimpleNamespace(stdout='ProcessStoppedAlive\n', returncode=0)
        self.assertTrue(control.stopped_alive())

    def test_bad_image_or_command_never_creates_helper(self):
        with self.assertRaises(RuntimeError):
            ProcessControl(self.cluster, self.cluster.pod, 'example/python:latest')
        self.cluster.pod['spec']['containers'][0]['args'] = ['--unexpected=true']
        with self.assertRaises(RuntimeError):
            self.control()
        self.assertFalse(self.mutations())


class ProcessScriptGuards(unittest.TestCase):
    def execute(self, operation='TERM', command=None, uid='65532', state='S (sleeping)', namespace='pid:[trial]'):
        expected = ['/sekvyr-operator', '--example=true']
        raw = b'\0'.join(s.encode() for s in (command or expected)) + b'\0'
        def source(path, mode='r'):
            return io.BytesIO(raw) if path == '/proc/1/cmdline' else io.StringIO('Uid:\t' + '\t'.join([uid] * 4) + '\nState:\t' + state + '\n')
        kill, output = Mock(), io.StringIO()
        with patch('builtins.open', source), patch('os.geteuid', return_value=65532, create=True), patch('os.kill', kill), \
             patch.multiple('signal', SIGSTOP=19, SIGCONT=18, create=True), \
             patch('os.readlink', side_effect=lambda p: 'pid:[trial]' if p == '/proc/1/ns/pid' else namespace), \
             patch('sys.argv', ['control', operation, json.dumps(expected)]), patch('sys.stdout', output):
            try:
                exec(CONTROL, {})
            except SystemExit as error:
                return kill, output.getvalue(), str(error)
        return kill, output.getvalue(), None

    def test_script_signals_only_pid_one_after_exact_argv_uid_namespace(self):
        kill, output, error = self.execute()
        self.assertIsNone(error)
        self.assertEqual(output.strip(), 'SignalAccepted')
        self.assertEqual([v.args[0] for v in kill.call_args_list], [1, 1])
        for options in ({'command': ['/other']}, {'command': ['/sekvyr-operator', '--wrong']},
                        {'command': ['/sekvyr-operator', '--example=true', '']},
                        {'uid': '0'}, {'namespace': 'pid:[foreign]'}, {'operation': 'KILL'}, {'operation': 'STOP'}, {'operation': 'CONT'}):
            with self.subTest(options=options):
                kill, output, error = self.execute(**options)
                self.assertIsNotNone(error)
                kill.assert_not_called()
                self.assertEqual(output, '')

    def test_stopped_proof_checks_liveness_without_sending_signal(self):
        for state, expected in (('T (stopped)', 'ProcessStoppedAlive'), ('S (sleeping)', 'ProcessRunningAlive')):
            kill, output, error = self.execute(operation='STOPPED', state=state)
            self.assertIsNone(error)
            self.assertEqual(output.strip(), expected)
            kill.assert_called_once_with(1, 0)


if __name__ == '__main__':
    unittest.main()
