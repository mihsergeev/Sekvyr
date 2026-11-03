"""Host-runtime pause guard tests. No real runtime or process is manipulated."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import canonical
import runtime_control as runtime
from test_process_control import ProcessCluster


class RuntimeGuards(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.cluster = ProcessCluster(directory.name)
        (self.cluster.task / 'private').mkdir()
        self.cid, self.pid, self.start, self.state = 'c' * 64, 321, '100', 'RUNNING'
        self.cluster.pod['spec']['nodeName'] = 'trial-node'
        self.cluster.pod['status']['containerStatuses'][0]['containerID'] = 'containerd://' + self.cid
        self.labels = {'io.kubernetes.pod.uid': self.cluster.pod['metadata']['uid'],
            'io.kubernetes.pod.name': self.cluster.pod['metadata']['name'], 'io.kubernetes.pod.namespace': 'trial-apps',
            'io.kubernetes.container.name': 'operator'}
        self.image = self.cluster.pod['spec']['containers'][0]['image']
        self.cluster.pod['status']['containerStatuses'][0]['imageID'] = self.image
        self.argv = ['/sekvyr-operator'] + self.cluster.pod['spec']['containers'][0]['args']
        self.commands, self.children = [], []
        self.lose_pause_ack = False
        self.spawn_dead = False
        for target, value in (('runtime_control.socket.gethostname', Mock(return_value='trial-node')),
                              ('runtime_control.command', self.command), ('runtime_control.process_identity', self.process),
                              ('runtime_control.subprocess.Popen', self.spawn)):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def command(self, *args):
        self.commands.append(args)
        if args == ('containers', 'info', self.cid):
            return json.dumps({'ID': self.cid, 'Image': self.image, 'Labels': copy.deepcopy(self.labels)})
        if args == ('tasks', 'list'):
            return 'TASK PID STATUS\n' + self.cid + ' ' + str(self.pid) + ' ' + self.state + '\n'
        if args == ('tasks', 'pause', self.cid):
            self.state = 'PAUSED'
            if self.lose_pause_ack:
                raise RuntimeError('Lost exact pause acknowledgement')
            return ''
        if args == ('tasks', 'resume', self.cid):
            self.state = 'RUNNING'
            return ''
        raise AssertionError('Unexpected runtime test operation')

    def process(self, pid):
        self.assertEqual(pid, self.pid)
        return {'argv': b'\0'.join(v.encode() for v in self.argv) + b'\0', 'start': self.start}

    def spawn(self, args, **kwargs):
        self.assertEqual(args[-2], '--watchdog')
        self.assertTrue(kwargs['start_new_session'])
        self.assertTrue(kwargs['close_fds'])
        self.assertEqual(kwargs['stdout'], runtime.subprocess.DEVNULL)
        path = Path(args[-1])
        self.assertEqual(path.parent, self.cluster.task / 'private')
        child = Mock()
        if self.spawn_dead:
            child.poll.return_value = 1
        else:
            failures = []
            raw = path.read_bytes()
            def run():
                try:
                    runtime.drive_watchdog(path, json.loads(raw), raw)
                except Exception as error:
                    failures.append(type(error).__name__)
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            child.poll.side_effect = lambda: None if thread.is_alive() else (1 if failures else 0)
            def joined(timeout):
                thread.join(timeout)
                if thread.is_alive():
                    raise runtime.subprocess.TimeoutExpired('owned-watchdog-test', timeout)
                return 1 if failures else 0
            child.wait.side_effect = joined
        self.children.append(child)
        return child

    def control(self, **kwargs):
        return runtime.RuntimeTaskControl(self.cluster, copy.deepcopy(self.cluster.pod), 'trial-node', **kwargs)

    def mutations(self):
        return [v for v in self.commands if v[:2] in (('tasks', 'pause'), ('tasks', 'resume'))]

    def test_exact_runtime_pause_has_independent_watchdog_and_finally_resumes(self):
        control = self.control()
        with self.assertRaisesRegex(ValueError, 'Caller fault'):
            with control.paused():
                self.assertTrue(control.paused_alive())
                raise ValueError('Caller fault')
        self.assertEqual(self.state, 'RUNNING')
        self.assertEqual(self.mutations(), [('tasks', 'pause', self.cid), ('tasks', 'resume', self.cid)])
        self.children[0].terminate.assert_not_called()
        self.children[0].wait.assert_called_once_with(timeout=12)

    def test_no_foreign_runtime_labels_can_be_paused(self):
        for key in self.labels:
            before = copy.deepcopy(self.labels)
            self.labels[key] = 'foreign'
            with self.assertRaises(RuntimeError):
                self.control()
            self.assertFalse(self.mutations())
            self.labels = before

    def test_runtime_pid_start_argv_or_pod_replacement_rejected_before_pause(self):
        for field in ('pid', 'start', 'argv', 'pod', 'imageID'):
            with self.subTest(field=field):
                control = self.control()
                before = (self.pid, self.start, copy.deepcopy(self.argv), copy.deepcopy(self.cluster.pod))
                if field == 'pid':
                    self.pid += 1
                elif field == 'start':
                    self.start = '101'
                elif field == 'argv':
                    self.argv.append('')
                elif field == 'pod':
                    self.cluster.pod['metadata']['uid'] = 'replacement'
                else:
                    self.cluster.pod['status']['containerStatuses'][0]['imageID'] = 'example/operator@sha256:' + 'e' * 64
                with self.assertRaises(RuntimeError):
                    control.pause()
                self.assertFalse(self.mutations())
                self.pid, self.start, self.argv = before[:3]
                self.cluster.resources[('Pod', 'stage6-operator-pod')] = before[3]

    def test_lost_pause_ack_resumes_only_exact_task_before_reporting_failure(self):
        control = self.control()
        self.lose_pause_ack = True
        with self.assertRaises(RuntimeError):
            control.pause()
        self.assertEqual(self.state, 'RUNNING')
        self.assertEqual(self.mutations(), [('tasks', 'pause', self.cid), ('tasks', 'resume', self.cid)])

    def test_dead_watchdog_prevents_injection(self):
        control = self.control()
        self.spawn_dead = True
        with self.assertRaisesRegex(RuntimeError, 'watchdog exited'):
            control.pause()
        self.assertFalse(self.mutations())

    def test_watchdog_cannot_resume_reused_pid_or_changed_container_labels(self):
        control = self.control()
        plan = copy.deepcopy(control.plan)
        self.state = 'PAUSED'
        self.start = 'other-process'
        with self.assertRaises(RuntimeError):
            runtime.resume_exact(plan)
        self.assertFalse(self.mutations())
        self.start = '100'
        self.labels['io.kubernetes.pod.uid'] = 'replacement'
        with self.assertRaises(RuntimeError):
            runtime.resume_exact(plan)
        self.assertFalse(self.mutations())

    def test_no_adoption_of_paused_task_or_unbounded_pause(self):
        self.state = 'PAUSED'
        with self.assertRaises(RuntimeError):
            self.control()
        self.state = 'RUNNING'
        for seconds in (0, 26, True):
            with self.assertRaises(RuntimeError):
                self.control(max_pause_seconds=seconds)
        control = self.control().pause()
        with self.assertRaises(RuntimeError):
            control.pause()
        control.resume()
        self.assertEqual(sum(v[:2] == ('tasks', 'pause') for v in self.commands), 1)

    def test_other_node_or_floating_container_id_cannot_reach_runtime(self):
        self.cluster.pod['spec']['nodeName'] = 'other-node'
        with self.assertRaises(RuntimeError):
            self.control()
        self.cluster.pod['spec']['nodeName'] = 'trial-node'
        self.cluster.pod['status']['containerStatuses'][0]['containerID'] = 'containerd://short'
        with self.assertRaises(RuntimeError):
            self.control()
        self.assertFalse(self.commands)

    def test_expired_worker_cannot_receive_a_late_parent_pause(self):
        control = self.control()
        path = self.cluster.task / 'private' / 'expired.json'
        plan = copy.deepcopy(control.plan)
        plan.update(deadline=runtime.time.monotonic() - 1, maxPauseSeconds=1)
        raw = canonical(plan)
        runtime.drive_watchdog(path, plan, raw)
        path.with_suffix('.request').write_bytes(canonical({'planHash': hashlib.sha256(raw).hexdigest()}))
        self.assertFalse(self.mutations())
        self.assertEqual(self.state, 'RUNNING')

    def test_worker_resumes_without_parent_after_bounded_pause(self):
        control = self.control()
        path = self.cluster.task / 'private' / 'worker.json'
        plan = copy.deepcopy(control.plan)
        plan.update(deadline=runtime.time.monotonic() + 2, maxPauseSeconds=0.05)
        raw = canonical(plan)
        path.with_suffix('.request').write_bytes(canonical({'planHash': hashlib.sha256(raw).hexdigest()}))
        runtime.drive_watchdog(path, plan, raw)
        self.assertEqual(self.mutations(), [('tasks', 'pause', self.cid), ('tasks', 'resume', self.cid)])
        self.assertEqual(self.state, 'RUNNING')

    def test_parent_completion_before_pause_request_never_pauses(self):
        control = self.control()
        path = self.cluster.task / 'private' / 'cancelled.json'
        plan = copy.deepcopy(control.plan)
        plan.update(deadline=runtime.time.monotonic() + 2, maxPauseSeconds=1)
        raw = canonical(plan)
        receipt = canonical({'planHash': hashlib.sha256(raw).hexdigest()})
        path.with_suffix('.request').write_bytes(receipt)
        path.with_suffix('.done').write_bytes(receipt)
        runtime.drive_watchdog(path, plan, raw)
        self.assertFalse(self.mutations())


class RuntimeImageGuards(unittest.TestCase):
    def test_verified_alias_requires_both_unique_records_at_exact_manifest_digest(self):
        digest, config = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
        expected, alias = 'example/operator@' + digest, 'example/operator:trial'
        table = expected + ' application/vnd.oci.image.manifest.v1+json ' + digest + ' 1 MiB linux/amd64 -\n' \
            + alias + ' application/vnd.oci.image.manifest.v1+json ' + digest + ' 1 MiB linux/amd64 -\n'
        with patch('runtime_control.manifest_config', return_value=config) as verified, patch('runtime_control.command', return_value=table) as listing:
            self.assertTrue(runtime.image_matches(expected, alias))
            verified.assert_called_with(digest)
            self.assertEqual(listing.call_args_list, [unittest.mock.call('images', 'list', 'name==' + json.dumps(expected)),
                unittest.mock.call('images', 'list', 'name==' + json.dumps(alias))])
            for changed in (table.splitlines()[0], table + table.splitlines()[1] + '\n',
                            table.replace(alias + ' application/vnd.oci.image.manifest.v1+json ' + digest,
                                alias + ' application/vnd.oci.image.manifest.v1+json sha256:' + 'c' * 64)):
                listing.return_value = changed
                self.assertFalse(runtime.image_matches(expected, alias))

    def test_raw_manifest_hash_is_verified_before_accepting_config(self):
        raw = canonical({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': {'digest': 'sha256:' + 'b' * 64}, 'layers': []})
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        result = Mock(returncode=0, stdout=raw)
        with patch('runtime_control.subprocess.run', return_value=result) as called:
            self.assertEqual(runtime.manifest_config(digest), 'sha256:' + 'b' * 64)
            self.assertNotIn('text', called.call_args.kwargs)
            with self.assertRaises(RuntimeError):
                runtime.manifest_config('sha256:' + 'd' * 64)
            result.stdout += b'\n'
            with self.assertRaises(RuntimeError):
                runtime.manifest_config(digest)


if __name__ == '__main__':
    unittest.main()
