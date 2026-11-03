"""Reversible pause of one owned trial container, from the host runtime.

Linux namespace init protection makes same-namespace SIGSTOP unsuitable.
Every operation pins the Kubernetes owner, container ID, runtime labels, PID,
start time and exact operator argv. A detached bounded watchdog can only resume
that same task. This module never sends a host signal or changes another task.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import uuid

from application import require, wait, write_values_once
from fixture import canonical, write_private
from process_control import ProcessControl


PREFIX = ['sudo', '-n', 'k0s', 'ctr', '-n', 'k8s.io']


def command(*args):
    try:
        value = subprocess.run(PREFIX + list(args), capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Owned runtime command unavailable') from None
    require(value.returncode == 0 and len(value.stdout) <= 262144, 'Owned runtime command rejected')
    return value.stdout


def manifest_config(digest):
    require(isinstance(digest, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', digest), 'Runtime manifest digest invalid')
    try:
        value = subprocess.run(PREFIX + ['content', 'get', digest], capture_output=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Runtime pinned manifest unavailable') from None
    require(value.returncode == 0 and len(value.stdout) <= 262144
        and 'sha256:' + hashlib.sha256(value.stdout).hexdigest() == digest, 'Runtime manifest content digest mismatch')
    manifest = json.loads(value.stdout)
    config = manifest.get('config', {}).get('digest')
    require(manifest.get('schemaVersion') == 2 and manifest.get('mediaType') in (
        'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')
        and isinstance(config, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', config),
        'Runtime pinned direct manifest invalid')
    return config


def image_matches(expected, actual):
    if actual == expected:
        return True
    require(isinstance(actual, str) and re.fullmatch(r'[a-z0-9][a-z0-9./:_@-]{1,252}', actual)
        and isinstance(expected, str) and re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', expected),
        'Runtime image reference invalid')
    digest = expected.rsplit('@', 1)[1]
    config = manifest_config(digest)
    if actual == config:
        return True
    # CRI may retain an imported tag as Container.Image. Names alone are never
    # sufficient: BOTH exact image records must resolve to the pinned manifest
    # on every action, whose raw content hash was checked independently above.
    records = {name: [] for name in (expected, actual)}
    for name in records:
        # Filter in containerd before reading output. A shared host may cache
        # many unrelated images; do not enumerate or enlarge the output bound.
        for line in command('images', 'list', 'name==' + json.dumps(name)).splitlines():
            fields = line.split()
            if fields and fields[0] == name:
                records[name].append(fields)
    return all(len(rows) == 1 and len(rows[0]) >= 3 and rows[0][2] == digest for rows in records.values())


def process_identity(pid):
    root = Path('/proc') / str(pid)
    try:
        with (root / 'cmdline').open('rb') as stream:
            argv = stream.read(65537)
        with (root / 'status').open() as stream:
            status = stream.read(16385)
        with (root / 'stat').open() as stream:
            stat = stream.read(8193)
    except OSError:
        raise RuntimeError('Owned runtime process unavailable') from None
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    stat_fields = stat.rsplit(')', 1)[-1].split()
    require(len(argv) <= 65536 and argv.endswith(b'\0') and len(status) <= 16384 and len(stat) <= 8192
        and fields.get('Uid', '').split() == ['65532'] * 4 and fields.get('NSpid', '').split()[-1:] == ['1']
        and fields.get('State', '').strip()[:1] not in ('Z', 'X') and len(stat_fields) >= 20
        and stat_fields[19].isdigit(), 'Owned runtime process identity invalid')
    return {'argv': argv, 'start': stat_fields[19]}


def inspect_runtime(plan):
    require(socket.gethostname() == plan['node'], 'Owned runtime host mismatch')
    require(isinstance(plan['cid'], str) and re.fullmatch(r'[0-9a-f]{64}', plan['cid']), 'Owned runtime container ID invalid')
    container = json.loads(command('containers', 'info', plan['cid']))
    require(container.get('ID') == plan['cid'] and container.get('Image') == plan.get('runtimeImage', container.get('Image'))
        and image_matches(plan['image'], container.get('Image'))
        and all(container.get('Labels', {}).get(k) == value for k, value in plan['labels'].items()),
        'Owned runtime container identity mismatch')
    matches = []
    for line in command('tasks', 'list').splitlines():
        fields = line.split()
        if fields and fields[0] == plan['cid']:
            matches.append(fields)
    require(len(matches) == 1 and len(matches[0]) == 3 and matches[0][1].isdigit()
        and matches[0][2] in ('RUNNING', 'PAUSED'), 'Owned runtime task is not unique or live')
    pid, state = int(matches[0][1]), matches[0][2]
    require(1 < pid <= 2147483647 and plan.get('pid', pid) == pid, 'Owned runtime task PID changed')
    process = process_identity(pid)
    expected = b'\0'.join(v.encode() for v in plan['argv']) + b'\0'
    require(process['argv'] == expected and plan.get('start', process['start']) == process['start'],
        'Owned runtime process changed')
    return {'pid': pid, 'start': process['start'], 'state': state, 'runtimeImage': container['Image']}


def resume_exact(plan):
    """Watchdog uses no kubeconfig; all exact runtime pins were reviewed before pause."""
    current = inspect_runtime(plan)
    if current['state'] == 'PAUSED':
        command('tasks', 'resume', plan['cid'])
    require(inspect_runtime(plan)['state'] == 'RUNNING', 'Owned runtime resume not confirmed')


def marker(path, suffix, expected):
    selected = path.with_suffix(suffix)
    if not selected.exists():
        return False
    require(not selected.is_symlink() and selected.is_file() and selected.stat().st_size <= 512
        and selected.read_bytes() == expected, 'Owned runtime watchdog marker changed')
    return True


def drive_watchdog(path, plan, raw):
    """Sole pause issuer: parent can never pause after this worker has exited."""
    receipt = canonical({'planHash': hashlib.sha256(raw).hexdigest()})
    inspect_runtime(plan)
    write_private(path.with_suffix('.ready'), receipt)
    while time.monotonic() < plan['deadline']:
        if marker(path, '.done', receipt):
            return
        if marker(path, '.request', receipt):
            break
        time.sleep(0.05)
    else:
        return  # No parent request means no pause, including after expiry.
    if marker(path, '.done', receipt):
        return
    attempted = False
    try:
        require(inspect_runtime(plan)['state'] == 'RUNNING', 'Runtime changed before watchdog pause')
        attempted = True
        command('tasks', 'pause', plan['cid'])
        require(inspect_runtime(plan)['state'] == 'PAUSED', 'Runtime pause not confirmed')
        deadline = time.monotonic() + plan['maxPauseSeconds']
        write_private(path.with_suffix('.paused'), canonical({'planHash': hashlib.sha256(raw).hexdigest(), 'deadline': deadline}))
        while time.monotonic() < deadline and not marker(path, '.done', receipt):
            time.sleep(0.05)
    finally:
        if attempted:
            # The same detached worker issues pause and owns its completion;
            # no future parent pause can race a one-shot watchdog exit.
            resume_exact(plan)


def watchdog(path):
    path = Path(path).absolute()
    require(path.resolve() == path and not path.is_symlink() and path.is_file()
        and re.fullmatch(r'runtime-control-[0-9a-f]{32}\.json', path.name)
        and path.parent.name == 'private'
        and path.parent.parent.parent == Path('/opt/sekvyr-trial')
        and re.fullmatch(r'sekvyr-stage6-[0-9]{8}-[0-9a-f]{8}', path.parent.parent.name)
        and path.stat().st_size <= 16384 and path.stat().st_uid == os.getuid()
        and path.stat().st_mode & 0o077 == 0, 'Owned runtime watchdog input unsafe')
    raw = path.read_bytes()
    plan = json.loads(raw)
    require(0 <= plan['deadline'] - time.monotonic() <= 10
        and type(plan['maxPauseSeconds']) is int and 1 <= plan['maxPauseSeconds'] <= 25,
        'Owned runtime watchdog deadline invalid')
    drive_watchdog(path, plan, raw)


class RuntimeTaskControl:
    def __init__(self, cluster, pod, expected_node, max_pause_seconds=25):
        require(type(max_pause_seconds) is int and 1 <= max_pause_seconds <= 25, 'Runtime pause deadline must be bounded')
        require(isinstance(expected_node, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', expected_node),
            'Explicit runtime node required')
        selected = [v for v in pod.get('spec', {}).get('containers', []) if v.get('name') == 'operator']
        require(len(selected) == 1, 'Runtime operator target ambiguous')
        self.guard = ProcessControl(cluster, pod, selected[0]['image'])
        self.cluster, self.node, self.seconds = cluster, expected_node, max_pause_seconds
        current = self.guard._owned()
        require(current['spec'].get('nodeName') == expected_node and socket.gethostname() == expected_node,
            'Runtime control must run on the exact owned Pod node')
        require(next(v for v in current['status']['containerStatuses'] if v['name'] == 'operator').get('imageID') == selected[0]['image'],
            'Runtime resolved Pod image mismatch')
        require(re.fullmatch(r'containerd://[0-9a-f]{64}', self.guard.container_id), 'Exact containerd task ID required')
        self.plan = {'cid': self.guard.container_id.removeprefix('containerd://'), 'node': expected_node,
            'image': selected[0]['image'], 'argv': self.guard.expected_argv,
            'labels': {'io.kubernetes.pod.uid': self.guard.uid, 'io.kubernetes.pod.name': self.guard.name,
                'io.kubernetes.pod.namespace': self.guard.namespace, 'io.kubernetes.container.name': 'operator'}}
        identity = inspect_runtime(self.plan)
        require(identity['state'] == 'RUNNING', 'Runtime target was already paused')
        self.plan.update(pid=identity['pid'], start=identity['start'], runtimeImage=identity['runtimeImage'])
        self.attempted, self.child, self.path, self.receipt = False, None, None, None

    def __repr__(self):
        return '<stage6 exact owned runtime task [redacted]>'

    def _inspect(self):
        pod = self.guard._owned()
        require(pod['spec'].get('nodeName') == self.node, 'Runtime Pod node changed')
        require(next(v for v in pod['status']['containerStatuses'] if v['name'] == 'operator').get('imageID') == self.plan['image'],
            'Runtime resolved Pod image changed')
        return inspect_runtime(self.plan)

    def _watchdog(self):
        private = self.cluster.task / 'private'
        require(private.is_dir() and not private.is_symlink(), 'Runtime private directory unsafe')
        path = private / ('runtime-control-' + uuid.uuid4().hex + '.json')
        self.plan['deadline'] = time.monotonic() + 10
        self.plan['maxPauseSeconds'] = self.seconds
        write_private(path, canonical(self.plan))
        self.path = path
        try:
            self.child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--watchdog', str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True, close_fds=True)
        except OSError:
            raise RuntimeError('Owned runtime watchdog unavailable') from None
        expected = canonical({'planHash': hashlib.sha256(path.read_bytes()).hexdigest()})
        self.receipt = expected
        ready = path.with_suffix('.ready')

        def acknowledged():
            require(self.child.poll() is None, 'Owned runtime watchdog exited before pause')
            if ready.exists():
                require(not ready.is_symlink() and ready.is_file() and ready.read_bytes() == expected,
                    'Owned runtime watchdog readiness changed')
                return True
            return False

        wait(acknowledged, timeout=min(self.seconds, 5))

    def pause(self):
        require(not self.attempted and self._inspect()['state'] == 'RUNNING', 'Runtime pause cannot be repeated or adopted')
        self._watchdog()  # Exists independently BEFORE the fault can be injected.
        self.attempted = True
        try:
            require(self._inspect()['state'] == 'RUNNING', 'Runtime changed before pause')
            require(self.plan['deadline'] > time.monotonic() and self.child.poll() is None,
                'Runtime watchdog request deadline already elapsed')
            write_private(self.path.with_suffix('.request'), self.receipt)

            def paused():
                require(self.child.poll() is None, 'Runtime watchdog exited before pause confirmation')
                path = self.path.with_suffix('.paused')
                if not path.exists():
                    return False
                require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 512,
                    'Runtime pause receipt unsafe')
                answer = json.loads(path.read_bytes())
                require(answer.get('planHash') == json.loads(self.receipt)['planHash']
                    and 0 < answer['deadline'] - time.monotonic() <= self.seconds,
                    'Runtime pause receipt changed or expired')
                self.plan['deadline'] = answer['deadline']
                return True

            wait(paused, timeout=12)
            require(self._inspect()['state'] == 'PAUSED', 'Runtime pause not confirmed')
        except Exception:
            self.resume()
            raise
        return self

    def paused_alive(self):
        return self._inspect()['state'] == 'PAUSED'

    def resume(self):
        require(self.attempted, 'Runtime resume lacks prior pause authorization')
        write_values_once(self.path.with_suffix('.done'), self.receipt)
        self._inspect()
        resume_exact(self.plan)
        if self.child is not None:
            try:
                # Never terminate the sole pause issuer while its RPC may be
                # pending. It owns finally/resume even if this parent fails.
                self.child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                raise RuntimeError('Owned runtime watchdog is still restoring its task') from None
        require(self._inspect()['state'] == 'RUNNING', 'Runtime is not running after resume')

    @contextmanager
    def paused(self):
        self.pause()
        try:
            yield self
        finally:
            self.resume()


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 3 and sys.argv[1] == '--watchdog', 'Explicit watchdog invocation required')
        watchdog(sys.argv[2])
    except Exception:
        # No runtime response, command line, endpoint or private plan in logs.
        raise SystemExit('OwnedRuntimeWatchdogRejected') from None
