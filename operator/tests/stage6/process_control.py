"""Bounded process faults in one explicitly owned trial operator Pod only.

No host process commands, privileged containers or credential mounts are used.
Only handled SIGTERM is sent from inside the target PID namespace. Linux init
protection ignores same-namespace SIGSTOP, even when kill(2) returns success;
pause/resume must use a separately reviewed ancestor runtime control.
The caller must independently observe takeover / same-Pod container restart.
"""

import copy
import json
import re
import uuid

from application import IMAGE, RELEASE, SA, require, wait


CONTROL = r'''
import json, os, signal, sys
operation, expected = sys.argv[1], json.loads(sys.argv[2])
if operation not in ('TERM', 'STOPPED'):
    raise SystemExit('ProcessOperationDenied')
actual = open('/proc/1/cmdline', 'rb').read(65537)
if len(actual) > 65536 or not actual.endswith(b'\0') or actual[:-1].split(b'\0') != [s.encode() for s in expected]:
    raise SystemExit('ProcessIdentityDenied')
status = open('/proc/1/status').read(16385)
fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
if os.geteuid() != 65532 or fields.get('Uid', '').split() != ['65532'] * 4:
    raise SystemExit('ProcessUserDenied')
if os.readlink('/proc/1/ns/pid') != os.readlink('/proc/self/ns/pid'):
    raise SystemExit('ProcessNamespaceDenied')
os.kill(1, 0)
if operation == 'STOPPED':
    print('ProcessStoppedAlive' if fields.get('State', '').strip().startswith(('T', 't')) else 'ProcessRunningAlive', flush=True)
else:
    os.kill(1, signal.SIGTERM)
    print('SignalAccepted', flush=True)
'''


def controller(resource, kind):
    owners = [v for v in resource.get('metadata', {}).get('ownerReferences', []) if v.get('controller') is True]
    require(len(owners) == 1 and owners[0].get('kind') == kind and owners[0].get('apiVersion') == 'apps/v1'
        and owners[0].get('name') and owners[0].get('uid'), 'Operator process owner mismatch')
    return owners[0]


class ProcessControl:
    def __init__(self, cluster, pod, image):
        require(isinstance(image, str) and IMAGE.fullmatch(image) is not None, 'Process helper image must be digest pinned')
        self.cluster, self.image = cluster, image
        self.namespace = cluster.fixture['namespaces']['apps']
        self.namespace_uid = cluster.namespace_pins()[self.namespace]
        meta = pod.get('metadata', {})
        require(meta.get('namespace') == self.namespace and isinstance(meta.get('name'), str)
            and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', meta['name']) and meta.get('uid'), 'Operator process Pod scope mismatch')
        self.name, self.uid = meta['name'], meta['uid']
        self.pins = {}
        for path in cluster.pins.glob('*.json'):
            require(not path.is_symlink(), 'Process creation registry unsafe')
            pin = json.loads(path.read_bytes())
            if pin.get('namespace') == self.namespace:
                identity = (pin['kind'], pin['name'])
                require(identity not in self.pins, 'Process creation registry ambiguous')
                self.pins[identity] = pin['uid']
        self.container_id, self.expected_argv = None, None
        self.control_name = 'trial-process-' + uuid.uuid4().hex[:12]
        self.created = False
        self._owned()

    def __repr__(self):
        return '<stage6 owned process control [redacted]>'

    def _get(self, kind, name):
        value = json.loads(self.cluster.kube('get', kind, name, '-n', self.namespace, '-o', 'json').stdout)
        require(value.get('metadata', {}).get('namespace') == self.namespace
            and value['metadata'].get('name') == name and not value['metadata'].get('deletionTimestamp'),
            'Operator process object scope changed')
        return value

    def _owned(self):
        namespace = json.loads(self.cluster.kube('get', 'namespace', self.namespace, '-o', 'json').stdout)
        require(namespace['metadata']['uid'] == self.namespace_uid, 'Operator process namespace replaced')
        deployment = self._get('Deployment', RELEASE + '-operator')
        service_account = self._get('ServiceAccount', SA)
        for kind, value in (('Deployment', deployment), ('ServiceAccount', service_account)):
            require(self.pins.get((kind, value['metadata']['name'])) == value['metadata'].get('uid'),
                'Operator process creation UID mismatch')
        pod = self._get('Pod', self.name)
        require(pod['metadata'].get('uid') == self.uid and pod['metadata'].get('resourceVersion')
            and pod['spec'].get('serviceAccountName') == SA
            and not any(pod['spec'].get(k) for k in ('hostPID', 'hostIPC', 'hostNetwork')),
            'Operator process Pod replaced or unsafe')
        owner = controller(pod, 'ReplicaSet')
        replica_set = self._get('ReplicaSet', owner['name'])
        require(replica_set['metadata']['uid'] == owner['uid'], 'Operator process ReplicaSet replaced')
        parent = controller(replica_set, 'Deployment')
        require(parent['name'] == deployment['metadata']['name'] and parent['uid'] == deployment['metadata']['uid'],
            'Operator process Deployment owner mismatch')
        template = deployment['spec']['template']['spec']
        require(template.get('serviceAccountName') == SA, 'Operator process ServiceAccount mismatch')
        selected = [v for v in pod['spec']['containers'] if v.get('name') == 'operator']
        desired = [v for v in template['containers'] if v.get('name') == 'operator']
        require(len(selected) == len(desired) == 1, 'Operator process target container ambiguous')
        target, desired = selected[0], desired[0]
        argv = target.get('command', ['/sekvyr-operator']) + target.get('args', [])
        require(target.get('image') == desired.get('image') and IMAGE.fullmatch(target.get('image', ''))
            and target.get('command', []) == desired.get('command', []) and target.get('args', []) == desired.get('args', [])
            and argv and argv[0] == '/sekvyr-operator' and all(isinstance(v, str) and len(v) <= 4096 for v in argv),
            'Operator process command differs from owned template')
        uid = target.get('securityContext', {}).get('runAsUser', pod['spec'].get('securityContext', {}).get('runAsUser'))
        require(uid == 65532, 'Operator process user mismatch')
        statuses = [v for v in pod.get('status', {}).get('containerStatuses', []) if v.get('name') == 'operator']
        require(len(statuses) == 1 and statuses[0].get('state', {}).get('running') is not None
            and isinstance(statuses[0].get('containerID'), str) and statuses[0]['containerID'], 'Operator process is not running')
        container_id = statuses[0]['containerID']
        require(self.container_id in (None, container_id) and self.expected_argv in (None, argv),
            'Operator process container changed; create a fresh reviewed control')
        self.container_id, self.expected_argv = container_id, argv
        return pod

    def prepare(self, timeout=60):
        require(not self.created, 'Process helper is already prepared')
        pod = self._owned()
        require(not any(v.get('name') == self.control_name for v in pod['spec'].get('ephemeralContainers', [])),
            'Process helper name already present')
        helper = {'name': self.control_name, 'targetContainerName': 'operator', 'image': self.image,
            'imagePullPolicy': 'IfNotPresent', 'command': ['python', '-c', 'import time; time.sleep(600)'],
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}}}
        proposed = copy.deepcopy(pod)
        proposed['spec'].setdefault('ephemeralContainers', []).append(helper)
        path = '/api/v1/namespaces/' + self.namespace + '/pods/' + self.name + '/ephemeralcontainers'
        # Pod PUT includes exact UID/resourceVersion: a replaced/concurrently
        # changed Pod is never adopted. No retry against a newly read version.
        answer = json.loads(self.cluster.kube('replace', '--raw', path, '-f', '-', data=json.dumps(proposed)).stdout)
        require(answer['metadata'].get('uid') == self.uid
            and any(v.get('name') == self.control_name and all(v.get(k) == val for k, val in helper.items())
                for v in answer['spec'].get('ephemeralContainers', [])), 'Process helper creation response mismatch')
        self.created = True

        def running():
            current = self._owned()
            statuses = [v for v in current.get('status', {}).get('ephemeralContainerStatuses', []) if v.get('name') == self.control_name]
            require(len(statuses) <= 1 and not any(v.get('state', {}).get('terminated') for v in statuses),
                'Process helper terminated')
            return bool(statuses and statuses[0].get('state', {}).get('running'))

        wait(running, timeout=timeout)
        self._execute('STOPPED')  # Prove PID namespace and command before faults.
        return self

    def _execute(self, operation):
        require(self.created, 'Process helper is not prepared')
        self._owned()
        result = self.cluster.kube('exec', self.name, '-n', self.namespace, '-c', self.control_name, '--',
            'python', '-c', CONTROL, operation, json.dumps(self.expected_argv), check=False)
        output = result.stdout.strip()
        require(result.returncode == 0 and output in ('SignalAccepted', 'ProcessStoppedAlive', 'ProcessRunningAlive'),
            'Owned process control was not acknowledged')
        return output

    def signal(self, operation):
        require(operation == 'TERM', 'Process signal denied; pause requires ancestor runtime control')
        require(self._execute(operation) == 'SignalAccepted', 'Process signal response invalid')

    def stopped_alive(self):
        return self._execute('STOPPED') == 'ProcessStoppedAlive'
