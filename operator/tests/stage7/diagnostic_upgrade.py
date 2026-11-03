"""One reviewed image-only Helm diagnostic change; no data publication."""

import copy
from datetime import datetime, timezone
import json
import time

from app_modes import require, wait
from application import RESOURCE, STORE, TARGET, REVISION
from e2e_cases import replicas_current
from fixture import canonical, write_private
from fresh_helm_sync import FreshHelmSync
from helm_lifecycle import identity
from readiness_upgrade import _processes

OLD = 'docker.io/library/sekvyr-operator-stage7@sha256:960d66695ae8faf3f020a83e183e3b17a3efde9091f393c525351e2ebe4ef881'
NEW = 'docker.io/library/sekvyr-operator-stage7@sha256:d328c35df0557ace446628172658d463e05eae0afeb2c11d283f090a80b21652'


def review_diff(before, after):
    left, right = ({identity(v): v for v in values} for values in (before, after))
    require(len(left) == len(before) and len(right) == len(after) and set(left) == set(right), 'Diagnostic identities changed')
    changed = set()
    for key, old in left.items():
        expected = copy.deepcopy(old)
        if old['kind'] == 'Deployment' and old['metadata']['name'] in ('stage6-operator', 'stage6-fencer'):
            containers = expected['spec']['template']['spec']['containers']
            require(len(containers) == 1 and containers[0]['image'] == OLD, 'Diagnostic original image differs')
            containers[0]['image'] = NEW
            changed.add(old['metadata']['name'])
        require(expected == right[key], 'Diagnostic upgrade changes more than the exact image')
    require(changed == {'stage6-operator', 'stage6-fencer'}, 'Diagnostic upgrade requires both exact deployments')


def run(e):
    root = e.root / 'diagnostic-image-upgrade'
    root.mkdir(mode=0o700, exist_ok=True)
    require(not root.is_symlink() and not (root / 'plan.json').exists(), 'Diagnostic attempt cannot reset')
    current = e.c.current()
    before, status, target = e.app.footprint(), wait(e.app.status), e.app.get('Secret', TARGET)
    old_processes = _processes(e)
    values = copy.deepcopy(e.values)
    require(values['image']['digest'] == OLD.split('@')[1], 'Diagnostic values image differs')
    values['image']['digest'] = NEW.split('@')[1]
    old_render, _ = e.lifecycle.render(e.values)
    new_render, _ = e.lifecycle.render(values)
    review_diff(old_render, new_render)
    write_private(root / 'plan.json', canonical({'oldValues': e.values, 'newValues': values, 'oldRender': old_render,
        'newRender': new_render, 'current': current, 'footprint': before, 'appStatus': status,
        'targetUID': target['metadata']['uid'], 'data': target['data'], 'revision': target['metadata']['annotations'][REVISION],
        'oldProcesses': old_processes}))
    e.lifecycle.upgrade(values)
    e.register_managed()
    e.values, e.image = values, NEW
    wait(lambda: replicas_current(e.app), timeout=240)

    def old_gone():
        pods = json.loads(e.c.cluster.kube('get', 'pods', '-n', e.app.namespace, '-o', 'json').stdout)['items']
        return not any(p['metadata']['uid'] in old_processes for p in pods)

    wait(old_gone, timeout=240)
    cr, store = e.app.get('SekvyrSecret', RESOURCE), e.app.get('SekvyrStore', STORE)
    baseline = cr['status']['lastSuccessfulSyncTime']
    cutover = datetime.now(timezone.utc)
    write_private(root / 'cutover.json', canonical({'cutover': cutover.isoformat(), 'baselineLastSuccess': baseline,
        'oldOwnedProcessesAbsent': True}))
    gate = FreshHelmSync(e.app, current['snapshot'], cutover=cutover, baseline_last_success=baseline,
        expected_cr_generation=cr['metadata']['generation'], expected_store_uid=store['metadata']['uid'],
        expected_store_generation=store['metadata']['generation'], old_owned_fencers_absent=True,
        cr_name=RESOURCE, store_name=STORE)
    gate.wait(poke=True)
    after = e.c.current()
    require(all(after[key] == current[key] for key in ('snapshot', 'authority', 'enrollments')), 'Diagnostic canonical context changed')
    actual = e.app.get('Secret', TARGET)
    require(actual['metadata']['uid'] == target['metadata']['uid'] and actual['data'] == target['data']
        and actual['metadata']['annotations'][REVISION] == target['metadata']['annotations'][REVISION], 'Diagnostic target changed')
    e.app.frozen(before, seconds=0)
    now = wait(e.app.status)
    require((now['pod_uid'], now['boot_id']) == (status['pod_uid'], status['boot_id']), 'Diagnostic app process changed')
    result = {'imageOnlyNativeHelmUpgrade': True, 'freshPostUpgradeSync': True, 'oldOwnedProcessesAbsent': True,
        'twoOperatorAndFencerReplicasReady': True, 'canonicalContextAndApplicationUnchanged': True,
        'availabilityFixClaimed': False, 'production': False}
    write_private(root / 'complete.json', canonical(result))
    return result
