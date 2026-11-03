"""Bounded status-only observation after the diagnostic image cutover."""

from datetime import datetime, timezone
import json
import os
import re
import time

from app_modes import require
from application import RESOURCE, STORE
from e2e_cases import replicas_current
from fixture import canonical, write_private


def run(e, duration=120):
    require(type(duration) is int and 1 <= duration <= 300, 'Typed observation duration denied')
    root = e.root / 'diagnostic-image-upgrade'
    require((root / 'complete.json').exists(), 'Fresh diagnostic cutover required')
    plan = json.loads((root / 'plan.json').read_bytes())
    expected = plan['current']
    path = root / 'typed-status.ndjson'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    began, count, failure = time.monotonic(), 0, None
    with os.fdopen(fd, 'wb') as stream:
        while True:
            cr, store = e.app.get('SekvyrSecret', RESOURCE), e.app.get('SekvyrStore', STORE)
            status = cr.get('status', {})
            require(status.get('observedGeneration') == cr['metadata']['generation']
                and status.get('observedStoreUID') == store['metadata']['uid']
                and status.get('observedStoreGeneration') == store['metadata']['generation'], 'Typed observation context is stale')
            conditions = [{key: c.get(key) for key in ('type', 'status', 'reason', 'observedGeneration')}
                for c in status.get('conditions', [])]
            require(all(re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,79}', c.get('reason', '')) for c in conditions), 'Typed reason shape denied')
            sample = {'utc': datetime.now(timezone.utc).isoformat(), 'elapsed': round(time.monotonic()-began, 3),
                'lastAttempt': status.get('lastAttemptTime'), 'lastSuccess': status.get('lastSuccessfulSyncTime'), 'conditions': conditions}
            stream.write(canonical(sample)+b'\n'); stream.flush(); os.fsync(stream.fileno()); count += 1
            bad = [c for c in conditions if c['type'] in ('Ready', 'DataCurrent', 'RolloutReady') and c['status'] != 'True']
            if bad:
                failure = {'utc': sample['utc'], 'lastAttempt': sample['lastAttempt'], 'lastSuccess': sample['lastSuccess'],
                    'reasons': sorted(set(c['reason'] for c in bad)), 'twoOperatorAndFencerReady': replicas_current(e.app)}
                break
            if time.monotonic()-began >= duration: break
            time.sleep(2)
    current = e.c.current()
    require(all(current[k] == expected[k] for k in ('snapshot', 'authority', 'enrollments')), 'Typed observation canonical context changed')
    result = {'durationSeconds': round(time.monotonic()-began, 3), 'samples': count,
        'firstTypedFailure': failure, 'canonicalContextUnchanged': True, 'availabilityFixClaimed': False, 'production': False}
    write_private(root / 'typed-status-summary.json', canonical(result))
    return result
