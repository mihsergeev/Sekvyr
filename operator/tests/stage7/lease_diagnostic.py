"""Correlate live Lease metadata with typed failure timestamps, without writes."""

from datetime import datetime, timezone
import json
import os
import time

from app_modes import require
from application import LEASE, RESOURCE
from fixture import canonical, write_private


def run(e, duration=90):
    require(type(duration) is int and 1 <= duration <= 120, 'Lease diagnostic duration denied')
    root = e.root / 'diagnostic-image-upgrade'
    path = root / 'lease-correlation.ndjson'
    lease_pin = e.app.get('Lease', LEASE)['metadata']['uid']
    cr_pin = e.app.get('SekvyrSecret', RESOURCE)['metadata']['uid']
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    began, count, ages, futures, attempts = time.monotonic(), 0, [], 0, {}
    with os.fdopen(fd, 'wb') as stream:
        while True:
            raw = e.c.cluster.kube('get', 'leases,sekvyrsecrets', '-n', e.app.namespace, '-o', 'json', '--request-timeout=5s').stdout
            require(len(raw.encode()) < 256*1024, 'Lease diagnostic bounds exceeded')
            items = json.loads(raw)['items']
            lease = next(v for v in items if v['kind']=='Lease' and v['metadata']['name']==LEASE)
            cr = next(v for v in items if v['kind']=='SekvyrSecret' and v['metadata']['name']==RESOURCE)
            require(lease['metadata']['uid']==lease_pin and cr['metadata']['uid']==cr_pin, 'Lease diagnostic identity changed')
            now = datetime.now(timezone.utc)
            renew = datetime.fromisoformat(lease['spec']['renewTime'].replace('Z','+00:00'))
            age = (now-renew).total_seconds(); duration_seconds=lease['spec']['leaseDurationSeconds']
            conditions=cr.get('status',{}).get('conditions',[])
            reason=next((v['reason'] for v in conditions if v['type']=='DataCurrent'),None)
            sample={'utc':now.isoformat(),'elapsed':round(time.monotonic()-began,3),'renewAgeSeconds':round(age,6),
                'durationSeconds':duration_seconds,'renewInFuture':age<0,'expiredAtRead':age>=duration_seconds,
                'lastAttempt':cr.get('status',{}).get('lastAttemptTime'),'lastSuccess':cr.get('status',{}).get('lastSuccessfulSyncTime'),
                'dataReason':reason,'leaseResourceVersion':lease['metadata']['resourceVersion']}
            stream.write(canonical(sample)+b'\n');stream.flush();os.fsync(stream.fileno())
            count+=1;ages.append(age);futures+=age<0
            if sample['lastAttempt']:
                attempts.setdefault(sample['lastAttempt'], {'reason':reason,'firstObservedRenewAge':round(age,6),'sampleUTC':sample['utc']})
            if time.monotonic()-began>=duration:break
            time.sleep(1)
    result={'samples':count,'durationSeconds':round(time.monotonic()-began,3),'minRenewAge':min(ages),'maxRenewAge':max(ages),
        'futureRenewSamples':futures,'attempts':attempts,'production':False}
    write_private(root/'lease-correlation-summary.json',canonical(result))
    return result
