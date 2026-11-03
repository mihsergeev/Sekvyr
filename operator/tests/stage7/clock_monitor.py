"""Observe UTC versus monotonic time without adjusting any clock or service."""

from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import re
import signal
import time


def run(root, seconds=21600):
    root = Path(root)
    if os.geteuid() != 0 or root.resolve() != root or root.is_symlink() or root.parent != Path('/opt/sekvyr-trial') or not re.fullmatch(r'sekvyr-stage7-[0-9]{8}-[0-9a-f]{8}', root.name):
        raise ValueError('Clock observer root denied')
    if type(seconds) is not int or not 1 <= seconds <= 21600:
        raise ValueError('Clock observer duration denied')
    receipt = json.loads((root/'receipts/root-task-create.json').read_bytes())
    info = root.stat()
    if (info.st_dev, info.st_ino, info.st_uid) != (receipt['dev'], receipt['ino'], 0):
        raise ValueError('Clock observer root replaced')
    stop = False
    def finish(signum, frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGINT, finish)
    began, last_wall, last_mono = time.monotonic(), time.time(), time.monotonic()
    samples = backwards = forwards = 0
    largest = 0.0
    fd = os.open(root/'receipts/clock-monitor.ndjson', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        while not stop:
            wall, mono = time.time(), time.monotonic()
            delta = (wall-last_wall)-(mono-last_mono)
            backwards += delta < -0.05
            forwards += delta > 0.05
            largest = max(largest, abs(delta))
            sample = {'utc': datetime.fromtimestamp(wall, timezone.utc).isoformat(), 'elapsedSeconds': round(mono-began,6), 'wallMinusMonotonicDeltaSeconds': round(delta,6)}
            stream.write(json.dumps(sample,sort_keys=True)+'\n');stream.flush();os.fsync(stream.fileno())
            samples += 1
            last_wall, last_mono = wall, mono
            if mono-began >= seconds: break
            time.sleep(min(2,max(0,seconds-(mono-began))))
    result = {'samples':samples,'durationSeconds':round(time.monotonic()-began,3),'backwardClockSteps':backwards,'forwardClockSteps':forwards,
        'largestWallMonotonicDiscontinuitySeconds':round(largest,6),'clockOrServiceModified':False,'production':False}
    fd=os.open(root/'receipts/clock-monitor-summary.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(result,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root-task',required=True);parser.add_argument('--seconds',type=int,default=21600)
    args=parser.parse_args();run(args.root_task,args.seconds)
