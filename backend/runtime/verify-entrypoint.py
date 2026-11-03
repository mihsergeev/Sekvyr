"""Linux image acceptance: real ownership, privilege drop and signal delivery."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile

ENTRYPOINT = "/usr/local/bin/docker-entrypoint.sh"
CHILD = r"""
import json,os,signal,sys
from pathlib import Path
root=Path(os.environ["RUNTIME_PROBE_ROOT"])
assert os.getuid()==10001 and os.getgid()==10001 and 0 not in os.getgroups()
assert (root/"data").stat().st_uid==10001
assert (root/"data"/"postgres").stat().st_uid==999
keydir=root/"secret"
assert keydir.stat().st_uid==10001 and keydir.stat().st_mode & 0o777==0o700
assert int(next(x.split()[1] for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("CapEff:")),16)==0
from alembic.config import Config
from alembic.script import ScriptDirectory
from app import main
assert Path(main.__file__).resolve()==Path("/srv/app/main.py") and callable(main.app)
config=Config("/srv/alembic.ini")
config.set_main_option("script_location","/srv/alembic")
migrations=ScriptDirectory.from_config(config)
assert len(migrations.get_heads())==1 and any(row.revision=="0029" for row in migrations.walk_revisions())
for code in ("/srv/app/api", "/srv/app/api/machine.py", "/srv/alembic/versions"):
    path=Path(code)
    assert path.stat().st_uid==0 and not os.access(path,os.W_OK)
(root/"data"/"application-write").write_text("public runtime fixture")
def finish(signum,frame):
    print(json.dumps({"termReceived":True}),flush=True)
    raise SystemExit(0)
signal.signal(signal.SIGTERM,finish)
print(json.dumps({"ready":True,"pid":os.getpid(),"uid":os.getuid(),"gid":os.getgid()}),flush=True)
signal.pause()
"""


def run_case(root, nonroot):
    environment = dict(os.environ, SEKVYR_DATA_DIR=str(root / "data"),
                       SEKVYR_DB_URL="sqlite+aiosqlite:///" + str(root / "data" / "probe.db"),
                       SEKVYR_ROOT_KEY_FILE=str(root / "secret" / "root.key"),
                       RUNTIME_PROBE_ROOT=str(root))
    command = (["su-exec", "10001:10001"] if nonroot else []) + [ENTRYPOINT, sys.executable, "-B", "-c", CHILD]
    process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    descriptor = os.pidfd_open(process.pid)
    try:
        if not select.select([process.stdout], [], [], 35)[0]:
            raise RuntimeError("Runtime child readiness deadline exceeded")
        ready = json.loads(process.stdout.readline())
        if ready != {"ready": True, "pid": process.pid, "uid": 10001, "gid": 10001}:
            raise RuntimeError("Entry point did not exec the exact unprivileged process")
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        output, error = process.communicate(timeout=10)
        if process.returncode != 0 or json.loads(output) != {"termReceived": True}:
            raise RuntimeError("Entry point signal or exit status differs")
        if (root / "data" / "postgres").stat().st_uid != 999:
            raise RuntimeError("PostgreSQL ownership changed")
        if (root / "data" / "postgres" / "marker").read_bytes() != b"postgres fixture":
            raise RuntimeError("PostgreSQL fixture content changed")
        if (root / "data" / "application-write").stat().st_uid != 10001:
            raise RuntimeError("Application write ownership differs")
    finally:
        if process.poll() is None:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            process.wait(timeout=10)
        os.close(descriptor)
        process.stdout.close()
        process.stderr.close()


def main():
    if os.geteuid() != 0 or not Path(ENTRYPOINT).is_file():
        raise RuntimeError("Execute only inside the reviewed candidate Linux image as root")
    with tempfile.TemporaryDirectory(prefix="sekvyr-runtime-probe-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        (root / "data" / "postgres").mkdir(parents=True)
        (root / "data" / "postgres" / "marker").write_bytes(b"postgres fixture")
        os.chown(root / "data" / "postgres", 999, 999)
        os.chown(root / "data" / "postgres" / "marker", 999, 999)
        run_case(root, nonroot=False)
        run_case(root, nonroot=True)
    return {"realRootAndNonrootStartup": True, "uidAndGid10001": True,
            "rootGroupsAndEffectiveCapabilitiesAbsent": True,
            "postgresOwnershipAndContentsPreserved": True,
            "privateKeyDirectoryMode700": True, "applicationDataWritable": True,
            "realAPIImportAndMigrationTraversalAsUID10001": True,
            "sameChildPIDExecAndSIGTERMDelivered": True}


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception:
        raise SystemExit("Runtime entrypoint verification failed") from None
