"""Fixed trial recovery supervisor. No action runs at import time.

The root supervisor and its direct CLI are independently pinned with pidfds.
Private inputs are safe to remove only after confirmed termination. The caller
must retain them when RecoveryProcessError.termination_confirmed is false.
"""

import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import uuid


class RecoveryProcessError(RuntimeError):
    def __init__(self, termination_confirmed=False):
        super().__init__("Verified recovery process rejected")
        self.termination_confirmed = termination_confirmed


def _require(value):
    if not value:
        raise RecoveryProcessError(False)


def process_identity(pid):
    _require(type(pid) is int and pid > 1)
    fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[-1].split()
    _require(len(fields) > 19 and fields[19].isdigit() and fields[1].isdigit())
    lines = (Path("/proc") / str(pid) / "status").read_text().splitlines()
    matches = [line.split()[1:] for line in lines if line.startswith("Uid:")]
    _require(len(matches) == 1 and len(matches[0]) == 4)
    return {"pid": pid, "start": fields[19], "parent": int(fields[1]),
        "uids": [int(item) for item in matches[0]], "state": fields[0]}


def ancestry(pid, caller):
    seen = set()
    for _ in range(24):
        if pid == caller["pid"]:
            current = process_identity(pid)
            return current["start"] == caller["start"] and current["uids"][0] == caller["uid"]
        if pid in seen or pid <= 1:
            return False
        seen.add(pid)
        pid = process_identity(pid)["parent"]
    return False


def pin_receipt(value, caller, nonce, parent=None):
    _require(isinstance(value, dict) and set(value) == {"nonce", "pid", "start", "uid"}
        and value["nonce"] == nonce and value["uid"] == 0)
    pid = value["pid"]
    current = process_identity(pid)
    _require(current["start"] == value["start"] and current["uids"] == [0] * 4 and current["state"] not in ("Z", "X"))
    if parent is None:
        _require(ancestry(pid, caller))
    else:
        _require(current["parent"] == parent["pid"] and process_identity(parent["pid"])["start"] == parent["start"])
    fd = os.pidfd_open(pid)
    try:
        after = process_identity(pid)
        _require(all(after[key] == current[key] for key in ("pid", "start", "parent", "uids"))
            and after["state"] not in ("Z", "X"))
        return {**value, "fd": fd}
    except BaseException:
        os.close(fd)
        raise


def exited(pin):
    poller = select.poll()
    poller.register(pin["fd"], select.POLLIN)
    return bool(poller.poll(0))


def _receipt(path):
    if not path.exists():
        return None
    _require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 4096)
    return json.loads(path.read_bytes())


def _gate(path, nonce):
    _require(not path.exists() and not path.is_symlink())
    pending = path.with_name(".pending-" + path.name)
    with pending.open("xb") as stream:
        stream.write(nonce.encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    pending.chmod(0o600)
    os.link(pending, path)
    pending.unlink()


# Root setup is selected only by a fixed source profile, never by a plan field.
def driver_source(profile):
    if profile == "kind":
        from kind_recovery import ROOT_SETUP
    elif profile == "host":
        from host_recovery import ROOT_SETUP
    elif profile == "remote-kind":
        from remote_kind_recovery import ROOT_SETUP
    else:
        raise RecoveryProcessError(True)
    return ROOT_PREFIX + "\n" + ROOT_SETUP + "\n" + ROOT_MAIN


ROOT_PREFIX = r'''
import ctypes, hashlib, json, os, pathlib, resource, select, signal, sys, threading, time
proc_directory=None
def need(value):
    if not value: raise RuntimeError('RecoveryChildGuardRejected')
def proc(pid):
    def read(name):
        if proc_directory is None: return pathlib.Path('/proc/'+str(pid)+'/'+name).read_text()
        fd=os.open(str(pid)+'/'+name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=proc_directory)
        try: return os.read(fd,65536).decode()
        finally: os.close(fd)
    f=read('stat').rsplit(')',1)[-1].split()
    need(len(f)>19 and f[19].isdigit() and f[0] not in ('Z','X'))
    lines=read('status').splitlines()
    u=[x.split()[1:] for x in lines if x.startswith('Uid:')]
    need(len(u)==1 and len(u[0])==4)
    return {'pid':pid,'start':f[19],'parent':int(f[1]),'uids':[int(x) for x in u[0]]}
def start(pid): return proc(pid)['start']
def filehash(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def write_receipt(name,body):
    pending='.pending-'+name
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        os.fchown(fd,caller['uid'],caller['gid'])
        raw=json.dumps(body,sort_keys=True,separators=(',',':')).encode()
        with os.fdopen(fd,'wb',closefd=False) as f: f.write(raw); f.flush(); os.fsync(fd)
    finally: os.close(fd)
    os.link(pending,name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
    os.unlink(pending,dir_fd=directory)
def wait_gate(name,timeout=15):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try: fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
        except FileNotFoundError: time.sleep(.03); continue
        try: need(os.read(fd,128)==caller['nonce'].encode())
        finally: os.close(fd)
        return
    raise RuntimeError('RecoveryChildGateExpired')
def reap(pid,timeout):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value,status=os.waitpid(pid,os.WNOHANG)
        if value==pid: return status
        time.sleep(.03)
    return None
'''


ROOT_MAIN = r'''
directory=None; cli=None; cli_fd=None; cli_start=None; cli_reaped=False; complete=False
try:
    need(os.geteuid()==0 and hasattr(os,'pidfd_open'))
    caller=json.loads(sys.argv[3]); need(set(caller)=={'pid','start','uid','gid','nonce'})
    need(type(caller['pid']) is int and caller['pid']>1 and caller['uid']>=0 and caller['gid']>=0)
    pidfd=os.pidfd_open(caller['pid']); identity=proc(caller['pid'])
    need(identity['start']==caller['start'] and identity['uids'][0]==caller['uid'])
    def watchdog():
        p=select.poll(); p.register(pidfd,select.POLLIN); p.poll(); os.kill(os.getpid(),signal.SIGKILL)
    threading.Thread(target=watchdog,daemon=True).start()
    path=pathlib.Path(sys.argv[1]); raw=path.read_bytes()
    need(len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==sys.argv[2] and not path.is_symlink())
    p=json.loads(raw); root=pathlib.Path(p['sandbox'])
    need(root.resolve()==root and path.parent==root and root.is_dir() and not root.is_symlink() and
        [root.stat().st_dev,root.stat().st_ino]==p['sandboxIdentity'])
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    proc_directory=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY)
    me=proc(os.getpid()); need(me['uids']==[0]*4)
    write_receipt('root-ready.json',{'nonce':caller['nonce'],'pid':me['pid'],'start':me['start'],'uid':0})
    wait_gate('root-go')
    names={'bin/sekvyr-checkpoint-recovery','etc/resolv.conf','etc/hosts','inputs/kubeconfig',
        'inputs/plan.json','inputs/envelope.json','inputs/reader-wrap.json','inputs/installation.json'}
    need(set(p['files'])==names)
    for name,expected in p['files'].items():
        f=root/name; need(f.resolve()==f and f.is_file() and not f.is_symlink() and filehash(f)==expected)
    root_setup(p)
    for name,expected in p['files'].items(): need(filehash(root/name)==expected)
    os.chdir(root); os.chroot(root); os.chdir('/')
    args=['/bin/sekvyr-checkpoint-recovery','--kubeconfig=/inputs/kubeconfig','--allow-trial-canonical-ledger',
        '--installation-file','/inputs/installation.json','--plan','/inputs/plan.json','--envelope',
        '/inputs/envelope.json','--reader-wrap','/inputs/reader-wrap.json']
    need(type(p['allowRollout']) is bool)
    if p['allowRollout']: args.append('--enable-rollout')
    # The direct CLI cannot exec before its own pidfd has been pinned by caller.
    barrier_r,barrier_w=os.pipe(); out_r,out_w=os.pipe(); err_r,err_w=os.pipe(); in_r,in_w=os.pipe()
    supervisor=os.getpid(); cli=os.fork()
    if cli==0:
        try:
            libc=ctypes.CDLL(None,use_errno=True)
            if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=supervisor: os._exit(125)
            os.close(barrier_w); os.close(in_w)
            if os.read(barrier_r,1)!=b'G' or os.getppid()!=supervisor: os._exit(125)
            os.dup2(in_r,0); os.dup2(out_w,1); os.dup2(err_w,2)
            os.closerange(3,resource.getrlimit(resource.RLIMIT_NOFILE)[0])
            os.execve(args[0],args,{'KUBECONFIG':'/inputs/kubeconfig'})
        except BaseException: os._exit(125)
    cli_fd=os.pidfd_open(cli)
    cli_start=start(cli)
    write_receipt('cli-ready.json',{'nonce':caller['nonce'],'pid':cli,'start':cli_start,'uid':0})
    wait_gate('cli-go')
    os.close(barrier_r); os.close(out_w); os.close(err_w); os.close(in_r); os.close(in_w)
    os.write(barrier_w,b'G'); os.close(barrier_w)
    outputs={out_r:bytearray(),err_r:bytearray()}; poller=select.poll()
    for fd in outputs: os.set_blocking(fd,False); poller.register(fd,select.POLLIN|select.POLLHUP)
    end=time.monotonic()+310; status=None
    while time.monotonic()<end:
        for fd,event in poller.poll(50):
            chunk=os.read(fd,4096)
            if chunk:
                outputs[fd].extend(chunk); need(sum(map(len,outputs.values()))<=8192)
            else: poller.unregister(fd)
        if status is None:
            found,result=os.waitpid(cli,os.WNOHANG)
            if found==cli: status=result; cli_reaped=True
        if status is not None and not poller.poll(0):
            # Only this pinned static Go CLI owns output descriptors.
            for fd in outputs:
                try: chunk=os.read(fd,4096)
                except BlockingIOError: chunk=b''
                outputs[fd].extend(chunk)
            break
    need(cli_reaped and os.waitstatus_to_exitcode(status)==0 and bytes(outputs[out_r]).strip()==b'CheckpointRecoveryComplete')
    complete=True
except BaseException:
    pass
finally:
    if cli is not None and not cli_reaped:
        try:
            if cli_fd is not None: signal.pidfd_send_signal(cli_fd,signal.SIGKILL)
            cli_reaped=reap(cli,5) is not None
        except BaseException: pass
    if directory is not None:
        try: write_receipt('root-done.json',{'nonce':caller['nonce'],'cli_started':cli is not None,
            'cli_pid':cli,'cli_start':cli_start,'cli_reaped':cli_reaped,'complete':complete})
        except BaseException: complete=False
    if complete: print('CheckpointRecoveryComplete',flush=True)
    else: print('RecoveryChildRejected',file=sys.stderr,flush=True)
    sys.exit(0 if complete else 1)
'''


KILL_PINNED = r'''
import os,pathlib,signal,sys
pid=int(sys.argv[1]); expected=sys.argv[2]
try: fd=os.pidfd_open(pid)
except ProcessLookupError: sys.exit(0)
try:
    fields=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[-1].split()
    if len(fields)<=19 or fields[19]!=expected: sys.exit(1)
    signal.pidfd_send_signal(fd,signal.SIGKILL)
finally: os.close(fd)
'''


def kill_pinned(pin):
    if exited(pin):
        return
    result = subprocess.run(["sudo", "-n", str(Path(sys.executable).resolve()), "-c", KILL_PINNED,
        str(pin["pid"]), pin["start"]], capture_output=True, timeout=10)
    _require(result.returncode == 0)


def confirmed_termination(root, cli, done, nonce):
    if root is None or not exited(root):
        return False
    if cli is not None:
        return exited(cli)
    return isinstance(done, dict) and done.get("nonce") == nonce and done.get("cli_started") is False


def run_recovery(plan_file, raw, profile):
    """Run one fixed profile; return only after root and direct CLI terminate."""
    process = None
    root = cli = done = None
    wrapper = None
    nonce = uuid.uuid4().hex
    plan_file = Path(plan_file)
    caller = None
    directory = plan_file.parent
    try:
        caller = {"pid": os.getpid(), "start": process_identity(os.getpid())["start"], "uid": os.getuid(), "gid": os.getgid(), "nonce": nonce}
        _require(plan_file.resolve() == plan_file and not plan_file.is_symlink() and plan_file.read_bytes() == raw)
        _require(all(not (directory / name).exists() for name in ("root-ready.json", "root-go", "cli-ready.json", "cli-go", "root-done.json")))
        code = driver_source(profile)
        command = ["sudo", "-n", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1",
            str(Path(sys.executable).resolve()), "-c", code, str(plan_file), hashlib.sha256(raw).hexdigest(), json.dumps(caller, separators=(",", ":"))]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wrapper = process_identity(process.pid)
        deadline = time.monotonic() + 340
        ready_deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if root is None:
                ready = _receipt(directory / "root-ready.json")
                if ready is not None:
                    root = pin_receipt(ready, caller, nonce)
                    _gate(directory / "root-go", nonce)
                elif process.poll() is not None or time.monotonic() >= ready_deadline:
                    raise RecoveryProcessError(False)
            if root is not None and cli is None:
                ready = _receipt(directory / "cli-ready.json")
                if ready is not None:
                    cli = pin_receipt(ready, caller, nonce, parent=root)
                    _gate(directory / "cli-go", nonce)
            if root is not None and exited(root):
                done = _receipt(directory / "root-done.json")
                break
            time.sleep(.03)
        else:
            raise RecoveryProcessError(False)
        out, err = process.communicate(timeout=5)
        _require(confirmed_termination(root, cli, done, nonce))
        _require(process.returncode == 0 and out.strip() == b"CheckpointRecoveryComplete" and isinstance(done, dict)
            and done.get("nonce") == nonce and done.get("complete") is True and done.get("cli_reaped") is True
            and cli is not None and done.get("cli_pid") == cli["pid"] and done.get("cli_start") == cli["start"])
        return {"checkpointRecoveryComplete": True, "terminationConfirmed": True,
            "hostNetworkAndDNSChanged": False, "production": False}
    except BaseException:
        # Never signal a discovered name/global group. These pins came only from
        # a nonce-bound root receipt and the exact caller ancestry checks.
        try:
            if root is not None: kill_pinned(root)
            if cli is not None: kill_pinned(cli)
            if process is not None:
                try: process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    if wrapper is not None:
                        fd = os.pidfd_open(wrapper["pid"])
                        try: kill_pinned({**wrapper, "fd": fd})
                        finally: os.close(fd)
                    process.communicate(timeout=5)
            end = time.monotonic() + 5
            while any(pin is not None and not exited(pin) for pin in (root, cli)) and time.monotonic() < end: time.sleep(.03)
            if done is None: done = _receipt(directory / "root-done.json")
            confirmed = confirmed_termination(root, cli, done, nonce)
            if process is None: confirmed = True
        except BaseException:
            confirmed = False
        raise RecoveryProcessError(confirmed) from None
    finally:
        for pin in (root, cli):
            if pin is not None: os.close(pin["fd"])
