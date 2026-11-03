"""Fixed d328 recovery in explicit remote-kind netns; root child only.

The old WSL profile and 960d proof remain unchanged. This fixed profile checks
same-host creator provenance before each FD guard and shares pidfd supervision.
"""

import json
from pathlib import Path
import re
import struct
import uuid

from app_modes import require
from fixture import canonical
from helm_lifecycle import private_exact
from kind_recovery import NET_JOIN, cleanup_sandbox, database_resolver, recovery_kubeconfig
from prepare import NODE
from recovery_process import run_recovery
from remote_kind_capability import Capability, digest, read

CLI_SHA256 = "641c2670ab103579ecb051f50f69fe9597b401b12093b5edf2a2b641422a6cc8"
IMAGE_DIGEST = "sha256:d328c35df0557ace446628172658d463e05eae0afeb2c11d283f090a80b21652"


def verified_cli(panel):
    expected = panel.task / "tools" / "sekvyr-checkpoint-recovery"
    require(panel.recovery_executable == expected and expected.is_file() and not expected.is_symlink()
        and expected.resolve() == expected and expected.stat().st_uid == 0, "Exact private remote-kind recovery executable required")
    _, proof = read(panel.task / "private" / "recovery-binary.json")
    require(set(proof) == {"image", "sha256"} and proof["sha256"] == CLI_SHA256
        and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@" + re.escape(IMAGE_DIGEST), proof["image"]), "Remote-kind CLI proof differs from fixed reviewed image")
    with expected.open("rb") as stream:
        raw = stream.read((128 << 20) + 1)
    require(64 <= len(raw) <= 128 << 20 and digest(raw) == CLI_SHA256 and raw[:6] == b"\x7fELF\x02\x01"
        and struct.unpack_from("<H", raw, 18)[0] == 62, "Remote-kind static amd64 CLI hash differs")
    offset, size, count = struct.unpack_from("<Q", raw, 32)[0], struct.unpack_from("<H", raw, 54)[0], struct.unpack_from("<H", raw, 56)[0]
    require(0 < count <= 128 and size >= 56 and offset + count * size <= len(raw)
        and all(struct.unpack_from("<I", raw, offset + index * size)[0] not in (2, 3) for index in range(count)), "Remote-kind CLI requires dynamic loader")
    return raw


ROOT_SETUP = NET_JOIN + "\nEXPECTED_NODE=" + repr(NODE) + "\nEXPECTED_CLI_SHA256=" + repr(CLI_SHA256) + "\n" + r'''
import hashlib,json,os,pathlib,re,stat,subprocess
def root_setup(p):
    def private(path):
        f=pathlib.Path(path); s=f.lstat()
        need(f.resolve()==f and stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=8388608)
        return f.read_bytes()
    def docker(*args):
        r=subprocess.run(['/usr/bin/docker','--host=unix:///var/run/docker.sock',*args],capture_output=True,timeout=10)
        need(r.returncode==0 and len(r.stdout)<=8388608)
        return r.stdout
    def start(pid):
        f=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[-1].split()
        need(len(f)>19 and f[19].isdigit() and f[0] not in ('Z','X'))
        return f[19]
    def guard():
        marker=pathlib.Path(p['capabilityPath']); candidate=marker.parent.parent
        need(candidate.parent==pathlib.Path('/var/tmp') and re.fullmatch(r'sekvyr-stage7\.[0-9a-f]{8}',candidate.name) and marker==candidate/'private'/'remote-kind-capability.json')
        raw=private(marker); need(hashlib.sha256(raw).hexdigest()==p['capabilitySHA256']); cap=json.loads(raw)
        task=pathlib.Path(cap['runtimeTask']); root=pathlib.Path(cap['rootTask']); backup=root/'private'/'creator'
        need(cap['format']=='sekvyr-stage7-remote-kind-v1' and task.parent==pathlib.Path('/var/tmp') and re.fullmatch(r'sekvyr-stage7\.[0-9a-f]{8}',task.name))
        sandbox=pathlib.Path(p['sandbox'])
        need(sandbox.parent==task/'private' and re.fullmatch(r'kind-recovery-[0-9a-f]{32}',sandbox.name))
        need(p['files']['bin/sekvyr-checkpoint-recovery']==EXPECTED_CLI_SHA256)
        need(root.parent==pathlib.Path('/opt/sekvyr-trial') and re.fullmatch(r'sekvyr-stage7-[0-9]{8}-[0-9a-f]{8}',root.name))
        need(p['capabilityPath']==str(task/'private'/'remote-kind-capability.json') and p['nodePinPath']==str(task/'private'/'node-pin.json'))
        for key,name in (('preflight','preflight.json'),('creator','creation.json'),('caps','caps.json')):
            need(p[key+'Path']==str(backup/name) and cap[key+'SHA256']==p[key+'SHA256'])
        for key in ('preflight','creator','caps','nodePin'):
            need(hashlib.sha256(private(p[key+'Path'])).hexdigest()==p[key+'SHA256'])
        pre=json.loads(private(p['preflightPath'])); made=json.loads(private(p['creatorPath'])); limits=json.loads(private(p['capsPath']))
        need(made['preflightSHA256']==cap['preflightSHA256'] and limits['creatorSHA256']==cap['creatorSHA256'])
        need(pre['runtimeTask']==str(task) and pre['rootTask']==str(root) and pre['clusterName']=='sekvyr-stage7-'+task.name.split('.')[1])
        receipt=root/'receipts'/'root-task-create.json'; s=receipt.lstat()
        need(receipt.resolve()==receipt and stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and s.st_size<=8192)
        raw=receipt.read_bytes(); need(hashlib.sha256(raw).hexdigest()==pre['rootCreationReceiptSHA256']); original=json.loads(raw); rootstat=root.lstat()
        need(original['format']=='sekvyr-stage7-root-task-creation-v1' and original['path']==str(root) and original['runtimeProposed']==str(task))
        need(original['uid']==original['gid']==0 and (original['dev'],original['ino'])==(rootstat.st_dev,rootstat.st_ino) and original['containerCreated'] is False and original['production'] is False)
        for pin,path in zip(pre['directories'],(root,task,backup)):
            s=path.lstat(); need(path.resolve()==path and stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==0)
            need(pin=={'path':str(path),'uid':0,'dev':s.st_dev,'ino':s.st_ino})
        need(len(pre['directories'])==3 and pre['host']['bootID']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        need(pre['host']['daemonIDHash']==hashlib.sha256(docker('info','--format={{.ID}}').strip()).hexdigest())
        pin=json.loads(private(p['nodePinPath'])); need(pin==made['node'] and pin['id'] not in pre['baseline']['containers'])
        values=json.loads(docker('inspect',pin['id'])); need(len(values)==1); v=values[0]
        need(v['Id']==pin['id'] and v['Config']['Image']==pre['nodeImage'] and v['State']['Running'] and v['State']['Pid']==made['process']['pid']==p['pid'])
        need(start(p['pid'])==made['process']['starttime']==p['starttime'])
        need(v['Config']['Labels'].get('io.x-k8s.kind.cluster')==pre['clusterName'] and v['Config']['Labels'].get('io.x-k8s.kind.role')=='control-plane')
        need(limits['limits']==pre['limits']=={'NanoCpus':4000000000,'Memory':8589934592,'MemorySwap':8589934592})
        need(all(v['HostConfig'].get(k)==n for k,n in limits['limits'].items()))
        def encoded(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        need(v['Name']==made['nodeName'] and hashlib.sha256(encoded(v['Config'])).hexdigest()==made['configSHA256'])
        need(hashlib.sha256(encoded(sorted(v.get('Mounts',[]),key=encoded))).hexdigest()==made['mountsSHA256'] and hashlib.sha256(encoded(v['HostConfig'])).hexdigest()==limits['hostConfigSHA256'])
        need(sorted(m['Name'] for m in v.get('Mounts',[]) if m.get('Type')=='volume')==sorted(pin['volumes']))
        need(set(v['NetworkSettings']['Networks'])=={'kind'} and v['NetworkSettings']['Networks']['kind']['NetworkID']==made['network']['id'])
        networks=json.loads(docker('network','inspect',made['network']['id'])); need(len(networks)==1)
        net=networks[0]; normalized={k:n for k,n in net.items() if k!='Containers'}
        need(net['Id']==made['network']['id'] and set(net.get('Containers',{}))=={pin['id']})
        need(hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==made['network']['configSHA256'])
        images=json.loads(docker('image','inspect',pre['nodeImage'])); need(len(images)==1 and images[0]['Id']==made['nodeOCIImageID']==v['Image'])
        need(pre['nodeImage']==p['image']==EXPECTED_NODE)
        repository=p['image'].split('@')[0].rsplit(':',1)[0]+'@'+p['image'].split('@')[1]
        need(any(x in (repository,'docker.io/'+repository) for x in images[0].get('RepoDigests',[])))
    join_network(p,guard)
'''


def _recover(panel, plan, envelope, wrapper, installation):
    owner = Capability(panel.cluster)
    require(panel.task == owner.task and installation.get("namespace") in panel.cluster.namespaces
        and isinstance(installation.get("ha"), dict), "Explicit owned remote-kind HA installation required")
    signed = json.loads(plan) if isinstance(plan, bytes) else plan
    require(type(signed.get("body", {}).get("allow_rollout")) is bool, "Explicit signed recovery rollout choice required")
    binary = verified_cli(panel)
    kube = recovery_kubeconfig(panel.cluster.config.read_bytes(), owner.exec("cat", "/etc/kubernetes/admin.conf"))
    resolv = database_resolver(panel)
    owner.guard()
    sandbox = owner.task / "private" / ("kind-recovery-" + uuid.uuid4().hex)
    sandbox.mkdir(mode=0o700)
    identity = sandbox.stat()
    for folder in ("bin", "inputs", "etc", "tmp"):
        (sandbox / folder).mkdir(mode=0o700)
    files = {"bin/sekvyr-checkpoint-recovery": binary, "etc/resolv.conf": resolv, "etc/hosts": b"127.0.0.1 localhost\n::1 localhost\n",
        "inputs/kubeconfig": kube, "inputs/plan.json": plan if isinstance(plan, bytes) else canonical(plan),
        "inputs/envelope.json": envelope if isinstance(envelope, bytes) else canonical(envelope),
        "inputs/reader-wrap.json": wrapper if isinstance(wrapper, bytes) else canonical(wrapper), "inputs/installation.json": canonical(installation)}
    confirmed = True
    try:
        for name, raw in files.items():
            private_exact(sandbox / name, raw)
        (sandbox / "bin" / "sekvyr-checkpoint-recovery").chmod(0o500)
        body = {"sandbox": str(sandbox), "sandboxIdentity": [identity.st_dev, identity.st_ino], **owner.root_plan(),
            **owner.creator["process"], "image": NODE, "files": {name: digest(raw) for name, raw in files.items()}, "allowRollout": signed["body"]["allow_rollout"]}
        raw = canonical(body)
        private_exact(sandbox / "launch.json", raw)
        confirmed = False
        try:
            result = run_recovery(sandbox / "launch.json", raw, profile="remote-kind")
        except BaseException as error:
            confirmed = getattr(error, "termination_confirmed", False) is True
            raise
        confirmed = result.get("terminationConfirmed") is True
        if not confirmed:
            failure = RuntimeError("Remote-kind child termination not confirmed")
            failure.termination_confirmed = False
            raise failure
        return result
    finally:
        cleanup_sandbox(owner.task, sandbox, (identity.st_dev, identity.st_ino), confirmed)


def recover(panel, plan, envelope, wrapper, installation):
    try:
        return _recover(panel, plan, envelope, wrapper, installation)
    except Exception as error:
        safe = RuntimeError("Verified remote-kind recovery rejected")
        if type(getattr(error, "termination_confirmed", None)) is bool:
            safe.termination_confirmed = error.termination_confirmed
        raise safe from None
