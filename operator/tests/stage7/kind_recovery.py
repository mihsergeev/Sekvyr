"""Native verified recovery CLI in only the creator-pinned kind network.

Only a root CHILD calls setns/chroot. No admin credential enters a Pod, argv,
environment or output. The parent never joins namespaces or changes host DNS.
https://docs.python.org/3.12/library/os.html#os.setns
https://man7.org/linux/man-pages/man7/namespaces.7.html
"""

import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import struct
import uuid

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app_modes import require
from fixture import safe_task
from helm_lifecycle import canonical, private_exact
from kind_jwks import KindJWKS, native_path
from prepare import NODE, CLUSTER

CLI_SHA256 = "753306b063061e53cd471d01029fa2ee09ef2f73c1eb5634b3062cdc8fa40e3a"
IMAGE_DIGEST = "sha256:960d66695ae8faf3f020a83e183e3b17a3efde9091f393c525351e2ebe4ef881"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def starttime(pid):
    raw = (Path("/proc") / str(pid) / "stat").read_text()
    fields = raw.rsplit(")", 1)[-1].split()
    require(len(fields) > 19 and fields[19].isdigit() and fields[0] not in ("Z", "X"), "Owned process start time unavailable")
    return fields[19]


class OwnedNode(KindJWKS):
    """Reuse only creator guard/exec, without any JWKS preparation side effect."""
    def __init__(self, cluster):
        self.cluster, self.task = cluster, safe_task(cluster.task)
        require(self.task.parent == Path("/var/tmp"), "Recovery network adapter is only for owned local kind")
        self.pin_file = self.task / "private" / "node-pin.json"
        require(not self.pin_file.is_symlink(), "Unsafe node pin")
        self.pin_raw = self.pin_file.read_bytes()
        self.pin = json.loads(self.pin_raw)
        require(self.pin.get("image") == NODE and re.fullmatch(r"[0-9a-f]{64}", self.pin.get("id", "")), "Exact kind creator pin required")
        reference = self.task / "private" / "native-backup-reference.json"
        require(not reference.is_symlink(), "Unsafe native receipt reference")
        value = json.loads(reference.read_bytes())
        require(set(value) == {"path"}, "Explicit native creation receipt required")
        self.creation_receipt = Path(value["path"]).absolute()
        native_path(self.creation_receipt.parent)
        require(self.creation_receipt.resolve() == self.creation_receipt and not self.creation_receipt.is_symlink(), "Unsafe native creation receipt")
        self.creation_raw = self.creation_receipt.read_bytes()
        native = json.loads(self.creation_raw)
        require(native["taskDirectory"] == str(self.task) and native["node"] == self.pin
            and native["fixture"]["namespaces"] == cluster.fixture["namespaces"], "Recovery native creator receipt differs")

    def process(self):
        self.guard()
        value = json.loads(self._docker("inspect", self.pin["id"]))[0]
        pid = value["State"]["Pid"]
        require(type(pid) is int and 1 < pid <= 2147483647 and value["Id"] == self.pin["id"] and value["State"]["Running"], "Owned node PID unavailable")
        return {"pid": pid, "starttime": starttime(pid)}


def _decode_config(raw):
    require(0 < len(raw) <= 128 << 10, "Recovery kubeconfig exceeds bounds")
    value = yaml.safe_load(raw)
    require(isinstance(value, dict) and value.get("apiVersion") == "v1" and value.get("kind") == "Config"
        and all(isinstance(value.get(key), list) and len(value[key]) == 1 for key in ("clusters", "users", "contexts")), "Recovery kubeconfig must have one exact context")
    cluster, user, context = value["clusters"][0], value["users"][0], value["contexts"][0]
    require(set(cluster) == {"name", "cluster"} and set(user) == {"name", "user"} and set(context) == {"name", "context"}
        and value.get("current-context") == context["name"] and context["context"].get("cluster") == cluster["name"]
        and context["context"].get("user") == user["name"] and set(context["context"]).issubset({"cluster", "user", "namespace"}), "Recovery kubeconfig context is ambiguous")
    require(set(cluster["cluster"]) == {"server", "certificate-authority-data"}
        and set(user["user"]) == {"client-certificate-data", "client-key-data"}, "Only embedded CA and client certificate credentials are permitted")
    decode = lambda field: base64.b64decode(field, validate=True)
    ca = x509.load_pem_x509_certificates(decode(cluster["cluster"]["certificate-authority-data"]))
    cert = x509.load_pem_x509_certificates(decode(user["user"]["client-certificate-data"]))
    key = serialization.load_pem_private_key(decode(user["user"]["client-key-data"]), None)
    spki = lambda public: public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(ca and len(cert) == 1 and spki(cert[0].public_key()) == spki(key.public_key()), "Recovery client certificate/private key mismatch")
    fingerprint = {"ca": sorted(set(item.public_bytes(serialization.Encoding.DER) for item in ca)),
        "certificate": cert[0].public_bytes(serialization.Encoding.DER), "publicKey": spki(key.public_key())}
    return value, fingerprint


def _config(raw):
    try:
        return _decode_config(raw)
    except Exception:
        # YAML/PEM parser errors can quote the input's credential-bearing line.
        raise RuntimeError("Recovery kubeconfig invalid") from None


def recovery_kubeconfig(host, own_admin):
    value, identity = _config(host)
    _, actual_identity = _config(own_admin)
    require(identity == actual_identity, "Recovery credentials do not match the creator-pinned node admin.conf")
    import urllib.parse
    origin = urllib.parse.urlsplit(value["clusters"][0]["cluster"]["server"])
    require(origin.scheme == "https" and origin.hostname == "127.0.0.1" and origin.port and not origin.username and not origin.password
        and not origin.path and not origin.query and not origin.fragment, "Host kubeconfig must target only the local kind API")
    # No proxy, TLS downgrade, credential helper or untrusted path survives.
    value["clusters"][0]["cluster"]["server"] = "https://127.0.0.1:6443"
    return yaml.safe_dump(value, sort_keys=False).encode()


def verified_cli(panel):
    executable = Path(panel.recovery_executable) if panel.recovery_executable else None
    expected = panel.task / "tools" / "sekvyr-checkpoint-recovery"
    require(executable == expected and expected.is_absolute() and expected.resolve() == expected and expected.is_file()
        and not expected.is_symlink(), "Exact private recovery binary required")
    proof_path = panel.task / "private" / "recovery-binary.json"
    require(not proof_path.is_symlink(), "Unsafe recovery binary proof")
    proof = json.loads(proof_path.read_bytes())
    require(set(proof) == {"image", "sha256"} and proof["sha256"] == CLI_SHA256
        and isinstance(proof["image"], str) and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@" + re.escape(IMAGE_DIGEST), proof["image"]), "Recovery binary proof is not the independently reviewed image")
    with expected.open("rb") as stream:
        raw = stream.read((128 << 20) + 1)
    require(64 <= len(raw) <= 128 << 20 and sha(raw) == CLI_SHA256, "Recovery binary hash differs from reviewed static CLI")
    require(raw[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", raw, 18)[0] == 62, "Recovery CLI must be Linux amd64 ELF")
    offset, entry_size, count = struct.unpack_from("<Q", raw, 32)[0], struct.unpack_from("<H", raw, 54)[0], struct.unpack_from("<H", raw, 56)[0]
    require(0 < count <= 128 and entry_size >= 56 and offset + count * entry_size <= len(raw), "Recovery ELF headers invalid")
    require(all(struct.unpack_from("<I", raw, offset + index * entry_size)[0] not in (2, 3) for index in range(count)), "Recovery CLI must not need a loader or shared libraries")
    return raw


def database_resolver(panel):
    deployment = panel.get("Deployment", "database")
    selector = deployment["spec"]["selector"]
    require(set(selector) == {"matchLabels"} and selector["matchLabels"], "Owned database selector is ambiguous")
    label = ",".join(key + "=" + value for key, value in sorted(selector["matchLabels"].items()))
    candidates = json.loads(panel.cluster.kube("get", "pods", "-n", panel.namespace, "-l", label, "-o", "json").stdout)["items"]
    candidates = [pod for pod in candidates if not pod["metadata"].get("deletionTimestamp") and any(item.get("type") == "Ready" and item.get("status") == "True" for item in pod.get("status", {}).get("conditions", []))]
    require(len(candidates) == 1, "Owned database Pod is not unique and ready")
    pod = candidates[0]
    refs = [ref for ref in pod["metadata"].get("ownerReferences", []) if ref.get("kind") == "ReplicaSet" and ref.get("controller") is True]
    require(len(refs) == 1, "Database Pod lacks one ReplicaSet owner")
    replica = json.loads(panel.cluster.kube("get", "replicaset", refs[0]["name"], "-n", panel.namespace, "-o", "json").stdout)
    require(replica["metadata"]["uid"] == refs[0]["uid"] and any(ref.get("kind") == "Deployment" and ref.get("controller") is True
        and ref.get("uid") == deployment["metadata"]["uid"] for ref in replica["metadata"].get("ownerReferences", [])), "Database owner chain changed")
    raw = panel.cluster.kube("exec", pod["metadata"]["name"], "-n", panel.namespace, "-c", "database", "--", "cat", "/etc/resolv.conf").stdout.encode()
    after = json.loads(panel.cluster.kube("get", "pod", pod["metadata"]["name"], "-n", panel.namespace, "-o", "json").stdout)
    require(after["metadata"]["uid"] == pod["metadata"]["uid"] and after["metadata"].get("ownerReferences") == pod["metadata"].get("ownerReferences")
        and not after["metadata"].get("deletionTimestamp"), "Database Pod replaced during DNS read")
    require(0 < len(raw) < 16384, "Recovery DNS exceeds bounds")
    servers = []
    for line in raw.decode("ascii").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        require(fields[0] in ("nameserver", "search", "options"), "Unexpected database resolver directive")
        if fields[0] == "nameserver":
            require(len(fields) == 2, "Invalid database nameserver")
            address = ipaddress.ip_address(fields[1])
            require(not (address.is_loopback or address.is_unspecified or address.is_multicast), "Database DNS must address the owned cluster resolver")
            servers.append(address)
        else:
            require(all(re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", value) for value in fields[1:]), "Unsafe database resolver option")
    require(1 <= len(servers) <= 3, "Owned cluster DNS nameserver unavailable")
    return raw


NET_JOIN = r'''
def join_network(p,guard):
    guard()
    net='/proc/'+str(p['pid'])+'/ns/net'
    before=os.stat(net)
    fd=os.open(net,os.O_RDONLY|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd); after=os.stat(net)
        need((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino)==(after.st_dev,after.st_ino))
        guard()
        again=os.stat(net)
        need((again.st_dev,again.st_ino)==(opened.st_dev,opened.st_ino))
        need(hasattr(os,'setns') and hasattr(os,'CLONE_NEWNET'))
        guard()
        final=os.stat(net)
        need((final.st_dev,final.st_ino)==(opened.st_dev,opened.st_ino))
        os.setns(fd,os.CLONE_NEWNET)
        current=os.stat('/proc/self/ns/net')
        need((current.st_dev,current.st_ino)==(opened.st_dev,opened.st_ino))
    finally:
        os.close(fd)
'''

ROOT_SETUP = NET_JOIN + r'''
import hashlib,json,os,pathlib,subprocess

def need(value):
    if not value: raise RuntimeError('RecoveryNetworkGuardRejected')

def root_setup(p):
    def filehash(path):
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    def start(pid):
        fields=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[-1].split()
        need(len(fields)>19 and fields[19].isdigit() and fields[0] not in ('Z','X'))
        return fields[19]
    def docker(*args):
        value=subprocess.run(['/usr/bin/docker','--host=unix:///var/run/docker.sock',*args],capture_output=True,timeout=10)
        need(value.returncode==0 and len(value.stdout)<=2097152)
        return json.loads(value.stdout)
    def guard():
        need(filehash(p['nodePinPath'])==p['nodePinHash'] and filehash(p['nativeReceiptPath'])==p['nativeReceiptHash'])
        objects=docker('inspect',p['cid']); need(len(objects)==1)
        value=objects[0]; labels=value['Config'].get('Labels',{})
        need(value['Id']==p['cid'] and value['State']['Running'] and value['State']['Pid']==p['pid'] and
             value['Config']['Image']==p['image'] and labels.get('io.x-k8s.kind.cluster')==p['cluster'] and
             labels.get('io.x-k8s.kind.role')=='control-plane' and start(p['pid'])==p['starttime'])
        images=docker('image','inspect',p['image'])
        need(len(images)==1 and images[0]['Id']==value['Image'] and
             any(item in p['imageRepoDigests'] for item in images[0].get('RepoDigests',[])))
    join_network(p,guard)
'''


def launch_child(plan_file, raw):
    from recovery_process import run_recovery
    return run_recovery(plan_file, raw, profile='kind')


def cleanup_sandbox(task, sandbox, identity, termination_confirmed):
    if termination_confirmed is not True:
        return False
    require(sandbox.resolve() == sandbox and not sandbox.is_symlink() and sandbox.parent == task / "private"
        and re.fullmatch(r"kind-recovery-[0-9a-f]{32}", sandbox.name)
        and (sandbox.stat().st_dev, sandbox.stat().st_ino) == identity, "Recovery sandbox cleanup identity changed")
    shutil.rmtree(sandbox)
    return True



def _recover(panel, plan, envelope, wrapper, installation):
    task = safe_task(panel.task)
    require(task.parent == Path("/var/tmp") and panel.cluster.task == task, "Recovery adapter is only for the explicit local kind")
    require(installation["namespace"] in panel.cluster.namespaces and installation.get("ha") is not None, "Explicit owned HA recovery configuration required")
    signed_plan = json.loads(plan) if isinstance(plan, bytes) else plan
    require(isinstance(signed_plan, dict) and isinstance(signed_plan.get("body"), dict)
        and type(signed_plan["body"].get("allow_rollout")) is bool, "Explicit signed recovery rollout choice required")
    node = OwnedNode(panel.cluster)
    identity = node.process()
    binary = verified_cli(panel)
    kube = recovery_kubeconfig(panel.cluster.config.read_bytes(), node._exec("cat", "/etc/kubernetes/admin.conf"))
    resolv = database_resolver(panel)
    node.guard()
    require(node.process() == identity, "Owned node process changed before recovery")
    sandbox = task / "private" / ("kind-recovery-" + uuid.uuid4().hex)
    sandbox.mkdir(mode=0o700)
    info = sandbox.stat()
    for name in ("bin", "inputs", "etc", "tmp"):
        (sandbox / name).mkdir(mode=0o700)
    values = {"bin/sekvyr-checkpoint-recovery": binary, "etc/resolv.conf": resolv, "etc/hosts": b"127.0.0.1 localhost\n::1 localhost\n",
        "inputs/kubeconfig": kube, "inputs/plan.json": plan if isinstance(plan, bytes) else canonical(plan),
        "inputs/envelope.json": envelope if isinstance(envelope, bytes) else canonical(envelope),
        "inputs/reader-wrap.json": wrapper if isinstance(wrapper, bytes) else canonical(wrapper),
        "inputs/installation.json": canonical(installation)}
    cleanup_allowed = True
    try:
        for name, raw in values.items():
            private_exact(sandbox / name, raw)
        (sandbox / "bin" / "sekvyr-checkpoint-recovery").chmod(0o500)
        repository = NODE.split("@", 1)[0].rsplit(":", 1)[0] + "@" + NODE.split("@", 1)[1]
        body = {"sandbox": str(sandbox), "sandboxIdentity": [info.st_dev, info.st_ino], "cid": node.pin["id"], "image": NODE,
            "imageRepoDigests": [repository, "docker.io/" + repository], "cluster": CLUSTER, **identity,
            "nodePinPath": str(node.pin_file), "nodePinHash": sha(node.pin_raw), "nativeReceiptPath": str(node.creation_receipt),
            "nativeReceiptHash": sha(node.creation_raw), "files": {name: sha(raw) for name, raw in values.items()},
            "allowRollout": signed_plan["body"]["allow_rollout"]}
        raw = canonical(body)
        private_exact(sandbox / "launch.json", raw)
        cleanup_allowed = False
        try:
            result = launch_child(sandbox / "launch.json", raw)
        except Exception as error:
            cleanup_allowed = getattr(error, "termination_confirmed", False) is True
            raise
        cleanup_allowed = result.get("terminationConfirmed") is True
        if not cleanup_allowed:
            error = RuntimeError("Recovery child termination was not confirmed; private inputs retained")
            error.termination_confirmed = False
            raise error
        return result
    finally:
        cleanup_sandbox(task, sandbox, (info.st_dev, info.st_ino), cleanup_allowed)


def recover(panel, plan, envelope, wrapper, installation):
    try:
        if panel is not None and hasattr(panel, "task"):
            marker = Path(panel.task) / "private" / "remote-kind-capability.json"
            if marker.exists() or marker.is_symlink():
                from remote_kind_recovery import recover as remote_recover
                return remote_recover(panel, plan, envelope, wrapper, installation)
        return _recover(panel, plan, envelope, wrapper, installation)
    except Exception as error:
        confirmed = getattr(error, "termination_confirmed", None)
        if confirmed is False:
            safe = RuntimeError("Recovery child termination unconfirmed; private inputs retained")
        else:
            safe = RuntimeError("Verified kind checkpoint recovery rejected")
        if type(confirmed) is bool:
            safe.termination_confirmed = confirmed
        # Never forward YAML/JSON/PEM/subprocess errors that can quote secrets.
        raise safe from None
