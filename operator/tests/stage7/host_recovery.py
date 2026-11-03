"""Recovery in one explicit remote trial, with private child-only DNS/chroot.

The original kubeconfig bytes and TLS identity are preserved. No namespace join,
host resolver change, credential argument, Pod, deployment or implicit reset.
"""

import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import urllib.parse
import uuid

from app_modes import OwnedNamespace, require
from fixture import safe_task
from helm_lifecycle import canonical, private_exact
from kind_recovery import _config, database_resolver, verified_cli, CLI_SHA256
from recovery_process import RecoveryProcessError, run_recovery


REMOTE_VERSION = "v1.34.1+k0s"


ROOT_SETUP = r'''
import hashlib,json,pathlib,re
def root_setup(p):
    task=pathlib.Path(p['task'])
    need(task.parent==pathlib.Path('/opt/sekvyr-trial') and task.resolve()==task and
        re.fullmatch(r'sekvyr-stage7-[0-9]{8}-[0-9a-f]{8}',task.name))
    original=task/'kubeconfig'; proof=task/'private'/'host-recovery-pin.json'
    need(not original.is_symlink() and original.resolve()==original and not proof.is_symlink() and proof.resolve()==proof)
    need(filehash(original)==p['kubeconfigSHA256'] and filehash(proof)==p['hostPinSHA256'])
    pin=json.loads(proof.read_bytes())
    need(pin['serverVersion']=='v1.34.1+k0s' and pin['kubeconfigSHA256']==p['kubeconfigSHA256'])
    need(filehash(pathlib.Path(p['sandbox'])/'inputs'/'kubeconfig')==p['kubeconfigSHA256'])
'''


def host_pin(panel):
    task = safe_task(panel.task)
    require(task.parent == Path("/opt/sekvyr-trial") and panel.cluster.task == task,
        "Remote recovery requires its explicit stage7 task")
    params = task / "infrastructure-parameters.json"
    require(params.is_file() and not params.is_symlink(), "Explicit remote infrastructure review required")
    reviewed = json.loads(params.read_bytes())
    require(reviewed.get("expected_kubernetes") == REMOTE_VERSION, "Remote Kubernetes version differs from reviewed trial")
    actual = json.loads(panel.cluster.kube("version", "-o", "json").stdout)
    require(actual["serverVersion"]["gitVersion"] == REMOTE_VERSION, "Remote live Kubernetes version changed")
    pins = panel.cluster.namespace_pins()
    require(len(pins) == 6 and set(pins) == panel.cluster.namespaces and panel.namespace in pins,
        "Exact six owned trial namespaces required")
    for namespace in sorted(pins):
        OwnedNamespace(panel.cluster, namespace).guard()
    config = task / "kubeconfig"
    require(panel.cluster.config == config and config.resolve() == config and config.is_file() and not config.is_symlink()
        and stat.S_IMODE(config.stat().st_mode) & 0o077 == 0, "Explicit private original kubeconfig required")
    raw = config.read_bytes()
    value, _ = _config(raw)
    origin = urllib.parse.urlsplit(value["clusters"][0]["cluster"]["server"])
    require(origin.scheme == "https" and origin.hostname and not origin.username and not origin.password
        and not origin.path and not origin.query and not origin.fragment and not origin.netloc.endswith(":"),
        "Original recovery API must retain strict HTTPS")
    # This is the administratively supplied original private config, not a key
    # learned from an incoming API response. Namespaces have CREATE-time pins.
    pin = {"serverVersion": REMOTE_VERSION, "kubeconfigSHA256": hashlib.sha256(raw).hexdigest(),
        "namespaceUIDs": pins, "cliSHA256": CLI_SHA256}
    path = task / "private" / "host-recovery-pin.json"
    private_exact(path, canonical(pin))
    return raw, pin, path


def cleanup_sandbox(task, sandbox, identity, confirmed):
    if confirmed is not True:
        return False
    require(sandbox.parent == task / "private" and sandbox.resolve() == sandbox and not sandbox.is_symlink()
        and re.fullmatch(r"host-recovery-[0-9a-f]{32}", sandbox.name)
        and (sandbox.stat().st_dev, sandbox.stat().st_ino) == identity, "Remote recovery cleanup identity changed")
    shutil.rmtree(sandbox)
    return True


def _recover(panel, plan, envelope, wrapper, installation):
    kube, pin, pin_path = host_pin(panel)
    require(isinstance(installation, dict) and installation.get("namespace") in pin["namespaceUIDs"]
        and isinstance(installation.get("ha"), dict), "Explicit owned HA recovery installation required")
    signed = json.loads(plan) if isinstance(plan, bytes) else plan
    require(isinstance(signed, dict) and isinstance(signed.get("body"), dict)
        and type(signed["body"].get("allow_rollout")) is bool, "Explicit signed recovery rollout choice required")
    binary = verified_cli(panel)
    resolv = database_resolver(panel)
    # Revalidate the exact config, server and namespace UIDs after the DNS read.
    require(host_pin(panel)[1] == pin, "Remote recovery identity changed during preparation")
    task = panel.task
    sandbox = task / "private" / ("host-recovery-" + uuid.uuid4().hex)
    sandbox.mkdir(mode=0o700)
    info = sandbox.stat()
    confirmed = True
    try:
        for name in ("bin", "inputs", "etc", "tmp"):
            (sandbox / name).mkdir(mode=0o700)
        values = {"bin/sekvyr-checkpoint-recovery": binary, "etc/resolv.conf": resolv,
            "etc/hosts": b"127.0.0.1 localhost\n::1 localhost\n", "inputs/kubeconfig": kube,
            "inputs/plan.json": plan if isinstance(plan, bytes) else canonical(plan),
            "inputs/envelope.json": envelope if isinstance(envelope, bytes) else canonical(envelope),
            "inputs/reader-wrap.json": wrapper if isinstance(wrapper, bytes) else canonical(wrapper),
            "inputs/installation.json": canonical(installation)}
        for name, raw in values.items():
            private_exact(sandbox / name, raw)
        (sandbox / "bin" / "sekvyr-checkpoint-recovery").chmod(0o500)
        body = {"sandbox": str(sandbox), "sandboxIdentity": [info.st_dev, info.st_ino], "task": str(task),
            "kubeconfigSHA256": pin["kubeconfigSHA256"], "hostPinSHA256": hashlib.sha256(pin_path.read_bytes()).hexdigest(),
            "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in values.items()}, "allowRollout": signed["body"]["allow_rollout"]}
        raw = canonical(body)
        launch = sandbox / "launch.json"
        private_exact(launch, raw)
        confirmed = False
        try:
            result = run_recovery(launch, raw, profile="host")
        except Exception as error:
            confirmed = getattr(error, "termination_confirmed", False) is True
            raise
        confirmed = result.get("terminationConfirmed") is True
        require(confirmed, "Remote recovery termination unconfirmed")
        return result
    finally:
        cleanup_sandbox(task, sandbox, (info.st_dev, info.st_ino), confirmed)


def recover(panel, plan, envelope, wrapper, installation):
    try:
        return _recover(panel, plan, envelope, wrapper, installation)
    except Exception as error:
        # YAML/PEM/subprocess errors can quote private inputs. Expose no detail.
        confirmed = getattr(error, "termination_confirmed", None)
        if type(confirmed) is bool:
            raise RecoveryProcessError(confirmed) from None
        raise RuntimeError("Verified remote checkpoint recovery rejected") from None
