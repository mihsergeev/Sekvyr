"""Stage 8 fixed RC recovery; shared pidfd/netns machinery is byte-unchanged."""

import hashlib
from types import FunctionType

from app_modes import require
from fixture import canonical
from .profiles import receipt, reviewed
from .capability import Capability, fixed_function
import remote_kind_recovery as legacy
import recovery_process as supervisor

_PREFIX_SHA = "28a6e5debf45794bf8aaebe1322ad2a9d6cdc1d95233ad0232f42e013b21f719"
_BODY_SHA = "ec3b18c025d8e191293116a20538114eb5a9f256a9909137ebb5d731f5f6fd52"
_JOIN = "    join_network(p,guard)\n"

def root_setup_source(profile):
    selected, artifacts = reviewed(profile)
    old_prefix = legacy.NET_JOIN + "\nEXPECTED_NODE=" + repr(legacy.NODE) + "\nEXPECTED_CLI_SHA256=" + repr(legacy.CLI_SHA256) + "\n"
    require(hashlib.sha256(old_prefix.encode()).hexdigest() == _PREFIX_SHA
        and legacy.ROOT_SETUP.startswith(old_prefix), "Reviewed recovery template prefix changed")
    body = legacy.ROOT_SETUP[len(old_prefix):]
    require(hashlib.sha256(body.encode()).hexdigest() == _BODY_SHA and body.count(_JOIN) == 1
        and body.endswith(_JOIN), "Reviewed recovery guard body changed")
    static = receipt(selected, artifacts, "", "", "0" * 64)
    for key in ("rootTask", "runtimeTask", "rootCreationReceiptSHA256"):
        del static[key]
    extra = r'''
    original_guard=guard
    def guard():
        # Validate Stage 8 classification before ANY original Docker operation.
        marker=pathlib.Path(p['capabilityPath']); candidate=marker.parent.parent
        need(candidate.parent==pathlib.Path('/var/tmp') and re.fullmatch(r'sekvyr-stage7\.[0-9a-f]{8}',candidate.name)
            and marker==candidate/'private'/'remote-kind-capability.json')
        cap=json.loads(private(marker))
        root=pathlib.Path(cap['rootTask']); task=pathlib.Path(cap['runtimeTask'])
        need(task==candidate and root.parent==pathlib.Path('/opt/sekvyr-trial')
            and re.fullmatch(r'sekvyr-stage7-[0-9]{8}-[0-9a-f]{8}',root.name))
        need(p['preflightPath']==str(root/'private'/'creator'/'preflight.json'))
        path=root/'receipts'/'stage8-profile.json'
        need(p['stage8ProfilePath']==str(path))
        raw=private(path); need(hashlib.sha256(raw).hexdigest()==p['stage8ProfileSHA256'])
        pre=json.loads(private(p['preflightPath']))
        need(pre.get('stage8ProfileSHA256')==p['stage8ProfileSHA256'])
        expected=dict(EXPECTED_STAGE8,rootTask=str(root),runtimeTask=str(task),
            rootCreationReceiptSHA256=pre['rootCreationReceiptSHA256'])
        need(raw==json.dumps(expected,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
        original_guard()
    join_network(p,guard)
'''
    # No replacement is sourced from a live plan or caller-supplied program.
    return legacy.NET_JOIN + "\nEXPECTED_NODE=" + repr(selected.node) + "\nEXPECTED_CLI_SHA256=" + repr(artifacts["recovery_sha256"]) + "\nEXPECTED_STAGE8=" + repr(static) + "\n" + body[:-len(_JOIN)] + extra

def driver_source(profile):
    return supervisor.ROOT_PREFIX + "\n" + root_setup_source(profile) + "\n" + supervisor.ROOT_MAIN

def verified_cli(panel, *, profile):
    _, artifacts = reviewed(profile)
    proof_path = panel.task / "private" / "recovery-binary.json"
    _, proof = legacy.read(proof_path)
    require(proof == {"image": artifacts["operator_image"], "sha256": artifacts["recovery_sha256"]},
        "Exact reviewed Stage 8 recovery proof required")
    return fixed_function(legacy.verified_cli, CLI_SHA256=artifacts["recovery_sha256"],
        IMAGE_DIGEST=artifacts["operator_image"].split("@", 1)[1])(panel)

def _operation(profile):
    selected, _ = reviewed(profile)
    def run(plan_file, raw, *, profile):
        require(profile == "remote-kind", "Fixed shared recovery call required")
        def fixed_driver(requested):
            require(requested == "stage8-fixed", "Fixed Stage 8 driver required")
            return driver_source(selected.name)
        operation = fixed_function(supervisor.run_recovery, driver_source=fixed_driver)
        return operation(plan_file, raw, "stage8-fixed")
    return fixed_function(legacy._recover, NODE=selected.node,
        Capability=lambda cluster: Capability(cluster, profile=selected.name),
        verified_cli=lambda panel: verified_cli(panel, profile=selected.name), run_recovery=run)

def recover(panel, plan, envelope, wrapper, installation, *, profile):
    operation = _operation(profile)  # Pins before filesystem/sudo.
    safe_boundary = fixed_function(legacy.recover, _recover=operation)
    return safe_boundary(panel, plan, envelope, wrapper, installation)

def bind(panel, profile):
    reviewed(profile)
    def callback(plan, envelope, wrapper, installation):
        return recover(panel, plan, envelope, wrapper, installation, profile=profile)
    return callback
