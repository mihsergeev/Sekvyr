"""One live CLI E2E attempt per fresh Stage 8 capability.

Prepare the infrastructure, storage bootstrap and gateway first. Supply the
reviewed HA Helm render, its independent hash and the private API/admission
endpoint tuples. The actor does not retry a phase after a partial write.
"""

import os

from acceptance_faults import leader_pending_restart, wrong_e2e_key
from application import REVISION, TARGET, wait
from coordinator import BudgetCluster, phase
from dependency_cases import run as dependency_outages
from fixture import canonical, write_private
from forward import Forward
from gateway_probe import clients, framed
from isolation_cases import run as authorization_isolation
from journal_client import JournalClient
import network_paths
from panel_cases import observe_jwt
from plain_cases import PlainCases
from plain_soak import run as projected_token_soak
from protocol import ProtocolAuthority, record_hash
from rollback_cases import RollbackCases

from .cli_coordinator import CLICoordinator, owned_capability, prepare_main_genesis
from .cli_e2e_cases import CLIE2E2Cases
from .jwks import RemoteKindJWKS
from .pg_verify import run as verify_postgres
from .profiles import reviewed
from .provision_adapter import digest, require, safe_public, strict
from .provision_live import complete_chain_reader


def _record(path, value):
    write_private(path, canonical(value))
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Attempt:
    def __init__(self, private, profile, capability_hash, render_hash, acceptance):
        self.private = private
        self.index = 0
        _record(private / "stage8-cli-actor-start.json", {
            "sourceStage": 8, "production": False, "profile": profile, "acceptance": acceptance,
            "capabilitySHA256": capability_hash, "reviewedHARenderSHA256": render_hash})

    def step(self, name, callback):
        self.index += 1
        stem = f"stage8-cli-actor-{self.index:02d}-{name}"
        entry = {"phase": name, "sourceStage": 8, "production": False}
        _record(self.private / (stem + "-start.json"), entry)
        result = callback()
        _record(self.private / (stem + "-complete.json"), entry)
        return result


def _initialize_auxiliary_logs(owner, admin):
    authority = ProtocolAuthority.load(owner.task)
    logs = authority.fault_logs
    require(set(logs) == {"duplicate-version", "delete-marker", "replica-cas"},
        "CLIActorUnexpectedAuxiliaryLogs")
    log_ids = {authority.scope["log_id"]}
    for entry in logs.values():
        registration, record = entry["registration"], entry["record"]
        log = registration["log_id"]
        require(log not in log_ids and record["log_id"] == log and record["journal_sequence"] == "0"
            and record_hash(record) == registration["genesis_hash"], "CLIActorAuxiliaryGenesisMismatch")
        log_ids.add(log)
    for label, entry in sorted(logs.items()):
        registration, record = entry["registration"], entry["record"]
        log = registration["log_id"]
        nonce, (status, stream, _) = admin.journal(log)
        require(status == 200 and framed(stream, nonce, "0" * 64) == [], "CLIActorAuxiliaryLogAlreadyInitialized")
        owner.guard()
        status, raw, _ = admin.append(log, "0", canonical(record), expected=(200,))
        receipt = strict(raw, 16 << 10)
        require(status == 200 and receipt.get("mode") == "COMPLIANCE" and receipt.get("version_id"),
            "CLIActorAuxiliaryGenesisReceiptRejected")
        nonce, (status, stream, _) = admin.journal(log)
        slots = framed(stream, nonce, registration["genesis_hash"])
        require(status == 200 and len(slots) == 1 and slots[0]["record"] == record,
            "CLIActorAuxiliaryGenesisReadbackMismatch")
        _record(owner.task / "private" / ("stage8-auxiliary-" + label + "-complete.json"),
            {"sourceStage": 8, "production": False, "retainedGenesisVerified": True})


def _reconnect_gateway(coordinator):
    coordinator.gateway_forward.close()
    coordinator.gateway_forward = Forward(coordinator.cluster, coordinator.namespaces["gateway"],
        "service/journal", 8443)
    gateway = JournalClient(coordinator.gateway_forward.origin, coordinator.private / "journal-ca.crt",
        coordinator.private / "admin.crt", coordinator.private / "admin.key")
    coordinator.bridge.read_complete_chain = complete_chain_reader(gateway,
        coordinator.protocol.scope["log_id"], coordinator.current)


def _jwks(owner, coordinator, plain, profile):
    observed = plain.token()
    claims = observe_jwt(observed["token"])
    require(claims["pod_uid"] == observed["pod_uid"], "CLIActorAgentTokenBindingDiffers")
    signer = RemoteKindJWKS(coordinator.cluster, owner.marker, profile=profile)

    def reconnect(phase_name):
        require(phase_name in ("rotated", "restored"), "CLIActorUnexpectedJWKSPhase")
        coordinator.panel.connect()
        coordinator.panel.login()

    return signer.run(plain.agent_provider, observed["token"],
        {"name": claims["pod_name"], "uid": observed["pod_uid"]}, after_control_plane_ready=reconnect)


def _uninstall_preserving_target(read_target, uninstall):
    def signature(value):
        metadata = value["metadata"]
        require(metadata["uid"] and not metadata.get("deletionTimestamp"), "CLIActorInvalidRetainedTarget")
        return metadata["uid"], value["data"], metadata["annotations"][REVISION]

    before = signature(read_target())
    uninstall()
    require(signature(read_target()) == before, "CLIActorUninstallChangedTarget")


def _panel_outage_then_plain_recovery(plain, cases):
    # Both releases use this panel. A fresh HA success does not imply the
    # independently scheduled Plain reconciler has recovered yet.
    current = wait(plain.installation.current, timeout=240)
    previous = current["status"]["lastSuccessfulSyncTime"]
    dependency_outages(cases, labels=("panel",))
    wait(lambda: plain.installation.current(after_success=previous), timeout=240)


@safe_public
def run(task, *, profile, helm, chart, ha_rendered, reviewed_ha_sha256,
        api_endpoints, admission_sources, acceptance="full"):
    """Execute one CLI HA E2E attempt on a fresh installation."""
    require(acceptance in ("full", "reduced", "ha-final"), "CLIActorUnknownAcceptanceProfile")
    require(acceptance != "ha-final" or profile == "kind-1.37.0", "CLIActorHAFinalProfileMismatch")
    full = acceptance == "full"
    check_leader_and_jwks = acceptance in ("full", "ha-final")
    selected, pins = reviewed(profile)
    owner = owned_capability(task, selected.name)
    owner.guard()
    task = owner.task
    cluster = BudgetCluster(task)
    namespaces, _ = network_paths._namespaces(cluster)
    require(network_paths._sha(ha_rendered) == reviewed_ha_sha256, "CLIActorReviewedRenderMismatch")
    expected = network_paths._render_selectors(ha_rendered, namespaces["apps"], "stage6", True)
    api_endpoints = network_paths._endpoints(api_endpoints, {443, 6443})
    admission_sources = network_paths._endpoints(admission_sources, {9443})
    attempt = Attempt(task / "private", selected.name, digest(owner.raw), reviewed_ha_sha256, acceptance)
    image, backend = pins["operator_image"], pins["backend_image"]
    provider = coordinator = None

    def genesis():
        nonlocal provider
        with Forward(cluster, namespaces["gateway"], "service/journal", 8443) as forward:
            provider, facts = prepare_main_genesis(task, profile=selected.name,
                gateway_client=clients(task, forward.origin)["admin"])
        return facts

    def auxiliary_logs():
        with Forward(cluster, namespaces["gateway"], "service/journal", 8443) as forward:
            _initialize_auxiliary_logs(owner, clients(task, forward.origin)["admin"])

    def run_step(name, callback):
        owner.guard()
        return attempt.step(name, callback)

    def open_coordinator():
        nonlocal coordinator, provider
        coordinator = CLICoordinator(task, profile=selected.name, provider=provider)
        provider = None  # Coordinator now owns the provider.

    try:
        run_step("cli-genesis", genesis)
        run_step("auxiliary-genesis", auxiliary_logs)
        run_step("witness", lambda: phase(task, "witness", image, backend))
        if full:
            run_step("postgres", lambda: verify_postgres(cluster, profile=selected.name))
        run_step("panel", lambda: phase(task, "panel", image, backend))
        run_step("coordinator", open_coordinator)

        def authenticate():
            coordinator.panel.connect()
            coordinator.panel.login()
            coordinator.panel.unseal()

        run_step("panel-auth", authenticate)
        plain = PlainCases(coordinator, image, helm, chart)

        def network_hook(cases):
            require(cases is plain, "CLIActorPlainLifecycleChanged")
            run_step("narrow-network-paths", lambda: network_paths.install(cases, ha_rendered=ha_rendered,
                reviewed_ha_sha256=reviewed_ha_sha256, api_endpoints=api_endpoints,
                admission_sources=admission_sources))

        run_step("plain-initial", lambda: plain.initial(before_first_publish=network_hook))
        if full:
            run_step("plain-rollout-off", plain.changed_rollout_off)
            run_step("plain-opt-in", plain.opt_in)
            run_step("plain-rollout-on", plain.changed_rollout_on)
        if check_leader_and_jwks:
            run_step("legacy-agent", plain.agent)
        if full:
            run_step("plain-equal", plain.equal)
            run_step("plain-projected-token-soak", lambda: projected_token_soak(plain))
        cases = CLIE2E2Cases(coordinator, image, helm, chart)

        def verify_ha_paths(actual):
            require(actual is cases and network_paths._render_selectors(actual.rendered,
                namespaces["apps"], "stage6", True) == expected, "CLIActorActualHARenderSelectorsDiffer")

        run_step("cli-prepare", lambda: cases.prepare(before_first_publish=verify_ha_paths))
        run_step("cli-initialize", cases.initialize)
        run_step("helm-install", cases.install)
        run_step("changed", cases.changed)
        rollback = RollbackCases(coordinator) if full else None
        if full:
            run_step("rollback-baseline", rollback.capture)
        run_step("equal", cases.equal)
        if full:
            run_step("helm-upgrade", cases.upgrade)
            run_step("authorization-isolation", lambda: authorization_isolation(plain, cases))
            run_step("dependencies", lambda: dependency_outages(cases))
            run_step("gateway-transport", lambda: _reconnect_gateway(coordinator))
            run_step("wrong-key-substitution", lambda: wrong_e2e_key(cases))
            run_step("state-and-index-rollback", lambda: rollback.run_after_advance(
                cases.selected["generation"], cases.selected["demo"]))
        if check_leader_and_jwks:
            run_step("pending-rollout-leader-restart", lambda: leader_pending_restart(cases))
        if acceptance == "reduced":
            run_step("panel-outage", lambda: _panel_outage_then_plain_recovery(plain, cases))
        run_step("helm-uninstall-ha", lambda: _uninstall_preserving_target(
            lambda: cases.app.get("Secret", TARGET), cases.uninstall))

        def uninstall_plain():
            reference = plain.installation.target_ref()
            _uninstall_preserving_target(lambda: plain.apps.target(reference), plain.installation.lifecycle.uninstall)

        run_step("helm-uninstall-plain", uninstall_plain)
        if check_leader_and_jwks:
            run_step("jwks", lambda: _jwks(owner, coordinator, plain, selected.name))
    finally:
        if coordinator is not None:
            coordinator.close()
        elif provider is not None:
            provider.close()

    facts = {"sourceStage": 8, "profile": selected.name, "production": False, "acceptance": acceptance,
        "plainInitialCompleted": True, "cliHAInstallChangeEqualCompleted": True,
        "panelOutageCompleted": acceptance != "ha-final", "helmUninstallRetainedResources": True,
        "postgresCompleted": full, "helmUpgradeCompleted": full, "jwksCompleted": check_leader_and_jwks,
        "pendingRolloutLeaderRestartCompleted": check_leader_and_jwks,
        "crossNamespaceAuthorizationCompleted": full,
        "projectedTokenSoakCompleted": full, "nodeReadKeyRotationTested": False,
        "hostRuntimeSplitBrainTested": False, "packetIsolationVerified": False}
    _record(task / "private" / "stage8-cli-actor-complete.json", facts)
    return facts
