"""Persistent CLI-backed Stage 8 coordinator; no network operation on import."""

import base64
import os
from pathlib import Path
from types import SimpleNamespace

from fixture import canonical, write_private
from forward import Forward
from journal_client import JournalClient
from protocol import ProtocolAuthority
import coordinator as legacy

from .capability import Capability, fixed_function
from .profiles import reviewed
from .recovery import bind, verified_cli
from .provision_adapter import CLIProvider, digest, require, safe_public, strict
from .provision_application import CLIApplication
from .provision_live import LiveCLIProvider, complete_chain_reader

def owned_capability(task, profile):
    task = legacy.safe_task(task)
    from remote_kind_capability import read
    _, fixture = read(task / "private" / "fixture.json")
    return Capability(SimpleNamespace(task=task, fixture=fixture), profile=profile)

def new_provider(task, protocol, pins):
    return CLIProvider.from_protocol(task / "tools" / "sekvyr-provision", pins["provision_sha256"],
        task / "private" / "provision-stage8", protocol)

def provider_matches(provider, task, protocol, pins):
    require(isinstance(provider, CLIProvider) and provider.files.path == task / "private" / "provision-stage8"
        and provider.cli.sha256 == pins["provision_sha256"] and provider.scope == protocol.scope
        and provider.registration == protocol.registration and provider.authority == protocol.authority
        and provider.node_public == protocol.node_public and provider.node_fingerprint == protocol.node_fingerprint
        and provider.panel_origin == protocol.panel_origin, "CLIProviderFixtureMismatch")

class CLITrialPanel(legacy.TrialPanel):
    def __init__(self, cluster, protocol, witness_client, recovery_executable=None, *, profile):
        super().__init__(cluster, protocol, witness_client, recovery_executable)
        self._native_recover = bind(self, profile)
        self.cli_bridge = None

    def recover(self, plan, envelope, wrapper, installation):
        return self._native_recover(plan, envelope, wrapper, installation)

    def _python_signer_forbidden(self, *args, **kwargs):
        require(False, "CLIProviderRequiredNoPythonSigner")

    publish = publish_sealed = grant_reader = enroll = project_rotation = _python_signer_forbidden

    @safe_public
    def offline_export(self):
        require(self.cli_bridge is not None, "CLIProviderNotAttached")
        current = self.cli_bridge.current()
        bundle = self.cli_bridge.snapshots.get(current["snapshot"]["envelope_hash"])
        require(bundle is not None, "CLIUnknownSnapshotExport")
        return bundle.raw("envelope.json"), bundle.raw("reader-wrap.json")

class CLICoordinator(legacy.Coordinator):
    @safe_public
    def __init__(self, task, *, profile, provider):
        selected, pins = reviewed(profile)
        self.capability = owned_capability(task, selected.name)  # Before Forward/API.
        self.task, self.private = self.capability.task, self.capability.task / "private"
        require(not os.path.lexists(self.private / "application-context.json"),
            "CLIApplicationCannotAdoptContext")
        provider_matches(provider, self.task, ProtocolAuthority.load(self.task), pins)
        require(getattr(provider, "_stage8_genesis_owner", None) ==
            (self.task, selected.name, digest(self.capability.raw)), "CLICommittedGenesisInstanceRequired")
        write_private(self.private / "stage8-coordinator-instance.json", canonical({
            "sourceStage": 8, "profile": selected.name,
            "capabilitySHA256": digest(self.capability.raw), "production": False}))
        self.profile = selected.name
        self.witness_forward = self.gateway_forward = self.panel = None
        self.provider = None
        self.cli_active = False
        self._publish_index, self._publish_pending = 0, False
        try:
            executable = self.task / "tools" / "sekvyr-checkpoint-recovery"
            verified_cli(SimpleNamespace(task=self.task, recovery_executable=executable), profile=self.profile)
            panel_factory = lambda *args: CLITrialPanel(*args, profile=self.profile)
            initialize = fixed_function(legacy.Coordinator.__init__, Application=CLIApplication, TrialPanel=panel_factory)
            initialize(self, self.task, executable)
            self.provider = provider
            provider_matches(self.provider, self.task, self.protocol, pins)
            self.capability.guard()
            self.gateway_forward = Forward(self.cluster, self.namespaces["gateway"], "service/journal", 8443)
            gateway = JournalClient(self.gateway_forward.origin, self.private / "journal-ca.crt",
                self.private / "admin.crt", self.private / "admin.key")
            self.bridge = LiveCLIProvider(self, self.provider,
                complete_chain_reader(gateway, self.protocol.scope["log_id"], self.current), self.panel.recover)
            self.panel.cli_bridge = self.bridge
        except BaseException:
            self.close()
            raise

    @safe_public
    def enable_cli_publications(self, installation):
        require(not self.cli_active and self.app.cli_trust_complete
            and self.bridge.bootstrap_bundle is not None
            and installation == self.bridge.bootstrap_bundle.value("installation.json"),
            "CLIInitializeNotComplete")
        self.capability.guard()
        protected = self.app.get("Secret", self.app.state_name)
        raw = base64.b64decode(protected["data"]["state.json"], validate=True)
        state = strict(raw, 512 << 10)
        require(protected["metadata"]["uid"] == installation["stateSecret"]["uid"]
            and state["installationID"] == installation["installationID"]
            and state["bootstrapGeneration"] == installation["bootstrapGeneration"]
            and state["trustBundleUID"] == installation["trustBundleSecret"]["uid"]
            and state["nodeFingerprint"] == self.provider.node_fingerprint
            and state["recovery"]["phase"] == "complete", "CLIInitializeNotComplete")
        write_private(self.private / "stage8-cli-sync-authorized.json", canonical({
            "sourceStage": 8, "installationSHA256": digest(canonical(installation)), "production": False}))
        self.cli_active = True

    @safe_public
    def publish(self, generation, demo):
        require(self.cli_active and not self._publish_pending and type(generation) is str and type(demo) is str,
            "CLIExplicitPublicationBlocked")
        self.capability.guard()
        self._publish_index += 1
        label = "runtime-publish-" + str(self._publish_index)
        self._publish_pending = True  # Failure freezes this persistent instance.
        write_private(self.private / (label + "-request.json"), canonical({
            "label": label, "inputsSHA256": digest(canonical({"generation": generation, "demo": demo})),
            "production": False}))
        snapshot = self.bridge.publish(generation, demo, label=label)
        write_private(self.private / (label + "-committed.json"), canonical({
            "label": label, "snapshot": snapshot, "production": False}))
        self._publish_pending = False
        return snapshot

    def close(self):
        failed = False
        for resource in (getattr(self, "panel", None), getattr(self, "gateway_forward", None),
                getattr(self, "witness_forward", None), getattr(self, "provider", None)):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    failed = True
        if failed:
            raise RuntimeError("CLICoordinatorCleanupIncomplete") from None

@safe_public
def prepare_main_genesis(task, *, profile, gateway_client):
    """Explicit empty-main-log initialization using CLI bytes; no old-log adoption."""
    selected, pins = reviewed(profile)
    owner = owned_capability(task, selected.name)
    task = owner.task
    marker = task / "private" / "stage8-main-genesis-start.json"
    write_private(marker, canonical({"profile": selected.name, "sourceStage": 8, "production": False}))
    protocol = ProtocolAuthority.load(task)
    provider = new_provider(task, protocol, pins)
    try:
        bundle = provider.genesis("main-genesis", protocol.genesis_record["genesis"]["body"])
        require(bundle.raw("record.json") == canonical(protocol.genesis_record)
            and bundle.raw("registration.json") == canonical(protocol.registration)
            and bundle.value("records.json") == [protocol.genesis_record], "CLIOriginalGenesisMismatch")
        from gateway_probe import framed
        nonce, (status, raw, _) = gateway_client.journal(protocol.scope["log_id"])
        require(status == 200 and framed(raw, nonce, "0" * 64) == [], "CLIMainLogAlreadyInitialized")
        owner.guard()
        status, response, _ = gateway_client.append(protocol.scope["log_id"], "0",
            bundle.raw("record.json"), expected=(200,))
        receipt = strict(response, 16 << 10)
        require(status == 200 and receipt.get("mode") == "COMPLIANCE" and receipt.get("version_id"),
            "CLIInitialGatewayReceiptRejected")
        nonce, (status, raw, _) = gateway_client.journal(protocol.scope["log_id"])
        slots = framed(raw, nonce, protocol.registration["genesis_hash"])
        require(status == 200 and len(slots) == 1
            and canonical(slots[0]["record"]) == bundle.raw("record.json"), "CLIGenesisReadbackMismatch")
        facts = {"sourceStage": 8, "cliGenesisMatchesIndependentPins": True,
            "gatewayConsumedCLIRecordBytes": True, "production": False}
        write_private(task / "private" / "stage8-main-genesis-complete.json", canonical(facts))
        provider._stage8_genesis_owner = (task, selected.name, digest(owner.raw))
        return provider, facts
    except BaseException:
        provider.close()
        raise
