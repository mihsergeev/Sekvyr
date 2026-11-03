"""Go CLI preparation for the existing native Helm E2E2 assertions."""

import copy
import os
from pathlib import Path

from application import RELEASE
from e2e_cases import E2E2Cases, PYTHON, reviewed_values
from fixture import canonical, issue_leaf, write_private
from helm_lifecycle import HelmLifecycle

from .cli_coordinator import CLICoordinator
from .profiles import reviewed
from .provision_adapter import digest, require, safe_public, strict

class CLIE2E2Cases(E2E2Cases):
    @safe_public
    def __init__(self, coordinator, image, helm, chart):
        require(isinstance(coordinator, CLICoordinator), "CLIStage8CoordinatorRequired")
        _, pins = reviewed(coordinator.profile)
        require(image == pins["operator_image"], "CLIStage8ImageMismatch")
        coordinator.capability.guard()
        require(not os.path.lexists(coordinator.private / "e2e-cases"), "CLIApplicationCasesCannotAdoptContext")
        super().__init__(coordinator, image, helm, chart)
        write_private(self.root / "stage8-cases-instance.json", canonical({"sourceStage": 8, "production": False}))
        self.installation = self.rendered = self.prepare_cursor = None

    def __repr__(self):
        return "<CLI-backed native Helm E2E2 cases [redacted]>"

    def proof(self, label, facts):
        return super().proof(label, {**facts, "sourceStage": 8})

    def _claim(self, operation):
        write_private(self.root / ("cli-" + operation + "-started.json"),
            canonical({"sourceStage": 8, "operation": operation, "production": False}))

    def _render_installation(self):
        manifests, _ = self.lifecycle.render(self.values)
        configs = [value for value in manifests if value["kind"] == "ConfigMap"
            and "installation.json" in value.get("data", {})]
        require(len(configs) == 1 and configs[0].get("immutable") is True
            and configs[0]["metadata"].get("namespace") == self.app.namespace,
            "CLIInstallationRenderAmbiguous")
        value = strict(configs[0]["data"]["installation.json"].encode(), 64 << 10)
        require(value.get("namespace") == self.app.namespace and isinstance(value.get("ha"), dict),
            "CLIInstallationRenderMismatch")
        return manifests, value

    def _prepare_render(self):
        c, app = self.c, self.app
        who = strict(c.cluster.kube("auth", "whoami", "-o", "json").stdout.encode())["status"]["userInfo"]
        subject = {"username": who["username"], "uid": who.get("uid", "")}
        params = strict((c.task / "infrastructure-parameters.json").read_bytes(), 16 << 10)
        self.values = reviewed_values(app, self.image, subject, c.gateway_origin,
            (c.private / "journal-ca.crt").read_bytes(), params["node_name"])
        external = [{"kind": kind, "name": name, "uid": pin["uid"]}
            for (kind, name), pin in app.created.items()]
        self.lifecycle = HelmLifecycle(c.cluster, self.helm, self.chart, RELEASE, app.namespace, external)
        self.rendered, self.installation = self._render_installation()
        write_private(self.root / "reviewed-values.json", canonical(self.values))
        write_private(self.root / "reviewed-installation.json", canonical(self.installation))

    @safe_public
    def prepare(self, *, before_first_publish=None):
        """One attempt. Optional explicit reviewed network callback before commit.

        The callback sees the captured reservations and reviewed HA render; no
        HA Deployment is installed yet. An already captured Plain lifecycle can
        be supplied by the caller's closure. This method never reports packet
        isolation or weakens default deny on the basis of a callback result.
        """
        require(before_first_publish is None or callable(before_first_publish), "CLIExplicitNetworkHookRequired")
        require(not self.prepared and self.lifecycle is None and not self.c.cli_active,
            "CLIApplicationPrepareCannotReset")
        c, app, bridge = self.c, self.app, self.c.bridge
        c.capability.guard()
        self._claim("prepare")  # O_EXCL before any remote write or new CLI nonce.
        current = bridge.current()
        require(current["scope"] == c.protocol.scope and current["genesis_hash"] == c.protocol.genesis_hash
            and current["snapshot"]["sequence"] == "0" and current["cursor"] == c.protocol.registration["minimum_cursor"],
            "CLIEmptyPinnedDataLogRequired")
        self.selected = pair = self.pair("initial")
        bundle, snapshot, expected = bridge.prepare_snapshot("initial-snapshot", pair["generation"], pair["demo"])
        require(snapshot["sequence"] == "1" and expected == current["cursor"], "CLIInitialCandidateMismatch")
        self.initial_snapshot = copy.deepcopy(snapshot)
        write_private(self.root / "initial-envelope.json", bundle.raw("envelope.json"))
        write_private(self.root / "intended-checkpoint.json", canonical(snapshot))

        host = RELEASE + "-fencer." + app.namespace + ".svc"
        label = "fencer-server-admission"
        require(all(not os.path.lexists(c.private / (label + "." + extension)) for extension in ("crt", "key")),
            "CLITLSMaterialAlreadyReserved")
        issue_leaf(c.task, "journal", label, "server", [host, host + ".cluster.local", "localhost"])
        materials = c.materials()
        materials.update(fencer_tls_cert=(c.private / (label + ".crt")).read_bytes(),
            fencer_tls_key=(c.private / (label + ".key")).read_bytes())
        app.prepare(PYTHON, c.panel_origin, c.witness_origin, snapshot, materials)
        override = {"fencerTLS": {"name": app.fencer_tls_secret_name,
            "uid": app.get("Secret", app.fencer_tls_secret_name)["metadata"]["uid"], "label": label}}
        write_private(c.private / "fixture-overrides.json", canonical(override))
        c.overrides = override
        self._prepare_render()
        if before_first_publish is not None:
            before_first_publish(self)
        c.capability.guard()
        app.runtime_absent()
        c.panel.bootstrap()
        committed = bridge.commit_snapshot(bundle, snapshot, expected)
        require(committed == self.initial_snapshot, "CLIInitialCanonicalCommitMismatch")
        bridge.grant_reader(bundle)
        accepted = bridge.current()
        require(all(accepted["snapshot"][key] == value for key, value in self.initial_snapshot.items()),
            "CLIInitialCanonicalCommitMismatch")
        self.prepare_cursor = copy.deepcopy(accepted["cursor"])
        self.prepared = True
        return self.proof("e2e2-prepared", {"cliSnapshotAndWrapConsumed": True,
            "actualPanelCanonicalCommit": True, "operatorStarted": False,
            "explicitNetworkHookCompleted": before_first_publish is not None})

    @safe_public
    def initialize(self):
        require(self.prepared and not self.initialized and self.lifecycle is not None and not self.c.cli_active,
            "CLIInitializeRequiresExactPreparedInstance")
        c, app, bridge = self.c, self.app, self.c.bridge
        c.capability.guard()
        self._claim("initialize")
        app.runtime_absent()
        current = bridge.current()
        require(current["cursor"] == self.prepare_cursor
            and all(current["snapshot"][key] == value for key, value in self.initial_snapshot.items()),
            "CLIInitialContextAdvanced")
        rendered, installation = self._render_installation()
        require(rendered == self.rendered and installation == self.installation
            and (self.root / "reviewed-values.json").read_bytes() == canonical(self.values)
            and (self.root / "reviewed-installation.json").read_bytes() == canonical(installation),
            "CLIInstallationRenderChanged")
        bootstrap = bridge.bootstrap("initial-bootstrap", installation)
        require(bootstrap.get("cliBootstrapConsumed") is True and app.cli_trust_complete, "CLITrustNotComplete")
        enrollment = bridge.enroll("initial-enrollment")
        require(enrollment.get("cliSignedEnrollmentCommitted") is True, "CLIEnrollmentNotCanonical")
        # The bridge reads a fresh complete signed chain after enrollment and
        # supplies only the saved CLI plan/envelope/wrap to native recovery.
        initialized = bridge.initialize("initial-recovery", installation)
        require(initialized.get("cliSignedInitializeConsumedByNativeRecovery") is True, "CLINativeRecoveryNotComplete")
        c.enable_cli_publications(installation)
        self.initialized = True
        return self.proof("e2e2-signed-initialization", {"cliBootstrapAndTrustSeal": True,
            "cliSignedEnrollment": True, "cliSignedCheckpointInitialization": True,
            "initialEnvFromVerifiedBeforeOperator": True})
