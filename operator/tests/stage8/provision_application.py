"""Narrow Application extension: real UID reservation for CLI trust bootstrap.

No action runs on import. Existing namespace/creation UID guards are reused;
only the first empty trust reservation is populated, before runtime starts.
"""

import base64
import copy
import os

from application import Application, RELEASE, SA, FENCER_SA
from stage8.provision_adapter import canonical, require, safe_public, strict


class CLIApplication(Application):
    def __init__(self, cluster, protocol):
        require(not os.path.lexists(cluster.task / "private" / "application-context.json"), "CLIApplicationCannotAdoptContext")
        super().__init__(cluster, protocol)
        self._reserving_cli_trust = False
        self._cli_trust_reservation = None
        self.cli_trust_complete = False

    def __repr__(self):
        return "<CLI-backed owned trial application [redacted]>"

    def runtime_absent(self):
        self.namespace_guard()
        for name in (RELEASE + "-operator", RELEASE + "-fencer"):
            raw = self.cluster.kube("get", "deployment", name, "-n", self.namespace, "--ignore-not-found", "-o", "json").stdout
            require(not raw.strip(), "CLITrustRequiresStoppedRuntime")
        pods = strict(self.cluster.kube("get", "pods", "-n", self.namespace, "-o", "json").stdout.encode())["items"]
        require(not any(pod.get("spec", {}).get("serviceAccountName") in (SA, FENCER_SA) for pod in pods), "CLITrustRequiresStoppedRuntime")

    @safe_public
    def prepare(self, *args, **kwargs):
        require(self._cli_trust_reservation is None, "CLITrustReservationAlreadyExists")
        self.runtime_absent()
        self._reserving_cli_trust = True
        try:
            return super().prepare(*args, **kwargs)
        finally:
            self._reserving_cli_trust = False

    def secret(self, name, values, immutable=True):
        if name != self.trust_name:
            return super().secret(name, values, immutable)
        require(self._reserving_cli_trust and self._cli_trust_reservation is None, "CLITrustReservationAlreadyExists")
        # The base constructs an unsigned trust dictionary, which is deliberately
        # not installed. Only CLI-produced trust bytes can fill this reservation.
        require(set(values) == {"trust.json"}, "CLITrustReservationShapeChanged")
        value = super().secret(name, {}, immutable=False)
        self._cli_trust_reservation = copy.deepcopy(value)
        return value

    def recovery_plan(self, *args, **kwargs):
        # Reusing a legacy initializer must not silently sign in Python.
        require(False, "CLIRecoveryRequiresExplicitProvider")

    @safe_public
    def populate_cli_trust(self, bundle, installation):
        require(not self.cli_trust_complete and self._cli_trust_reservation is not None, "CLITrustReservationMissing")
        self.runtime_absent()
        original = self._cli_trust_reservation
        current = self.get("Secret", self.trust_name)
        uid, rv = original["metadata"]["uid"], original["metadata"]["resourceVersion"]
        require(current["metadata"]["uid"] == uid and current["metadata"]["resourceVersion"] == rv
            and current.get("type") == "Opaque" and current.get("immutable") is False and not current.get("data")
            and current["metadata"].get("ownerReferences") == original["metadata"].get("ownerReferences"), "CLITrustReservationChanged")
        require(bundle.value("installation.json") == installation, "CLIInstallationRenderChanged")
        trust = bundle.raw("trust.json")
        marker = self.get("Secret", self.state_name)
        require(base64.b64decode(marker["data"]["installation.json"], validate=True) == bundle.raw("state-marker.json"), "CLIStateMarkerChanged")
        identity = self.get("Secret", self.node_secret_name)
        require(identity.get("immutable") is True and identity["metadata"]["uid"] == installation["identityKeySecret"]["uid"], "CLIIdentityReservationChanged")
        data = {"trust.json": base64.b64encode(trust).decode("ascii")}
        operations = [{"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": rv},
            {"op": "add", "path": "/data", "value": data}, {"op": "replace", "path": "/immutable", "value": True}]
        self.cluster.kube("patch", "secret", self.trust_name, "-n", self.namespace, "--type=json",
            "--patch-file=/dev/stdin", "-o", "json", data=canonical(operations).decode())
        verified = self.get("Secret", self.trust_name)
        require(verified["metadata"]["uid"] == uid and verified.get("immutable") is True and verified.get("type") == "Opaque"
            and verified.get("data") == data and verified["metadata"].get("ownerReferences") == original["metadata"].get("ownerReferences"), "CLITrustCASNotVerified")
        self.cli_trust_complete = True
        return {"reservedTrustUIDPreserved": True, "cliTrustInstalledImmutable": True, "production": False}

    @safe_public
    def start_application_after_initialize(self):
        require(self.cli_trust_complete, "CLITrustNotComplete")
        return super().start_application_after_initialize()
