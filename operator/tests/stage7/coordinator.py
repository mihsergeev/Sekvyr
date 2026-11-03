"""Stage7 uses the actual shared protocol/provider, with a new private lifecycle."""

import json
from pathlib import Path

from application import Application
from fixture import canonical, safe_task, write_private
from forward import Forward
from fullstack import Coordinator as PriorCoordinator
from infrastructure import BudgetCluster
from journal_client import JournalClient
from panel import Panel
from protocol import ProtocolAuthority


class TrialPanel(Panel):
    def recover(self, plan, envelope, wrapper, installation):
        if self.task.parent == Path("/var/tmp"):
            from kind_recovery import recover
            return recover(self, plan, envelope, wrapper, installation)
        from host_recovery import recover
        return recover(self, plan, envelope, wrapper, installation)


class Coordinator(PriorCoordinator):
    def __init__(self, task, recovery_executable=None):
        self.task = safe_task(task)
        self.cluster = BudgetCluster(self.task)
        self.private = self.task / "private"
        self.protocol = ProtocolAuthority.load(self.task)
        self.namespaces = self.cluster.fixture["namespaces"]
        self.app = Application(self.cluster, self.protocol)
        self.overrides = {}
        override_path = self.private / "fixture-overrides.json"
        if override_path.exists():
            # Application already validates the Secret creation UID and exact
            # immutable TLS bytes against this explicit private override.
            if override_path.is_symlink() or override_path.stat().st_size > 8192:
                raise RuntimeError("Fixture material override invalid")
            override = json.loads(override_path.read_bytes())
            tls = override.get("fencerTLS", {}) if isinstance(override, dict) else {}
            if set(override) != {"fencerTLS"} or set(tls) != {"name", "uid", "label"} or tls["label"] not in ("fencer-server", "fencer-server-admission") or tls["name"] != self.app.fencer_tls_secret_name or tls["uid"] != self.app.created[("Secret", tls["name"])]["uid"]:
                raise RuntimeError("Fixture material override differs from creation pins")
            self.overrides = override
        self.witness_forward = Forward(self.cluster, self.namespaces["witness"], "service/witness", 8443)
        self.client = JournalClient(self.witness_forward.origin, self.private / "journal-ca.crt",
            self.private / "admin.crt", self.private / "admin.key")
        self.panel = TrialPanel(self.cluster, self.protocol, self.client, recovery_executable)
        self.panel_origin = self.protocol.panel_origin
        self.witness_origin = "https://witness." + self.namespaces["witness"] + ".svc.cluster.local:8443"
        self.gateway_origin = "https://journal." + self.namespaces["gateway"] + ".svc.cluster.local:8443"
        self.app.materials = self.materials()
        self.app.panel_origin, self.app.witness_origin = self.panel_origin, self.witness_origin


def phase(task, action, operator_image, backend_image):
    from run import install_gateway
    from storage_probe import storage_bootstrap
    from gateway_probe import bootstrap_and_authorize
    import witness
    task = safe_task(task)
    cluster = BudgetCluster(task)
    params = json.loads((task / "infrastructure-parameters.json").read_bytes())
    if action == "storage-bootstrap":
        with Forward(cluster, cluster.fixture["namespaces"]["storage"], "service/s3", 8333) as forward:
            return storage_bootstrap(cluster, forward.origin)
    if action == "gateway":
        result = install_gateway(task, operator_image, params["node_name"])
        cluster.kube("-n", cluster.fixture["namespaces"]["gateway"], "rollout", "status", "deployment/journal", "--timeout=180s")
        return result
    if action == "genesis":
        with Forward(cluster, cluster.fixture["namespaces"]["gateway"], "service/journal", 8443) as forward:
            result = bootstrap_and_authorize(task, forward.origin)
        write_private(task / "private" / "stage7-genesis-ready.json", canonical(result))
        return result
    if action == "genesis-resume":
        # A lost transport acknowledgement is resolved only against the exact
        # existing signed genesis bytes. No append, reset or automatic rebase.
        from gateway_probe import clients, framed
        from journal_client import JournalClient
        protocol = ProtocolAuthority.load(task)
        entries = [{"record": protocol.genesis_record, "registration": protocol.registration}, *protocol.fault_logs.values()]
        with Forward(cluster, cluster.fixture["namespaces"]["gateway"], "service/journal", 8443) as forward:
            identities = clients(task, forward.origin)
            admin = identities["admin"]
            for entry in entries:
                nonce, (_, raw, _) = admin.journal(entry["registration"]["log_id"])
                slots = framed(raw, nonce, entry["registration"]["genesis_hash"])
                if len(slots) != 1 or slots[0]["record"] != entry["record"]:
                    raise RuntimeError("Genesis acknowledgement does not match the saved signed record")
            log = protocol.scope["log_id"]
            path = JournalClient.path(log, "0")
            for role in ("witness-a", "witness-b", "fencer", "operator"):
                identities[role].append(log, "0", canonical(protocol.genesis_record), expected=(403,))
            for method, suffix in (("DELETE", ""), ("DELETE", "?versionId=not-authorized"), ("POST", "?uploads")):
                admin.request(method, path + suffix, b"{}" if method == "POST" else None,
                    {"Content-Type": "application/json"}, expected=(400, 403, 405))
        result = {"exactRetainedGenesisRecordsResolved": len(entries), "storageReset": False,
            "runtimeProfilesCannotInitialize": 4, "unsafeAPIsDenied": True, "production": False}
        write_private(task / "private" / "stage7-genesis-ready.json", canonical(result))
        return result
    if action == "witness":
        witness.install(cluster, operator_image, params["node_name"])
        for name in ("witness-a", "witness-b"):
            cluster.kube("-n", cluster.fixture["namespaces"]["witness"], "rollout", "status", "deployment/" + name, "--timeout=180s")
        return {"witnessProcessesReady": 2, "production": False}
    if action == "panel":
        coordinator = Coordinator(task)
        try:
            result = coordinator.panel.prepare(backend_image, params["storage_class"], coordinator.witness_origin, params["node_name"])
            cluster.kube("-n", cluster.fixture["namespaces"]["panel"], "rollout", "status", "deployment/panel", "--timeout=180s")
            coordinator.panel.connect()
            coordinator.panel.login()
            coordinator.panel.unseal()
            return dict(result, tlsPanelReady=True, ownerAuthenticated=True)
        finally:
            coordinator.close()
    raise ValueError("Explicit reviewed bootstrap phase required")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("storage-bootstrap", "gateway", "genesis", "genesis-resume", "witness", "panel"), required=True)
    parser.add_argument("--operator-image", required=True)
    parser.add_argument("--backend-image", required=True)
    args = parser.parse_args()
    print(json.dumps(phase(args.task_dir, args.phase, args.operator_image, args.backend_image)), flush=True)
