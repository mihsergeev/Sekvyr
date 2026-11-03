"""Actual trial orchestration; no action runs on import and no implicit reset."""

from contextlib import contextmanager
import copy
import json
from pathlib import Path
import subprocess

from application import Application, wait
from cluster import Cluster
from fixture import canonical, write_private
from forward import Forward
from journal_client import JournalClient
from panel import Panel
from protocol import ProtocolAuthority


class Coordinator:
    def __init__(self, task, recovery_executable=None):
        self.cluster = Cluster(task)
        self.task, self.private = self.cluster.task, self.cluster.task / "private"
        self.protocol = ProtocolAuthority.load(self.task)
        self.namespaces = self.cluster.fixture["namespaces"]
        self.app = Application(self.cluster, self.protocol)
        overrides_file = self.private / "fixture-overrides.json"
        self.overrides = json.loads(overrides_file.read_text(encoding="utf-8")) if overrides_file.exists() else {}
        if self.overrides.get("fencerTLS"):
            self.app.fencer_tls_secret_name = self.overrides["fencerTLS"]["name"]
        self.witness_forward = Forward(self.cluster, self.namespaces["witness"], "service/witness", 8443)
        self.client = JournalClient(self.witness_forward.origin, self.private / "journal-ca.crt",
            self.private / "admin.crt", self.private / "admin.key")
        self.panel = Panel(self.cluster, self.protocol, self.client, recovery_executable)
        self.panel_origin = self.protocol.panel_origin
        self.witness_origin = "https://witness." + self.namespaces["witness"] + ".svc.cluster.local:8443"
        self.gateway_origin = "https://journal." + self.namespaces["gateway"] + ".svc.cluster.local:8443"
        self.app.materials = self.materials()
        self.app.panel_origin, self.app.witness_origin = self.panel_origin, self.witness_origin

    def __repr__(self):
        return "<isolated actual stage6 coordinator [redacted]>"

    def materials(self):
        ca = (self.private / "journal-ca.crt").read_bytes()
        result = {label + "_ca": ca for label in ("panel", "witness", "journal", "fencer")}
        tls_label = self.overrides.get("fencerTLS", {}).get("label", "fencer-server")
        if tls_label not in ("fencer-server", "fencer-server-admission"):
            raise RuntimeError("Unreviewed fixture TLS material label")
        for prefix, label in (("fencer_tls", tls_label), ("operator_client", "operator"), ("fencer_client", "fencer")):
            for suffix, extension in (("cert", "crt"), ("key", "key")):
                result[prefix + "_" + suffix] = (self.private / (label + "." + extension)).read_bytes()
        return result

    def close(self):
        self.panel.close()
        self.witness_forward.close()

    def install_crds(self, chart):
        import yaml
        resources = []
        for path in sorted((Path(chart) / "crds").glob("*.yaml")):
            resources.extend(value for value in yaml.safe_load_all(path.read_text(encoding="utf-8")) if value)
        if len(resources) != 2 or any(value["kind"] != "CustomResourceDefinition" for value in resources):
            raise RuntimeError("Expected exactly two reviewed operator CRDs")
        self.cluster.review_cluster_manifests(resources)
        for value in resources:
            self.cluster.create(value)
            self.cluster.kube("wait", "--for=condition=Established", "crd/" + value["metadata"]["name"], "--timeout=60s")

    def prepare(self, panel_image, python_image, storage_class, node_name, chart):
        if (self.private / "application-initial-envelope.json").exists():
            raise RuntimeError("Fullstack prepare may not reset an earlier fixture")
        self.install_crds(chart)
        envelope, digest = self.protocol.snapshot(1, "0" * 64, "initial", "public-trial-initial")
        intended = {"sequence": "1", "envelope_hash": digest}
        write_private(self.private / "application-initial-envelope.json", canonical(envelope))
        write_private(self.private / "application-intended-checkpoint.json", canonical(intended))
        # This reservation is an intended pin, not authenticated current data.
        # No operator, recovery command or app starts before actual commit.
        enrollment = self.app.prepare(python_image, self.panel_origin, self.witness_origin, intended, self.materials())
        self.panel.prepare(panel_image, storage_class, self.witness_origin, node_name)
        self.cluster.kube("-n", self.namespaces["panel"], "rollout", "status", "deployment/panel", "--timeout=240s")
        self.panel.connect()
        self.panel.bootstrap()
        committed = self.panel.publish_sealed(envelope, digest)
        if committed["sequence"] != "1" or committed["envelope_hash"] != digest:
            raise RuntimeError("Actual first canonical commit differs from intended pin")
        self.panel.grant_reader()
        self.panel.enroll(enrollment)
        return {"actualPanelBootstrap": True, "actualInitialCanonicalCommit": True,
            "enrollmentCommitted": True, "operatorStarted": False, "production": False}

    def initialize_and_start(self, image, helm, chart, node_name=""):
        self.panel.connect()
        self.panel.login()
        self.panel.unseal()
        current = self.current()
        plan_file = self.private / "initialization-plan.json"
        if plan_file.exists():
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            if plan["body"]["cursor"] != current["cursor"]:
                raise RuntimeError("Journal advanced after saved initialization authorization")
        else:
            plan = self.app.recovery_plan(current)
            write_private(plan_file, canonical(plan))
        who = json.loads(self.cluster.kube("auth", "whoami", "-o", "json").stdout)["status"]["userInfo"]
        subject = {"username": who["username"], "uid": who.get("uid", "")}
        values = self.app.chart_values(image, subject, self.gateway_origin,
            (self.private / "journal-ca.crt").read_bytes(), node_name)
        envelope, wrap = self.panel.offline_export()
        # Recovery consumes the SAME normalized RootConfig as the chart, with
        # explicit HA, rollout allowlists and protected credential pins.
        import yaml
        render_values = self.private / "recovery-render-values.json"
        if render_values.exists():
            if render_values.read_bytes() != canonical(values):
                raise RuntimeError("Initialization configuration changed after authorization")
        else:
            write_private(render_values, canonical(values))
        rendered = subprocess.run([str(helm), "template", "stage6", str(chart), "-n", self.app.namespace,
            "-f", str(render_values)], capture_output=True, text=True, timeout=60)
        if rendered.returncode:
            raise RuntimeError("Recovery installation rendering failed")
        installations = [json.loads(value["data"]["installation.json"])
            for value in yaml.safe_load_all(rendered.stdout) if value and value["kind"] == "ConfigMap"
            and "installation.json" in value.get("data", {})]
        if len(installations) != 1:
            raise RuntimeError("Ambiguous chart installation RootConfig")
        self.panel.recover(plan, envelope, wrap, installations[0])
        self.app.start_application_after_initialize()
        self.app.install_chart(values, helm, chart)
        self.cluster.kube("-n", self.app.namespace, "rollout", "status", "deployment/stage6-fencer", "--timeout=180s")
        self.cluster.kube("-n", self.app.namespace, "rollout", "status", "deployment/stage6-operator", "--timeout=180s")
        wait(lambda: self.app.current(current["snapshot"], True), timeout=240)
        return {"signedCheckpointInitializeComplete": True, "twoOperatorReplicas": True,
            "twoFencerReplicas": True, "initialDataCurrent": True, "production": False}

    def current(self):
        return self.panel.current()

    def publish(self, generation, demo):
        return self.panel.publish(generation, demo)

    def normalize_active_installation(self, image, helm, chart, node_name=""):
        """Explicit post-TLS repair render, without adopting a live difference.

        Original initialization values stay immutable. The old operator spec
        must still match that render plus the separately approved image change.
        Only its installation ConfigMap reference may change in this step.
        """
        import yaml
        who = json.loads(self.cluster.kube("auth", "whoami", "-o", "json").stdout)["status"]["userInfo"]
        values = self.app.chart_values(image, {"username": who["username"], "uid": who.get("uid", "")},
            self.gateway_origin, (self.private / "journal-ca.crt").read_bytes(), node_name)
        old_values = json.loads((self.private / "application-values.json").read_text(encoding="utf-8"))
        old_values["image"] = copy.deepcopy(values["image"])

        def render(selected, label):
            path = self.private / (label + ".json")
            raw = canonical(selected)
            if path.exists():
                if path.read_bytes() != raw:
                    raise RuntimeError("Active installation render authorization changed")
            else:
                write_private(path, raw)
            result = subprocess.run([str(helm), "template", "stage6", str(chart), "-n", self.app.namespace,
                "-f", str(path)], capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError("Active installation Helm render failed")
            return {(v["kind"], v["metadata"]["name"]): v for v in yaml.safe_load_all(result.stdout) if v}

        old_render = render(old_values, "normalization-prior-values")
        new_render = render(values, "active-values-normalized")
        current = self.app.get("Deployment", "stage6-operator")

        def normalized(desired):
            proposed = copy.deepcopy(desired)
            proposed["metadata"].update(uid=current["metadata"]["uid"], resourceVersion=current["metadata"]["resourceVersion"])
            return json.loads(self.cluster.kube("replace", "--dry-run=server", "-f", "-", "-o", "json",
                data=json.dumps(proposed)).stdout)["spec"]

        old_spec = normalized(old_render[("Deployment", "stage6-operator")])
        new_spec = normalized(new_render[("Deployment", "stage6-operator")])
        if current["spec"] != old_spec:
            raise RuntimeError("Operator differs from its explicit prior render")
        permitted = copy.deepcopy(old_spec)
        changed = 0
        for old_volume, new_volume in zip(permitted["template"]["spec"]["volumes"], new_spec["template"]["spec"]["volumes"]):
            if old_volume["name"] == "installation":
                old_volume["configMap"]["name"] = new_volume["configMap"]["name"]
                changed += 1
        if changed != 1 or permitted != new_spec:
            raise RuntimeError("TLS normalization changed another operator field")
        config_maps = [v for (kind, _), v in new_render.items() if kind == "ConfigMap" and "installation.json" in v.get("data", {})]
        if len(config_maps) != 1:
            raise RuntimeError("Ambiguous normalized installation ConfigMap")
        self.app.create(config_maps[0])
        self.app.patch("Deployment", "stage6-operator", [{"op": "test", "path": "/spec", "value": old_spec},
            {"op": "replace", "path": "/spec", "value": new_spec}])
        self.cluster.kube("-n", self.app.namespace, "rollout", "status", "deployment/stage6-operator", "--timeout=180s")
        return values

    def _scale_own(self, role, name, replicas):
        namespace = self.namespaces[role]
        pins = [json.loads(path.read_text()) for path in self.cluster.pins.glob("*.json")]
        pin = next((value for value in pins if (value["kind"], value["namespace"], value["name"]) ==
            ("Deployment", namespace, name)), None)
        if pin is None:
            raise RuntimeError("Outage target lacks own creation UID")
        live = json.loads(self.cluster.kube("get", "deployment", name, "-n", namespace, "-o", "json").stdout)
        if live["metadata"]["uid"] != pin["uid"] or live["metadata"].get("deletionTimestamp"):
            raise RuntimeError("Outage target replaced")
        patch = [{"op": "test", "path": "/metadata/uid", "value": pin["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": live["metadata"]["resourceVersion"]},
            {"op": "replace", "path": "/spec/replicas", "value": replicas}]
        self.cluster.kube("patch", "deployment", name, "-n", namespace, "--type=json", "-p", json.dumps(patch))

    @contextmanager
    def outage(self, label):
        targets = {"panel": [("panel", "panel", 1)], "witness": [("witness", "witness-a", 1),
            ("witness", "witness-b", 1)], "fencer": [("apps", "stage6-fencer", 2)]}
        if label not in targets:
            raise ValueError("Unapproved trial dependency outage")
        try:
            for role, name, _ in targets[label]:
                self._scale_own(role, name, 0)
                self.cluster.kube("-n", self.namespaces[role], "rollout", "status", "deployment/" + name, "--timeout=120s")
            yield
        finally:
            for role, name, replicas in targets[label]:
                self._scale_own(role, name, replicas)
                self.cluster.kube("-n", self.namespaces[role], "rollout", "status", "deployment/" + name, "--timeout=180s")
            if label == "panel":
                self.panel.connect()
                self.panel.login()
                self.panel.unseal()
            if label == "witness":
                self.witness_forward.close()
                self.witness_forward = Forward(self.cluster, self.namespaces["witness"], "service/witness", 8443)
                self.client = JournalClient(self.witness_forward.origin, self.private / "journal-ca.crt",
                    self.private / "admin.crt", self.private / "admin.key")
                self.panel.witness_client = self.client
