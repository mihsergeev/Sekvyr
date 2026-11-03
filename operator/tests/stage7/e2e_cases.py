"""Actual E2E2 plus native Helm lifecycle in the coordinator's owned trial.

No action runs on import. Keep the object alive on failure: preparation and
signed initialization are one-shot, never an adoption or automatic rebase.
"""

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid
import re

from application import APP, TARGET, RELEASE, RESOURCE, STORE, SA, FENCER_SA, LEASE, REVISION, wait
from app_modes import require
from fixture import canonical, issue_leaf, write_private
from helm_lifecycle import HelmLifecycle, identity
from fresh_helm_sync import FreshHelmSync

PYTHON = "docker.io/library/python@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8"


def reviewed_values(app, image, subject, origin, ca, node_name):
    values = app.chart_values(image, subject, origin, ca, node_name)
    values["serviceAccount"] = {"create": False, "uid": app.get("ServiceAccount", SA)["metadata"]["uid"]}
    values["leaderElection"].update(create=False, uid=app.get("Lease", LEASE)["metadata"]["uid"])
    values["ha"]["fencer"]["serviceAccount"]["create"] = False
    require(values["ha"]["fencer"]["serviceAccount"]["uid"] == app.get("ServiceAccount", FENCER_SA)["metadata"]["uid"],
        "E2E2 fencer account pin differs")
    values["resources"] = {"requests": {"cpu": "25m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "128Mi"}}
    values["auth"] = {"tokenExpirationSeconds": 600}
    values["configuration"] = {"retain": True}
    return values


def replicas_current(app):
    for name in (RELEASE + "-operator", RELEASE + "-fencer"):
        deployment = app.get("Deployment", name)
        require(deployment["spec"]["replicas"] == 2, "E2E2 reviewed replica count changed")
        status = deployment.get("status", {})
        if status.get("observedGeneration") != deployment["metadata"]["generation"] or any(
                status.get(field, 0) != 2 for field in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas")):
            return False
    return True


def owned_component_snapshot(e, component):
    require(component in ("operator", "fencer"), "Unreviewed Helm component")
    deployment = e.app.get("Deployment", RELEASE + "-" + component)
    selector = deployment["spec"]["selector"]
    require(set(selector) == {"matchLabels"} and selector["matchLabels"], "Exact component selector required")
    label = ",".join(key + "=" + value for key, value in sorted(selector["matchLabels"].items()))
    def listed(kind):
        return json.loads(e.c.cluster.kube("get", kind, "-n", e.app.namespace, "-l", label, "-o", "json").stdout)["items"]
    sets = listed("replicasets")
    for value in sets:
        owners = [owner for owner in value["metadata"].get("ownerReferences", []) if owner.get("controller") is True]
        require(value["metadata"].get("namespace") == e.app.namespace and len(owners) == 1
            and owners[0].get("kind") == "Deployment" and owners[0].get("apiVersion") == "apps/v1"
            and owners[0].get("uid") == deployment["metadata"]["uid"]
            and owners[0].get("name") == deployment["metadata"]["name"], "Component ReplicaSet has foreign owner")
    parent = {value["metadata"]["uid"]: value["metadata"]["name"] for value in sets}
    pods = listed("pods")
    require(len(pods) == 2, "Exactly two physical component Pods required")
    instances = []
    for pod in pods:
        owners = [owner for owner in pod["metadata"].get("ownerReferences", []) if owner.get("controller") is True]
        require(pod["metadata"].get("namespace") == e.app.namespace and not pod["metadata"].get("deletionTimestamp")
            and len(owners) == 1 and owners[0].get("kind") == "ReplicaSet" and owners[0].get("apiVersion") == "apps/v1"
            and owners[0].get("uid") in parent and owners[0].get("name") == parent[owners[0]["uid"]]
            and pod["spec"].get("serviceAccountName") == deployment["spec"]["template"]["spec"]["serviceAccountName"], "Component Pod has foreign owner or is replacing")
        statuses = pod.get("status", {}).get("containerStatuses", [])
        require(len(statuses) == len(pod["spec"]["containers"]) and len({value.get("name") for value in statuses}) == len(statuses)
            and {value.get("name") for value in statuses} == {value.get("name") for value in pod["spec"]["containers"]}
            and all(value.get("ready") is True
            and value.get("state", {}).get("running") is not None and re.fullmatch(r"containerd://[0-9a-f]{64}", value.get("containerID", ""))
            and type(value.get("restartCount")) is int for value in statuses), "Component process is not uniquely ready")
        instances.append({"uid": pod["metadata"]["uid"], "name": pod["metadata"]["name"], "replicaSetUID": owners[0]["uid"],
            "containers": sorted((value["name"], value["containerID"], value["restartCount"]) for value in statuses)})
    require(len({value["uid"] for value in instances}) == 2, "Component Pod UIDs are not unique")
    return {"deploymentUID": deployment["metadata"]["uid"], "generation": deployment["metadata"]["generation"],
        "template": copy.deepcopy(deployment["spec"]["template"]), "replicaSets": sorted(parent), "pods": sorted(instances, key=lambda value: value["uid"])}


def old_component_pods_absent(e, component, uids):
    require(component in ("operator", "fencer") and len(uids) == 2 and len(set(uids)) == 2,
        "Two exact previous component Pod UIDs required")
    e.app.get("Deployment", RELEASE + "-" + component)  # Creation UID / namespace guard.
    pods = json.loads(e.c.cluster.kube("get", "pods", "-n", e.app.namespace, "-o", "json").stdout)["items"]
    # Include deleting Pods and ignore selector/Ready: physical absence is the
    # requirement. A changed ReplicaSet count is not an equivalent proof.
    return not any(value["metadata"]["uid"] in uids for value in pods)


def _memory_values(e):
    path = e.root / "reviewed-values.json"
    require(path.is_file() and not path.is_symlink(), "Original reviewed upgrade values required")
    original = json.loads(path.read_bytes())
    require(original["resources"]["limits"]["memory"] == "128Mi", "Original memory phase differs")
    values = copy.deepcopy(original)
    values["resources"]["limits"]["memory"] = "160Mi"
    return original, values


def _memory_render(e, original, values):
    before, _ = e.lifecycle.render(original)
    after, _ = e.lifecycle.render(values)
    prior, incoming = ({identity(value): value for value in items} for items in (before, after))
    require(len(prior) == len(before) and len(incoming) == len(after) and set(prior) == set(incoming),
        "Memory upgrade changed the resource identities")
    changed = set()
    for key, value in prior.items():
        expected = copy.deepcopy(value)
        if value["kind"] == "Deployment":
            require(value["metadata"]["namespace"] == e.app.namespace
                and value["metadata"]["name"] in (RELEASE + "-operator", RELEASE + "-fencer"),
                "Unexpected memory-upgrade Deployment")
            containers = expected["spec"]["template"]["spec"]["containers"]
            require(len(containers) == 1 and containers[0]["resources"]["limits"]["memory"] == "128Mi",
                "Original component memory differs")
            containers[0]["resources"]["limits"]["memory"] = "160Mi"
            changed.add(value["metadata"]["name"])
        require(incoming[key] == expected, "Memory upgrade changes fields beyond both component memory limits")
    require(changed == {RELEASE + "-operator", RELEASE + "-fencer"}, "Both component templates must change")
    return incoming


def _native_memory_guard(e, values):
    e.lifecycle._external_guard()
    e.lifecycle._retained_guard()
    rendered, _ = e.lifecycle.render(values)
    incoming = {identity(value): value for value in rendered}
    require(len(incoming) == len(rendered) and set(incoming) == set(e.lifecycle.managed), "Captured upgrade resource set differs")
    for key, saved in e.lifecycle.managed.items():
        require(saved["manifest"] == incoming[key], "Captured native upgrade manifest differs")
        current = e.lifecycle._get(saved["manifest"])
        e.lifecycle._owned(current, saved["uid"])
        e.lifecycle._matches(current, saved["manifest"])


def _unchanged_upgrade_data(e, context, target, before, old):
    current = e.c.current()
    require(all(current[field] == context[field] for field in ("snapshot", "authority", "enrollments")),
        "Memory upgrade changed canonical context")
    actual = e.app.get("Secret", TARGET)
    require(actual["metadata"]["uid"] == target["metadata"]["uid"] and actual["data"] == target["data"]
        and actual["metadata"]["annotations"][REVISION] == target["metadata"]["annotations"][REVISION],
        "Memory upgrade changed target data or revision")
    require(e.app.footprint() == before, "Memory upgrade changed application footprint")
    status = wait(e.app.status)
    require(all(field in old and status.get(field) == old[field] for field in ("pod_uid", "boot_id", "generation", "value_digest")),
        "Memory upgrade changed application process or values")


def _finish_memory_upgrade(e, *, values, context, target, before, old, old_operators, fencers, expected_cr, expected_store):
    require(e.installed and e.values == values, "Exact completed memory-upgrade values required")
    old_fencers = [pod["uid"] for pod in fencers["pods"]]
    require(len(old_operators) == len(old_fencers) == 2 and len(set(old_operators + old_fencers)) == 4,
        "Four distinct old component Pod UIDs required")
    path = e.root / "e2e2-helm-upgrade-cutover.json"
    require(not path.exists() and not path.is_symlink() and not (e.root / "e2e2-helm-upgrade-proof.json").exists(),
        "Upgrade observation already advanced")
    _native_memory_guard(e, values)
    wait(lambda: replicas_current(e.app), timeout=240)
    wait(lambda: old_component_pods_absent(e, "operator", old_operators), timeout=240)
    wait(lambda: old_component_pods_absent(e, "fencer", old_fencers), timeout=240)
    for role, previous in (("operator", old_operators), ("fencer", old_fencers)):
        component = owned_component_snapshot(e, role)
        require(not set(previous).intersection(pod["uid"] for pod in component["pods"]), "Old component Pod still present")
        if role == "fencer":
            require(component["deploymentUID"] == fencers["deploymentUID"], "Fencer Deployment replaced")
    _unchanged_upgrade_data(e, context, target, before, old)
    baseline = e.app.get("SekvyrSecret", RESOURCE)["status"]["lastSuccessfulSyncTime"]
    cutover = datetime.now(timezone.utc)
    write_private(path, canonical({"cutover": cutover.isoformat(), "baselineLastSuccess": baseline,
        "oldOperatorPodUIDs": old_operators, "oldFencerPodUIDs": old_fencers,
        "oldOperatorsPhysicallyAbsent": True, "oldFencersPhysicallyAbsent": True, "snapshot": context["snapshot"]}))
    require(old_component_pods_absent(e, "operator", old_operators), "Old operator returned before fresh gate")
    gate = FreshHelmSync(e.app, context["snapshot"], cutover=cutover, baseline_last_success=baseline,
        expected_cr_generation=expected_cr["metadata"]["generation"], expected_store_uid=expected_store["metadata"]["uid"],
        expected_store_generation=expected_store["metadata"]["generation"],
        old_owned_fencers_absent=old_component_pods_absent(e, "fencer", old_fencers), cr_name=RESOURCE, store_name=STORE)
    gate.wait(poke=True)
    _unchanged_upgrade_data(e, context, target, before, old)
    e.app.frozen(before)
    return e.proof("e2e2-helm-upgrade", {"actualHelmUpgrade": True, "externalUIDsPreserved": True, "appPodAndBootUnchanged": True,
        "oldOperatorPodsPhysicallyAbsent": True, "oldFencerPodsPhysicallyAbsent": True, "freshPostUpgradeSync": True})


def resume_after_upgrade(e, retained_upgrade_frame):
    """Observe the exact already-completed native upgrade; never repeat it."""
    frame = retained_upgrade_frame.f_locals if hasattr(retained_upgrade_frame, "f_locals") else retained_upgrade_frame
    required = {"self", "values", "context", "target", "old", "fencers", "before", "old_operators", "expected_cr", "expected_store"}
    require(isinstance(frame, dict) and required.issubset(frame) and frame["self"] is e and e.installed,
        "Exact retained incomplete upgrade frame required")
    original, expected = _memory_values(e)
    require(frame["values"] == expected == e.values, "Retained upgrade values differ from reviewed memory-only change")
    _memory_render(e, original, expected)
    _native_memory_guard(e, expected)
    _unchanged_upgrade_data(e, frame["context"], frame["target"], frame["before"], frame["old"])
    marker = e.root / "e2e2-helm-upgrade-observer-resume.json"
    require(not marker.exists() and not marker.is_symlink()
        and not (e.root / "e2e2-helm-upgrade-cutover.json").exists()
        and not (e.root / "e2e2-helm-upgrade-proof.json").exists(), "Upgrade observer resume already attempted")
    write_private(marker, canonical({"format": "sekvyr-stage7-upgrade-observer-resume-v1",
        "retainedInputsSHA256": hashlib.sha256(canonical({key: frame[key] for key in required - {"self"}})).hexdigest(),
        "originalAttemptIncomplete": True, "repeatedHelmOrPublish": False, "production": False}))
    return _finish_memory_upgrade(e, **{key: frame[key] for key in required - {"self"}})


class E2E2Cases:
    def __init__(self, coordinator, image, helm, chart):
        self.c, self.app = coordinator, coordinator.app
        self.image, self.helm, self.chart = image, Path(helm), Path(chart)
        self.root = coordinator.private / "e2e-cases"
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.lifecycle, self.values = None, None
        self.prepared = self.initialized = self.installed = False

    def __repr__(self):
        return "<actual E2E2 Helm cases [redacted]>"

    def pair(self, label):
        path = self.root / (label + "-values.json")
        if not path.exists():
            write_private(path, canonical({"generation": "stage7-e2e-" + uuid.uuid4().hex, "demo": uuid.uuid4().hex}))
        return json.loads(path.read_bytes())

    def proof(self, label, facts):
        value = {"id": label, "status": "PASS", "production": False, **facts}
        write_private(self.root / (label + "-proof.json"), canonical(value))
        print(json.dumps(value), flush=True)
        return value

    def prepare(self):
        c, app = self.c, self.app
        require(not self.prepared and not (self.root / "initial-envelope.json").exists(), "E2E2 preparation cannot reset an earlier attempt")
        current = c.current()
        require(current["scope"] == c.protocol.scope and current["genesis_hash"] == c.protocol.genesis_hash
            and current["snapshot"]["sequence"] == "0", "E2E2 needs the independently known empty data log")
        self.selected = pair = self.pair("initial")
        envelope, digest = c.protocol.snapshot(1, "0" * 64, pair["generation"], pair["demo"])
        self.initial_snapshot = {"sequence": "1", "envelope_hash": digest}
        write_private(self.root / "initial-envelope.json", canonical(envelope))
        write_private(self.root / "intended-checkpoint.json", canonical(self.initial_snapshot))
        # Explicitly issue both webhook and product SANs before the Secret is
        # created. The original immutable genesis/root keys stay unchanged.
        host = RELEASE + "-fencer." + app.namespace + ".svc"
        label = "fencer-server-admission"
        require(not (c.private / (label + ".key")).exists() and not (c.private / (label + ".crt")).exists(),
            "E2E2 TLS preparation may not regenerate saved material")
        issue_leaf(c.task, "journal", label, "server", [host, host + ".cluster.local", "localhost"])
        materials = c.materials()
        materials.update(fencer_tls_cert=(c.private / (label + ".crt")).read_bytes(),
            fencer_tls_key=(c.private / (label + ".key")).read_bytes())
        enrollment = app.prepare(PYTHON, c.panel_origin, c.witness_origin, self.initial_snapshot, materials)
        override = {"fencerTLS": {"name": app.fencer_tls_secret_name,
            "uid": app.get("Secret", app.fencer_tls_secret_name)["metadata"]["uid"], "label": label}}
        write_private(c.private / "fixture-overrides.json", canonical(override))
        c.overrides = override
        c.panel.bootstrap()
        snapshot = c.panel.publish_sealed(envelope, digest)
        require(snapshot["sequence"] == "1" and snapshot["envelope_hash"] == digest, "E2E2 initial commit differs")
        c.panel.grant_reader()
        c.panel.enroll(enrollment)
        self.prepared = True
        return self.proof("e2e2-prepared", {"actualPanelCanonicalCommit": True, "signedEnrollment": True, "operatorStarted": False})

    def initialize(self):
        require(self.prepared and not self.initialized and self.lifecycle is None, "E2E2 initialization requires this exact prepared instance")
        c, app = self.c, self.app
        current = c.current()
        require(current["snapshot"]["sequence"] == self.initial_snapshot["sequence"]
            and current["snapshot"]["envelope_hash"] == self.initial_snapshot["envelope_hash"], "E2E2 initialization snapshot advanced")
        plan = app.recovery_plan(current)
        write_private(self.root / "initialization-plan.json", canonical(plan))
        who = json.loads(c.cluster.kube("auth", "whoami", "-o", "json").stdout)["status"]["userInfo"]
        subject = {"username": who["username"], "uid": who.get("uid", "")}
        params = json.loads((c.task / "infrastructure-parameters.json").read_bytes())
        self.values = reviewed_values(app, self.image, subject, c.gateway_origin,
            (c.private / "journal-ca.crt").read_bytes(), params["node_name"])
        external = [{"kind": kind, "name": name, "uid": pin["uid"]} for (kind, name), pin in app.created.items()]
        self.lifecycle = HelmLifecycle(c.cluster, self.helm, self.chart, RELEASE, app.namespace, external)
        rendered, _ = self.lifecycle.render(self.values)
        configs = [json.loads(value["data"]["installation.json"]) for value in rendered
            if value["kind"] == "ConfigMap" and "installation.json" in value.get("data", {})]
        require(len(configs) == 1, "E2E2 recovery installation rendering is ambiguous")
        write_private(self.root / "reviewed-values.json", canonical(self.values))
        write_private(self.root / "reviewed-installation.json", canonical(configs[0]))
        envelope, wrap = c.panel.offline_export()
        write_private(self.root / "initialization-envelope.json", envelope)
        write_private(self.root / "initialization-reader-wrap.json", wrap)
        if c.task.parent == Path("/var/tmp"):
            from kind_recovery import recover
        else:
            from host_recovery import recover
        recover(c.panel, plan, envelope, wrap, configs[0])
        app.start_application_after_initialize()
        self.initialized = True
        return self.proof("e2e2-signed-initialization", {"signedCheckpointInitialization": True, "initialEnvFromVerifiedBeforeOperator": True})

    def register_managed(self):
        for saved in self.lifecycle.managed.values():
            value = saved["manifest"]
            if value["metadata"].get("namespace") == self.app.namespace:
                key = value["kind"], value["metadata"]["name"]
                require(key not in self.app.created or self.app.created[key]["uid"] == saved["uid"], "E2E2 Helm pin collides with an external UID")
                self.app.created[key] = {"uid": saved["uid"]}

    def install(self):
        require(self.initialized and not self.installed, "E2E2 install requires signed initialization")
        self.lifecycle.install(self.values)
        self.register_managed()
        wait(lambda: replicas_current(self.app), timeout=240)
        wait(lambda: self.app.current(self.initial_snapshot, True), timeout=240)
        status = wait(self.app.status)
        require(status["generation"] == self.selected["generation"] and status["value_digest"] == hashlib.sha256(self.selected["demo"].encode()).hexdigest(),
            "E2E2 initial envFrom values differ")
        footprint = self.app.footprint()
        require(len(footprint["replica_sets"]) == 1 and not footprint["template"]["metadata"].get("annotations"), "E2E2 initial data caused historical rollout")
        self.installed = True
        return self.proof("e2e2-initial", {"actualHelmInstall": True, "twoOperatorAndFencerReplicasReady": True,
            "signedFullSnapshotDecrypted": True, "initialEnvFromVerified": True, "noHistoricalRollout": True})

    def changed(self):
        require(self.installed, "E2E2 change requires this installed lifecycle")
        before, old = self.app.footprint(), wait(self.app.status)
        self.selected = pair = self.pair("changed")
        snapshot = self.c.publish(pair["generation"], pair["demo"])
        self.app.poke()
        wait(lambda: self.app.current(snapshot, True), timeout=240)
        new = wait(lambda: value if (value := self.app.status()) and value["generation"] == pair["generation"] else False)
        after = self.app.footprint()
        require(new["pod_uid"] != old["pod_uid"] and new["boot_id"] != old["boot_id"]
            and new["value_digest"] == hashlib.sha256(pair["demo"].encode()).hexdigest(), "E2E2 new envFrom process differs")
        require(len(set(after["replica_sets"]) - set(before["replica_sets"])) == 1, "E2E2 change must create exactly one new ReplicaSet")
        target = self.app.get("Secret", TARGET)
        expected = copy.deepcopy(before["template"])
        expected["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/restart-" + target["metadata"]["uid"]] = target["metadata"]["annotations"][REVISION]
        require(after["template"] == expected, "E2E2 rollout changed another template field")
        return self.proof("e2e2-changed", {"actualCanonicalAdvance": True, "newEnvFromPodAndBoot": True, "newReplicaSets": 1, "onlyOwnRestartAnnotation": True})

    def equal(self, label="e2e2-equal"):
        require(self.installed, "E2E2 equality requires this installed lifecycle")
        require(isinstance(label, str) and label in ("e2e2-equal", "e2e2-post-node-equal"), "Unreviewed E2E2 equality proof label")
        path = self.root / (label + "-proof.json")
        require(not path.exists() and not path.is_symlink(), "Existing equality proof cannot be reused before another publication")
        before, old = self.app.footprint(), wait(self.app.status)
        target = self.app.get("Secret", TARGET)
        snapshot = self.c.publish(self.selected["generation"], self.selected["demo"])
        self.app.poke()
        wait(lambda: self.app.current(snapshot, True), timeout=240)
        actual = self.app.get("Secret", TARGET)
        require(actual["metadata"]["uid"] == target["metadata"]["uid"] and actual["data"] == target["data"]
            and actual["metadata"]["annotations"][REVISION] == target["metadata"]["annotations"][REVISION], "Equal E2E2 plaintext changed target data/revision")
        self.app.frozen(before)
        new = wait(self.app.status)
        require((new["pod_uid"], new["boot_id"]) == (old["pod_uid"], old["boot_id"]), "Equal E2E2 data restarted the app")
        return self.proof(label, {"newCanonicalCiphertextVerified": True, "sameDataRevisionPodBootAndReplicaSets": True})

    def upgrade(self):
        require(self.installed, "E2E2 upgrade requires this installed lifecycle")
        path = self.root / "e2e2-helm-upgrade-proof.json"
        require(not path.exists() and not path.is_symlink() and self.values["resources"]["limits"]["memory"] == "128Mi",
            "Memory upgrade requires the original unapplied 128Mi phase")
        before, old = self.app.footprint(), wait(self.app.status)
        context = self.c.current()
        expected_cr, expected_store = self.app.get("SekvyrSecret", RESOURCE), self.app.get("SekvyrStore", STORE)
        target = self.app.get("Secret", TARGET)
        old_operators = [pod["uid"] for pod in owned_component_snapshot(self, "operator")["pods"]]
        fencers = owned_component_snapshot(self, "fencer")
        values = copy.deepcopy(self.values)
        values["resources"]["limits"]["memory"] = "160Mi"
        original, expected_values = _memory_values(self)
        require(self.values == original and values == expected_values, "Upgrade baseline differs from reviewed initial values")
        _memory_render(self, original, values)
        self.lifecycle.upgrade(values)
        self.register_managed()
        self.values = values
        return _finish_memory_upgrade(self, values=values, context=context, target=target, before=before, old=old,
            old_operators=old_operators, fencers=fencers, expected_cr=expected_cr, expected_store=expected_store)

    def uninstall(self):
        require(self.installed, "E2E2 uninstall requires this installed lifecycle")
        self.lifecycle.uninstall()
        self.installed = False
        return self.proof("e2e2-helm-uninstall", {"actualHelmUninstall": True, "externalResourcesAndRetainedConfigPreserved": True})


def prepare_and_start(coordinator, image, helm, chart):
    case = E2E2Cases(coordinator, image, helm, chart)
    case.prepare()
    case.initialize()
    case.install()
    return case
