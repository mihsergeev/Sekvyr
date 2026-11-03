"""Reproducible actual Plain/Helm/application sequence; values stay private."""

import base64
import hashlib
import json
import re
import uuid

from application import wait
from app_modes import Stage7Applications, require
from fixture import canonical, write_private
from panel_cases import PanelCases
from plain_installation import PlainInstallation
from plain_rollout import enable_rollout

PYTHON = "docker.io/library/python@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8"
AGENT = "ghcr.io/mihsergeev/sekvyr-agent@sha256:efa4b55850a1e0ea5b31907991dae8fa163bb7218c648dc8d8b609b90d96d884"


class PlainCases:
    def __init__(self, coordinator, image, helm, chart):
        self.c = coordinator
        self.provider = PanelCases(coordinator, "plain-main")
        self.installation = PlainInstallation(coordinator, self.provider, image, helm, chart)
        self.apps = Stage7Applications(coordinator.cluster, self.installation.namespace, PYTHON, AGENT)
        self.root = coordinator.private / "plain-cases"
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.target_name, self.env_name, self.volume_name, self.agent_name = "plain-runtime-env", "plain-env-app", "plain-volume-app", "legacy-agent-app"
        self.proofs = []

    def __repr__(self):
        return "<actual stage7 Plain cases [redacted]>"

    def pair(self, label):
        path = self.root / (label + "-values.json")
        if not path.exists():
            write_private(path, canonical({"generation": "stage7-" + uuid.uuid4().hex, "demo": uuid.uuid4().hex}))
        return json.loads(path.read_bytes())

    def proof(self, label, facts):
        value = {"id": label, "status": "PASS", "production": False, **facts}
        write_private(self.root / (label + "-proof.json"), canonical(value))
        self.proofs.append(value)
        print(json.dumps(value), flush=True)
        return value

    def poke(self):
        p = self.installation
        current = p.owned.get("SekvyrSecret", p.cr_name)
        annotations = dict(current["metadata"].get("annotations", {}), **{"stage7-trial-reconcile": uuid.uuid4().hex})
        p.owned.patch("SekvyrSecret", p.cr_name, [{"op": "add", "path": "/metadata/annotations", "value": annotations}])

    def publish(self, pair):
        p = self.installation
        before = p.owned.get("SekvyrSecret", p.cr_name).get("status", {}).get("lastSuccessfulSyncTime")
        self.provider.publish(pair["generation"], pair["demo"])
        self.poke()
        wait(lambda: p.current(after_success=before))
        target = p.target_ref(pair["generation"], pair["demo"], after_success=before)
        self.selected = pair
        return target

    def initial(self, before_first_publish=None):
        """A coordinator hook may install reviewed paths after Helm capture."""
        require(before_first_publish is None or callable(before_first_publish), "Explicit first-publish hook must be callable")
        p = self.installation
        p.prepare()
        self.apps.create_env(self.env_name, self.target_name, replicas=0)
        self.apps.create_volume(self.volume_name, self.target_name, replicas=0)
        p.prepare_store(self.target_name)
        p.install()
        if before_first_publish is not None:
            before_first_publish(self)
        return self.initial_after_install()

    def initial_after_install(self):
        """Continue an in-memory lifecycle after a pre-create CLI flag repair."""
        p = self.installation
        pair = self.pair("initial")
        target = self.publish(pair)
        for name in (self.env_name, self.volume_name):
            self.apps.owned.patch("Deployment", name, [{"op": "replace", "path": "/spec/replicas", "value": 1}])
            wait(lambda: value if (value := self.apps.status(name)) and value["generation"] == pair["generation"] else False)
            require(len(self.apps.footprint(name)["replica_sets"]) == 1, "Initial application gained historical ReplicaSets")
        self.reference = target
        self.baselines = {name: self.apps.capture(name) for name in (self.env_name, self.volume_name)}
        return self.proof("plain-initial", {"actualHelmInstall": True, "plainTargetUIDFromProtectedState": True,
            "initialEnvAndVolumeVerified": True, "noHistoricalRollout": True})

    def changed_rollout_off(self):
        before = {name: self.apps.capture(name) for name in (self.env_name, self.volume_name)}
        self.publish(self.pair("off-change"))
        self.apps.frozen(self.env_name, before[self.env_name], seconds=2)
        self.apps.assert_reloaded_without_restart(self.volume_name, before[self.volume_name], self.selected["generation"], self.selected["demo"])
        return self.proof("plain-rollout-off", {"envFromKeptOldProcess": True, "volumeReloadedWithoutRestart": True})

    def opt_in(self):
        enable_rollout(self.installation, [self.env_name])
        return self.proof("plain-explicit-opt-in", {"actualHelmUpgrade": True, "noHistoricalRollout": True})

    def changed_rollout_on(self):
        before = {name: self.apps.capture(name) for name in (self.env_name, self.volume_name)}
        target = self.publish(self.pair("on-change"))
        result = self.apps.assert_env_changed(self.env_name, before[self.env_name], self.selected["generation"], self.selected["demo"], target)
        self.apps.assert_reloaded_without_restart(self.volume_name, before[self.volume_name], self.selected["generation"], self.selected["demo"])
        return self.proof("plain-rollout-on", dict(result, volumeReloadedWithoutRestart=True))

    def agent(self):
        self.agent_provider = PanelCases(self.c, "plain-agent")
        self.apps.owned.create_service_account("legacy-agent")
        route = self.agent_provider.prepare_plain("legacy-agent", namespace=self.installation.namespace)
        pair = self.pair("agent-initial")
        self.agent_provider.publish(pair["generation"], pair["demo"])
        self.apps.create_agent(self.agent_name, route["source_config"], "legacy-agent",
            {"name": self.installation.ca_name, "key": "ca.crt"}, token_expiration=600)
        wait(lambda: value if (value := self.apps.status(self.agent_name)) and value["generation"] == pair["generation"] else False)
        before = self.apps.capture(self.agent_name)
        require(before["status"].get("initial_loaded") is True, "Agent did not gate initial application startup")
        pair = self.pair("agent-change")
        self.agent_provider.publish(pair["generation"], pair["demo"])
        self.apps.assert_reloaded_without_restart(self.agent_name, before, pair["generation"], pair["demo"])
        self.agent_selected = pair
        return self.proof("published-agent-init-sidecar", {"publishedAgentUnchanged": True, "initialRenderBeforeApplication": True,
            "samePodReloadedAfterAgentFileUpdate": True, "projectedTokenExpirationRequestedSeconds": 600})

    def equal(self):
        names = (self.env_name, self.volume_name, self.agent_name)
        before = {name: self.apps.capture(name) for name in names}
        target = self.apps.target(self.installation.target_ref())
        revision = target["metadata"]["annotations"]["secrets.sekvyr.ru/revision"]
        self.publish(self.selected)
        self.agent_provider.publish(self.agent_selected["generation"], self.agent_selected["demo"])
        for name in names:
            self.apps.frozen(name, before[name], seconds=2)
        actual = self.apps.target(self.installation.target_ref())
        require(actual["metadata"]["annotations"]["secrets.sekvyr.ru/revision"] == revision, "Equal Plain data rotated opaque revision")
        return self.proof("plain-equality", {"freshPlainSync": True, "noExtraReplicaSetPodOrBoot": True, "opaqueRevisionUnchanged": True})

    def token(self):
        name = self.agent_name
        footprint = self.apps.footprint(name)
        pods = json.loads(self.c.cluster.kube("get", "pods", "-n", self.installation.namespace,
            "-l", "secrets.sekvyr.ru/stage7-app=" + name, "-o", "json").stdout)["items"]
        active = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp") and any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod.get("status", {}).get("conditions", []))]
        require(len(active) == 1, "Stable legacy agent Pod is not unique/ready")
        pod = active[0]
        require(any(ref.get("kind") == "ReplicaSet" and ref.get("uid") in footprint["replica_sets"] for ref in pod["metadata"].get("ownerReferences", [])), "Agent Pod owner differs")
        statuses = [s for s in pod["status"].get("containerStatuses", []) if s["name"] == "sekvyr-agent" and s.get("state", {}).get("running")]
        require(len(statuses) == 1 and re.fullmatch(r"containerd://[0-9a-f]{64}", statuses[0].get("containerID", "")), "Agent container identity unavailable")
        raw = self.c.cluster.kube("exec", pod["metadata"]["name"], "-n", self.installation.namespace, "-c", "sekvyr-agent", "--", "cat", "/var/run/secrets/sekvyr/token").stdout.strip()
        require(0 < len(raw) <= 8000, "Projected agent token bounds invalid")
        return {"token": raw, "pod_uid": pod["metadata"]["uid"], "container_id": statuses[0]["containerID"]}
