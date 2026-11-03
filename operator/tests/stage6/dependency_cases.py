"""Actual bounded dependency and interrupted-barrier trial cases."""

import base64
import copy
import hashlib
import json

from application import REVISION, TARGET, require, wait
from forward import Forward
from journal_client import JournalClient
from protocol import canonical, domain


def grant_hash(grant):
    return hashlib.sha256(domain("sekvyr-e2e2/fence-grant-hash/v1") + canonical(grant["body"])).hexdigest()


class DependencyCases:
    def __init__(self, coordinator):
        self.c, self.app = coordinator, coordinator.app

    def values(self):
        data = self.app.get("Secret", TARGET)["data"]
        return base64.b64decode(data["GENERATION"]).decode(), base64.b64decode(data["DEMO_VALUE"]).decode()

    def baseline(self):
        target = self.app.get("Secret", TARGET)
        return {"data": target["data"], "revision": target["metadata"]["annotations"][REVISION],
            "footprint": self.app.footprint(), "boot": wait(self.app.status)["boot_id"]}

    def unchanged(self, before):
        target = self.app.get("Secret", TARGET)
        require(target["data"] == before["data"] and target["metadata"]["annotations"][REVISION] == before["revision"],
            "Dependency case changed selected data or opaque revision")
        require(self.app.footprint() == before["footprint"] and wait(self.app.status)["boot_id"] == before["boot"],
            "Dependency case restarted the application")

    def reset_forward(self, target="service/witness"):
        require(target in ("service/witness", "service/witness-b"), "Unreviewed witness test route")
        self.c.witness_forward.close()
        self.c.witness_forward = Forward(self.c.cluster, self.c.namespaces["witness"], target, 8443)
        self.c.client = JournalClient(self.c.witness_forward.origin, self.c.private / "journal-ca.crt",
            self.c.private / "admin.crt", self.c.private / "admin.key")
        self.c.panel.witness_client = self.c.client

    def gateway_outage(self):
        before, snapshot = self.baseline(), self.c.current()["snapshot"]
        try:
            self.c._scale_own("gateway", "journal", 0)
            self.c.cluster.kube("-n", self.c.namespaces["gateway"], "rollout", "status", "deployment/journal", "--timeout=120s")
            self.app.poke()
            wait(self.app.unavailable)
            self.app.frozen(before["footprint"], seconds=7)
            self.unchanged(before)
        finally:
            self.c._scale_own("gateway", "journal", 1)
            self.c.cluster.kube("-n", self.c.namespaces["gateway"], "rollout", "status", "deployment/journal", "--timeout=180s")
        self.app.poke()
        wait(lambda: self.app.current(snapshot, True))
        self.unchanged(before)
        return {"gatewayOutageObservedDataCurrentFalse": True, "noDataRevisionOrApplicationRestart": True,
            "freshCurrentRecovered": True, "production": False}

    def one_witness(self):
        before = self.baseline()
        generation, demo = self.values()
        self.reset_forward("service/witness-b")
        try:
            self.c._scale_own("witness", "witness-a", 0)
            self.c.cluster.kube("-n", self.c.namespaces["witness"], "rollout", "status", "deployment/witness-a", "--timeout=120s")
            snapshot = self.c.publish(generation, demo)
            self.app.poke()
            wait(lambda: self.app.current(snapshot, True))
            self.unchanged(before)
        finally:
            self.c._scale_own("witness", "witness-a", 1)
            self.c.cluster.kube("-n", self.c.namespaces["witness"], "rollout", "status", "deployment/witness-a", "--timeout=180s")
            self.reset_forward()
        log = self.c.protocol.scope["log_id"]
        states = []
        for replica in ("witness-a", "witness-b"):
            with Forward(self.c.cluster, self.c.namespaces["witness"], "service/" + replica, 8443) as forward:
                client = JournalClient(forward.origin, self.c.private / "journal-ca.crt", self.c.private / "admin.crt", self.c.private / "admin.key")
                states.append(json.loads(client.request("GET", "/v2/logs/" + log + "/authority")[1]))
        require(states[0]["snapshot"] == states[1]["snapshot"] == snapshot and states[0]["authority"] == states[1]["authority"],
            "Restarted witness did not replay current authority and snapshot")
        return {"oneWitnessUnavailableFreshDataProgress": True, "restartedWitnessReplayAgreement": True,
            "equalDataNoRevisionOrRestart": True, "production": False}

    def partial_barrier(self):
        before = self.baseline()
        generation, demo = self.values()
        role = self.app.get("Role", "stage6-fencer")
        original = copy.deepcopy(role["rules"])
        reduced, changed = [], 0
        for rule in original:
            if rule.get("resources") == ["secrets"] and "patch" in rule.get("verbs", []) and TARGET in rule.get("resourceNames", []):
                require(rule["verbs"] == ["get", "patch"] and self.app.state_name in rule["resourceNames"],
                    "Unexpected managed-Secret barrier capability")
                retained = copy.deepcopy(rule)
                retained["resourceNames"] = [name for name in rule["resourceNames"] if name != TARGET]
                reduced.extend([retained, {"apiGroups": [""], "resources": ["secrets"], "resourceNames": [TARGET], "verbs": ["get"]}])
                changed += 1
            else:
                reduced.append(copy.deepcopy(rule))
        require(changed == 1, "Exactly one existing target patch permission must be reduced")
        self.app.patch("Role", "stage6-fencer", [{"op": "test", "path": "/rules", "value": original},
            {"op": "replace", "path": "/rules", "value": reduced}])
        actor = "system:serviceaccount:" + self.app.namespace + ":sekvyr-fencer"
        def permission(expected):
            result = self.c.cluster.kube("auth", "can-i", "patch", "secret/" + TARGET, "-n", self.app.namespace,
                "--as", actor, check=False)
            return result.returncode in (0, 1) and result.stdout.strip() == ("yes" if expected else "no")
        try:
            wait(lambda: permission(False), timeout=30)
            snapshot = self.c.publish(generation, demo)
            pod, holder = self.app.operator_pod()
            token = self.app.projected_token(pod)
            with Forward(self.c.cluster, self.app.namespace, "service/stage6-fencer", 9443) as forward:
                status, raw, _ = self.app.fencer_call(forward.origin, self.c.private / "journal-ca.crt", token, "acquire",
                    {"bootstrap_generation": self.app.generation, "expected_lease_holder_identity": holder})
                require(status == 200, "Current leader could not acquire the interrupted grant")
                acquired = json.loads(raw)
                status, raw, _ = self.app.fencer_call(forward.origin, self.c.private / "journal-ca.crt", token, "barriers",
                    {"grant_hash": acquired["grant_hash"]})
                require(status == 409 and json.loads(raw).get("reason") == "BarrierConflict", "Expected exact interrupted target barrier failure")
            state = self.c.current()
            grant = state["grants"][self.c.protocol.installation_id]
            digest = grant_hash(grant)
            activation = state["activations"].get(self.c.protocol.installation_id)
            require(grant["body"]["snapshot"] == snapshot and (activation is None or activation["body"]["grant_hash"] != digest),
                "Interrupted grant became active")
            matching = 0
            for reference in grant["body"]["objects"]:
                obj = self.app.get(reference["kind"], reference["name"])
                raw_fence = obj["metadata"].get("annotations", {}).get("secrets.sekvyr.ru/fence")
                matching += bool(raw_fence and json.loads(raw_fence).get("grant_hash") == digest)
            require(0 < matching < len(grant["body"]["objects"]), "Partial barrier progress was not actually observed")
            api_token = self.app.projected_token(pod, audience=None)
            denied = self.app.token_update_target(api_token, self.app.late_write_body(digest))
            require(denied == 403, "Ordinary writer used an inactive partial grant")
            self.app.poke()
            wait(self.app.unavailable)
            self.unchanged(before)
        finally:
            self.app.patch("Role", "stage6-fencer", [{"op": "test", "path": "/rules", "value": reduced},
                {"op": "replace", "path": "/rules", "value": original}])
            wait(lambda: permission(True), timeout=30)
        self.app.poke()
        wait(lambda: self.app.current(snapshot, True))
        self.unchanged(before)
        return {"partialBarrierProgressObserved": True, "activationAbsentUntilAllBarriers": True,
            "inactiveOrdinaryWriteHTTP": 403, "barrierFailureHTTP": 409, "recoveryNoExtraRestart": True, "production": False}
