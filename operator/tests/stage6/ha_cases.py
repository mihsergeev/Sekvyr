"""Real process/replica fencing and a genuinely already-approved late write."""

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import re
import time
import uuid

from application import RELEASE, SA, TARGET, require, wait
from dependency_cases import DependencyCases, grant_hash
from fixture import canonical, write_private
from forward import Forward
from manifests import LABEL, object_resource
from process_control import ProcessControl
from relay_fixture import install as install_relay, retry_owned as retry_relay
from runtime_control import RuntimeTaskControl, command as runtime_command


def current_activation(state, installation, pod_uid, holder):
    """Proof predicates over the real replayed journal, never old receipts."""
    grant = state.get("grants", {}).get(installation, {}).get("body")
    activation = state.get("activations", {}).get(installation, {}).get("body")
    enrollment = state.get("enrollments", {}).get(installation)
    if not grant or not activation or not enrollment:
        return False
    keys = ("scope", "genesis_hash", "installation_id", "bootstrap_generation", "owner_pod_uid",
        "lease_holder_identity", "term", "authority_digest", "snapshot", "objects")
    if any(key not in grant or key not in activation for key in keys) or grant.get("format") != "sekvyr-fence-grant-v1" or activation.get("format") != "sekvyr-fence-activation-v1":
        return False
    if not (grant.get("owner_pod_uid") == pod_uid and grant.get("lease_holder_identity") == holder
        and grant.get("installation_id") == installation and grant.get("scope") == state.get("scope")
        and grant.get("genesis_hash") == state.get("genesis_hash")
        and grant.get("bootstrap_generation") == enrollment.get("bootstrap_generation")
        and grant.get("authority_digest") == state.get("authority_digest")
        and grant.get("snapshot") == state.get("snapshot") and grant.get("objects") == enrollment.get("allowed_objects")):
        return False
    return all(activation.get(key) == grant.get(key) for key in keys) and activation.get("grant_hash") == grant_hash({"body": grant})


def correlated_hold(value, expected):
    return (value.get("upstream_allowed") is True and isinstance(value.get("request_uid"), str) and bool(value["request_uid"])
        and all(value.get(key) == expected[key] for key in ("target_uid", "old_pod_uid", "request_marker", "resource_version")))


def require_pending(future):
    require(not future.done(), "External request completed before its held response release")


def lease_duration_patch(lease, duration, expected_holder=None):
    spec, meta = lease["spec"], lease["metadata"]
    require(spec.get("leaseDurationSeconds") in (2, 15), "Unexpected owned Lease duration")
    if expected_holder is not None:
        require(spec.get("holderIdentity") == expected_holder and spec.get("leaseDurationSeconds") == 15,
            "Old owner Lease changed before bounded expiry injection")
    return [{"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
        {"op": "test", "path": "/spec/holderIdentity", "value": spec["holderIdentity"]},
        {"op": "test", "path": "/spec/renewTime", "value": spec["renewTime"]},
        {"op": "test", "path": "/spec/leaseDurationSeconds", "value": spec["leaseDurationSeconds"]},
        {"op": "replace", "path": "/spec/leaseDurationSeconds", "value": duration}]


def same_pod_replacement(current, holder, old_uid, old_holder, old_cid):
    statuses = [s for s in current.get("status", {}).get("containerStatuses", []) if s.get("name") == "operator"]
    cid = statuses[0].get("containerID") if len(statuses) == 1 else None
    return bool(current.get("metadata", {}).get("uid") == old_uid and holder and holder != old_holder
        and isinstance(cid, str) and re.fullmatch(r"containerd://[0-9a-f]{64}", cid) and cid != old_cid
        and statuses[0].get("state", {}).get("running"))


class HACases:
    def __init__(self, coordinator, helper_image, node):
        self.c, self.app, self.image, self.node = coordinator, coordinator.app, helper_image, node
        self.dependencies = DependencyCases(coordinator)

    def pods(self):
        deployment = self.app.get("Deployment", RELEASE + "-operator")
        selector = ",".join(k + "=" + v for k, v in sorted(deployment["spec"]["selector"]["matchLabels"].items()))
        pods = json.loads(self.c.cluster.kube("get", "pods", "-n", self.app.namespace, "-l", selector, "-o", "json").stdout)["items"]
        selected = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
        require(len(selected) == 2, "Exactly two actual operator Pods are required")
        return selected

    def same_pod_process(self):
        baseline = self.dependencies.baseline()
        leader, holder = self.app.operator_pod()
        other = next(p for p in self.pods() if p["metadata"]["uid"] != leader["metadata"]["uid"])
        old_cid = next(s["containerID"] for s in leader["status"]["containerStatuses"] if s["name"] == "operator")
        old_token = self.app.projected_token(leader)
        process = ProcessControl(self.c.cluster, leader, self.image).prepare()
        standby = RuntimeTaskControl(self.c.cluster, other, self.node, max_pause_seconds=25)
        acknowledged = False
        with standby.paused():
            try:
                process.signal("TERM")
                acknowledged = True
            except RuntimeError as error:
                # A PID-namespace init exit can tear down exec before its ack.
                # This never counts as success without all independent facts.
                require(str(error) == "Owned process control was not acknowledged", "TERM failed its ownership or transport guard")
            def replaced():
                selected = self.leader_or_none()
                if selected is None:
                    return False
                current, current_holder = selected
                return current if same_pod_replacement(current, current_holder, leader["metadata"]["uid"], holder, old_cid) else False
            wait(replaced, timeout=18)
            require(standby.paused_alive(), "Standby was not retained during the same-Pod process case")
            with Forward(self.c.cluster, self.app.namespace, "service/stage6-fencer", 9443) as forward:
                current, new_holder = self.app.operator_pod()
                status, _, _ = self.app.fencer_call(forward.origin, self.c.private / "journal-ca.crt", old_token,
                    "acquire", {"bootstrap_generation": self.app.generation, "expected_lease_holder_identity": new_holder})
                require(status == 200, "Same bound token was not valid for the independently observed new process")
                status, raw, _ = self.app.fencer_call(forward.origin, self.c.private / "journal-ca.crt", old_token,
                    "acquire", {"bootstrap_generation": self.app.generation, "expected_lease_holder_identity": holder})
                require(status == 409 and json.loads(raw).get("reason") == "LeaseMismatch", "Old process was not rejected for the exact stale holder")
                result = {"samePodNewProcessOldHolderDenied": True, "oldHolderHTTP": 409,
                    "oldHolderReason": "LeaseMismatch", "sameTokenNewHolderHTTP": 200}
        self.app.poke()
        wait(lambda: self.app.current(self.c.current()["snapshot"], True))
        self.dependencies.unchanged(baseline)
        return {**result, "samePodUIDNewContainerObserved": True, "newLeaseProcessIdentity": True,
            "termSignalAcknowledged": acknowledged, "standbyPausedForControlledCase": True,
            "applicationNotRestarted": True, "production": False}

    def leader_or_none(self):
        try:
            return self.app.operator_pod()
        except RuntimeError as error:
            if str(error) == "No unique bound operator leader pod":
                return None  # Expected short gap after graceful Lease release.
            raise

    def owned(self, kind, name):
        pins = [json.loads(p.read_text()) for p in self.c.cluster.pins.glob("*.json")]
        matches = [p for p in pins if (p["kind"], p["name"], p["namespace"]) == (kind, name, self.app.namespace)]
        require(len(matches) == 1, "HA test resource lacks exact creation pin")
        value = json.loads(self.c.cluster.kube("get", kind, name, "-n", self.app.namespace, "-o", "json").stdout)
        require(value["metadata"]["uid"] == matches[0]["uid"], "HA test resource replaced")
        return value

    def relay_exec(self, code):
        self.owned("Deployment", "admission-relay")
        result = self.c.cluster.kube("exec", "deployment/admission-relay", "-n", self.app.namespace, "-c", "relay", "--",
            "python3", "-B", "-c", code, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 4096, "Owned relay control failed")
        return result.stdout.strip()

    def late_approved_takeover(self, *, retry_existing=False, network_partition=True, inject_expiry=False):
        baseline = self.dependencies.baseline()
        old_pod, old_holder = self.app.operator_pod()
        old_uid = old_pod["metadata"]["uid"]
        control = RuntimeTaskControl(self.c.cluster, old_pod, self.node, max_pause_seconds=25)
        network_control = ProcessControl(self.c.cluster, old_pod, self.image).prepare() if network_partition else None
        api_service = json.loads(self.c.cluster.kube("get", "service", "kubernetes", "-n", "default", "-o", "json").stdout)["spec"]["clusterIP"] if network_partition else None
        state = self.c.current()
        grant = state["grants"][self.c.protocol.installation_id]
        digest = grant_hash(grant)
        require(grant["body"]["owner_pod_uid"] == old_uid and grant["body"]["lease_holder_identity"] == old_holder
            and state["activations"][self.c.protocol.installation_id]["body"]["grant_hash"] == digest,
            "Late-write baseline is not the active current owner")
        target = self.app.get("Secret", TARGET)
        api_token = self.app.projected_token(old_pod, audience=None)
        body = self.app.late_write_body(digest)
        marker = uuid.uuid4().hex
        body["metadata"]["annotations"]["stage6-trial-late-write"] = marker
        expected = {"upstream_origin": "https://stage6-fencer." + self.app.namespace + ".svc.cluster.local:9443",
            "namespace": self.app.namespace, "name": TARGET, "target_uid": target["metadata"]["uid"],
            "operator_username": "system:serviceaccount:" + self.app.namespace + ":" + SA,
            "operator_sa_uid": self.app.get("ServiceAccount", SA)["metadata"]["uid"], "old_pod_uid": old_uid,
            "kind": "Secret", "api_version": "v1", "maximum_hold_seconds": 25,
            "request_marker": marker, "expected_resource_version": body["metadata"]["resourceVersion"]}
        if retry_existing:
            retry_relay(self.c.cluster, expected)
        else:
            install_relay(self.c.cluster, self.image, expected, self.node)
        self.c.cluster.kube("-n", self.app.namespace, "rollout", "status", "deployment/admission-relay", "--timeout=120s")
        webhook_pin = [p for p in self.c.cluster.cluster_creation_pins() if p["kind"] == "ValidatingWebhookConfiguration"]
        require(len(webhook_pin) == 1, "Exact own webhook required")
        original = json.loads(self.c.cluster.kube("get", "ValidatingWebhookConfiguration", webhook_pin[0]["name"], "-o", "json").stdout)
        relay_hook = copy.deepcopy(original)
        relay_hook["webhooks"][0]["clientConfig"]["service"]["name"] = "admission-relay"
        token = uuid.uuid4().hex
        label = "secrets.sekvyr.ru/trial-partition"
        partition = object_resource("CiliumNetworkPolicy", "trial-old-owner-partition", self.app.namespace, {
            "endpointSelector": {"matchLabels": {"k8s:" + LABEL: "operator", "k8s:" + label: token}},
            "egressDeny": [{"toEntities": ["kube-apiserver"]}, {"toEndpoints": [{"matchLabels": {
                "k8s:io.kubernetes.pod.namespace": self.app.namespace, "k8s:" + LABEL: "fencer"}}]},
                {"toEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": self.c.namespaces["gateway"],
                    "k8s:" + LABEL: "journal-gateway"}}]}]}, "cilium.io/v2")
        partition = self.c.cluster.create(partition) if network_partition else None
        paused = False
        expiry_lease = None
        future = None
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            self.c.cluster.update_cluster_webhook(relay_hook)
            # Nonmatching bootstrap dry-run must traverse actual relay TLS and
            # real upstream admission before an external old-writer request.
            probe = [{"op": "add", "path": "/metadata/annotations/stage6-trial-relay-probe", "value": "dry-run-only"}]
            self.c.cluster.kube("patch", "secret", TARGET, "-n", self.app.namespace, "--type=json", "-p", json.dumps(probe), "--dry-run=server", "-o", "name")
            future = executor.submit(self.app.token_update_target, api_token, body)
            def held():
                raw = self.relay_exec("from pathlib import Path; p=Path('/state/held.json'); print(p.read_text() if p.is_file() else '{}')")
                value = json.loads(raw)
                return value if correlated_hold(value, {"target_uid": target["metadata"]["uid"], "old_pod_uid": old_uid,
                    "request_marker": marker, "resource_version": body["metadata"]["resourceVersion"]}) else False
            wait(held, timeout=10)
            require_pending(future)
            observed = time.monotonic()
            control.pause()
            paused = True
            if inject_expiry:
                require(control.paused_alive(), "Old task not paused before expiry injection")
                expiry_lease = self.owned("Lease", "sekvyr-operator-leader")
                patch = lease_duration_patch(expiry_lease, 2, old_holder)
                self.c.cluster.kube("patch", "lease", expiry_lease["metadata"]["name"], "-n", self.app.namespace,
                    "--type=json", "-p", json.dumps(patch))
            live = json.loads(self.c.cluster.kube("get", "pod", old_pod["metadata"]["name"], "-n", self.app.namespace, "-o", "json").stdout)
            require(live["metadata"]["uid"] == old_uid, "Old-owner Pod changed before partition")
            labels = dict(live["metadata"].get("labels", {}), **{label: token})
            patch = [{"op": "test", "path": "/metadata/uid", "value": old_uid},
                {"op": "test", "path": "/metadata/resourceVersion", "value": live["metadata"]["resourceVersion"]},
                {"op": "add", "path": "/metadata/labels", "value": labels}]
            if network_partition:
                self.c.cluster.kube("patch", "pod", old_pod["metadata"]["name"], "-n", self.app.namespace, "--type=json", "-p", json.dumps(patch))
            # The helper has a separate cgroup but the EXACT same Pod network.
            # Prove the partition, rather than inferring it from policy YAML.
            if network_control:
                network_control._owned()
            probe_code = "import socket,sys\ntry:\n s=socket.create_connection((sys.argv[1],443),timeout=.5);s.close();print('Reachable')\nexcept OSError:print('Blocked')"
            def partitioned():
                response = self.c.cluster.kube("exec", network_control.name, "-n", self.app.namespace,
                    "-c", network_control.control_name, "--", "python", "-c", probe_code, api_service, check=False)
                require(response.returncode == 0, "Old Pod partition diagnostic failed")
                return response.stdout.strip() == "Blocked"
            if network_partition:
                wait(partitioned, timeout=3)
            def takeover():
                selected = self.leader_or_none()
                if selected is None:
                    return False
                pod, holder = selected
                if pod["metadata"]["uid"] == old_uid or holder == old_holder:
                    return False
                if inject_expiry:
                    lease = self.owned("Lease", expiry_lease["metadata"]["name"])
                    if lease["spec"].get("leaseDurationSeconds") != 15 or lease["spec"].get("holderIdentity") != holder:
                        return False
                current = self.c.current()
                if not current_activation(current, self.c.protocol.installation_id, pod["metadata"]["uid"], holder):
                    return False
                g = current["grants"][self.c.protocol.installation_id]
                digest = grant_hash(g)
                for reference in g["body"]["objects"]:
                    obj = self.app.get(reference["kind"], reference["name"])
                    fence = json.loads(obj["metadata"].get("annotations", {}).get("secrets.sekvyr.ru/fence", "{}"))
                    if fence.get("grant_hash") != digest or fence.get("owner_pod_uid") != pod["metadata"]["uid"] or fence.get("term") != g["body"]["term"]:
                        return False
                return True
            wait(takeover, timeout=19)
            require(time.monotonic() - observed < 22 and control.paused_alive(), "Old process was not retained within the admission deadline")
            require_pending(future)
            self.relay_exec("from pathlib import Path; p=Path('/state/release'); p.open('x').close(); print('Released')")
            status = future.result(timeout=5)
            self.app.assert_late_write_conflicted(status)
            result = {"alreadyApprovedLateWriteHTTP": status, "genuineUpstreamAllowHeld": True,
                "oldRuntimeTaskAlivePausedDuringTakeover": True, "differentReplicaActivatedCanonicalGrant": True,
                "oldPodAPIPartitionActuallyObserved": network_partition, "stopTheWorldOldOwnerTested": True,
                "boundedLeaseExpiryInjected": inject_expiry, "natural15SecondFailoverClaimed": not inject_expiry,
                "sameObjectStorageCASRejectedOldWrite": True, "production": False}
            write_private(self.c.task / "phase-a-late-write-core-proof.json", canonical(result))
        finally:
            # Undo only these exact owned fault resources, even if a timeout or
            # failed assertion prevents claiming success.
            try:
                self.c.cluster.update_cluster_webhook(original)
            finally:
                try:
                    if paused:
                        try:
                            control.resume()
                        except RuntimeError:
                            # The bounded watchdog may already have resumed an
                            # init which then exited on lost leadership. Never
                            # adopt or signal its replacement container.
                            remaining = [line.split() for line in runtime_command("tasks", "list").splitlines()
                                if line.split() and line.split()[0] == control.plan["cid"]]
                            require(not remaining, "Old runtime task still exists after failed exact resume")
                finally:
                    if expiry_lease:
                        lease = self.owned("Lease", expiry_lease["metadata"]["name"])
                        if lease["spec"].get("leaseDurationSeconds") == 2:
                            self.c.cluster.kube("patch", "lease", lease["metadata"]["name"], "-n", self.app.namespace,
                                "--type=json", "-p", json.dumps(lease_duration_patch(lease, 15)))
                    if partition:
                        live_partition = self.owned("CiliumNetworkPolicy", partition["metadata"]["name"])
                        require(live_partition["metadata"]["uid"] == partition["metadata"]["uid"], "Partition fixture replaced")
                        delete = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": partition["metadata"]["uid"]}}
                        self.c.cluster.kube("delete", "--raw", "/apis/cilium.io/v2/namespaces/" + self.app.namespace +
                            "/ciliumnetworkpolicies/" + partition["metadata"]["name"], "-f", "-", data=json.dumps(delete))
                    old_live = json.loads(self.c.cluster.kube("get", "pod", old_pod["metadata"]["name"], "-n", self.app.namespace, "-o", "json").stdout)
                    if old_live["metadata"]["uid"] == old_uid and old_live["metadata"].get("labels", {}).get(label) == token:
                        patch = [{"op": "test", "path": "/metadata/uid", "value": old_uid},
                            {"op": "test", "path": "/metadata/resourceVersion", "value": old_live["metadata"]["resourceVersion"]},
                            {"op": "test", "path": "/metadata/labels/" + label.replace("/", "~1"), "value": token},
                            {"op": "remove", "path": "/metadata/labels/" + label.replace("/", "~1")}]
                        self.c.cluster.kube("patch", "pod", old_pod["metadata"]["name"], "-n", self.app.namespace, "--type=json", "-p", json.dumps(patch))
                    executor.shutdown(wait=True, cancel_futures=True)
        self.app.poke()
        wait(lambda: self.app.current(self.c.current()["snapshot"], True))
        self.dependencies.unchanged(baseline)
        return result
