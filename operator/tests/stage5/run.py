#!/usr/bin/env python3
"""Isolated stage-5 real-service Deployment rollout acceptance, never production."""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import traceback
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "stage4"
sys.path.insert(0, str(SHARED))
import common
import infrastructure
from authority import Authority, b64, canonical, protected_write, pem

module = importlib.util.spec_from_file_location("stage4_runner", SHARED / "run.py")
base = importlib.util.module_from_spec(module)
module.loader.exec_module(base)

APP = "environment-app"
RELEASE = "stage5"
ANNOTATION_PREFIX = "secrets.sekvyr.ru/restart-"
RELOADER_OPTOUT = {"reloader.stakater.com/auto": "false", "secret.reloader.stakater.com/auto": "false",
                   "configmap.reloader.stakater.com/auto": "false"}
PASSES = []
PROOFS = {}
PROGRESS_TASK = None


def passed(name):
    PASSES.append(name)
    print("PASS " + name, flush=True)
    if PROGRESS_TASK is not None:
        (PROGRESS_TASK / "progress.json").write_text(json.dumps({"passed": PASSES, "proofs": PROOFS}, indent=2), encoding="utf-8")


def patch_resource(kind, name, operations):
    return json.loads(common.kube("patch", kind, name, "-n", infrastructure.APP_NS, "--type=json", "-p", json.dumps(operations), "-o", "json").stdout)


def child():
    return common.get("sekvyrsecret", base.RESOURCE, infrastructure.APP_NS)


def state_matches(data_current, rollout_ready=None):
    resource = child()
    if resource.get("status", {}).get("observedGeneration") != resource["metadata"]["generation"]:
        return False
    conditions = {item["type"]: item["status"] for item in resource.get("status", {}).get("conditions", [])}
    if data_current is not None and conditions.get("DataCurrent") != ("True" if data_current else "False"):
        return False
    if rollout_ready is not None and conditions.get("RolloutReady") != ("True" if rollout_ready else "False"):
        return False
    return resource


def revision(target=None):
    target = target or common.get("secret", base.TARGET, infrastructure.APP_NS)
    return target["metadata"]["annotations"][base.REVISION]


def deployment():
    return common.get("deployment", APP, infrastructure.APP_NS)


def ready_pod():
    pods = json.loads(common.kube("get", "pods", "-n", infrastructure.APP_NS, "-l", "app=" + APP, "-o", "json").stdout)["items"]
    live = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp") and
            any(condition["type"] == "Ready" and condition["status"] == "True" for condition in pod.get("status", {}).get("conditions", []))]
    return live[0] if len(live) == 1 else False


def app_status(task):
    pod = ready_pod()
    if not pod:
        return False
    forward = common.Forward(task, infrastructure.APP_NS, "pod/" + pod["metadata"]["name"], 8080)
    try:
        with urllib.request.urlopen("http://127.0.0.1:" + str(forward.port) + "/status", timeout=5) as response:
            result = json.load(response)
        result["pod_uid"] = pod["metadata"]["uid"]
        result["container_restarts"] = [item["restartCount"] for item in pod["status"]["containerStatuses"]]
        return result
    finally:
        forward.close()


def template_snapshot():
    current = deployment()
    return {"uid": current["metadata"]["uid"], "generation": current["metadata"]["generation"], "template": current["spec"]["template"]}


def assert_frozen(snapshot, seconds=7):
    deadline = time.monotonic() + seconds
    while True:
        current = template_snapshot()
        assert current["uid"] == snapshot["uid"] and current["template"] == snapshot["template"]
        if time.monotonic() >= deadline:
            return
        time.sleep(1)


def create_app(python_image):
    infrastructure.config_map(infrastructure.APP_NS, "environment-app-source", {"app.py": (HERE / "app.py").read_text()})
    return infrastructure.deployment(infrastructure.APP_NS, APP, [{
        "name": "app", "image": python_image, "imagePullPolicy": "Never", "command": ["python", "/app/app.py"],
        "envFrom": [{"secretRef": {"name": base.TARGET}}], "ports": [{"containerPort": 8080}],
        "volumeMounts": [{"name": "app", "mountPath": "/app", "readOnly": True}],
        "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 1},
    }], [{"name": "app", "configMap": {"name": "environment-app-source"}}],
       security_context={"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
       annotations=dict(RELOADER_OPTOUT))


def poke():
    base.poke()


def publish(session, authority, sequence, previous_hash, generation, demo):
    envelope, digest = authority.snapshot(sequence, previous_hash, generation, demo)
    session.publish(envelope, digest, sequence - 1, previous_hash)
    poke()
    common.wait("current verified stage-5 snapshot", lambda: value if (value := state_matches(True)) and
                value.get("status", {}).get("lastVerifiedCheckpoint") == {"sequence": str(sequence), "envelopeHash": digest} else False)
    return envelope, digest


def install_operator(task, authority, metadata, operator_image):
    values = base.chart_values(authority, metadata, operator_image)
    values["rollout"] = {"enabled": True, "allowedDeployments": [APP]}
    path = task / "operator-values.json"
    protected_write(path, canonical(values))
    helm = os.environ.get("HELM_BIN", "helm")
    common.run([helm, "lint", str(base.CHART), "-n", infrastructure.APP_NS, "-f", str(path)])
    common.run([helm, "upgrade", "--install", RELEASE, str(base.CHART), "--namespace", infrastructure.APP_NS,
                "--kubeconfig", str(task / "kubeconfig"), "-f", str(path), "--wait", "--timeout", "180s"])


def exercise(task, operator_image):
    if not operator_image:
        raise RuntimeError("Stage-5 needs a fresh digest-pinned integrated operator")
    authority = Authority.load(task)
    metadata = json.loads((task / "private" / "bootstrap.json").read_text())
    images = json.loads((task / "private" / "images.json").read_text())
    base.load_image(task, operator_image)
    session = base.Session(task, authority)
    try:
        session.login()
        session.ensure_unsealed()
        foreign = infrastructure.secret(infrastructure.APP_NS, base.TARGET, {"KEEP": b64(os.urandom(24))}, immutable=False)
        install_operator(task, authority, metadata, operator_image)
        common.create(common.object_resource("SekvyrSecret", base.RESOURCE, infrastructure.APP_NS, {
            "storeRef": {"name": base.STORE, "uid": metadata["store_uid"]}, "binding": "runtime",
            "refreshIntervalSeconds": 30, "suspend": False, "rollout": {"enabled": False, "deployments": []},
        }, api=base.API))
        common.wait("foreign target fail closed", lambda: state_matches(False))
        current = common.get("secret", base.TARGET, infrastructure.APP_NS)
        assert current["metadata"]["uid"] == foreign["metadata"]["uid"] and current["data"] == foreign["data"]
        common.kube("delete", "secret", base.TARGET, "-n", infrastructure.APP_NS)
        poke()
        common.wait("initial secret without restart request", lambda: state_matches(True, True))
        target = common.get("secret", base.TARGET, infrastructure.APP_NS)
        annotation = ANNOTATION_PREFIX + target["metadata"]["uid"]
        created_app = create_app(images["python"])
        base.ready_deployment(infrastructure.APP_NS, APP)
        first = common.wait("app initial environment", lambda: value if (value := app_status(task)) and value["generation"] == "initial" else False)
        initial_template = template_snapshot()
        initial_replica_sets = replica_set_uids()
        assert len(initial_replica_sets) == 1
        assert annotation not in initial_template["template"]["metadata"].get("annotations", {})
        patch_resource("sekvyrsecret", base.RESOURCE, [{"op": "replace", "path": "/spec/rollout", "value": {"enabled": True, "deployments": [APP]}}])
        common.wait("rollout enabled without historical intent", lambda: state_matches(True, True))
        assert_frozen(initial_template)
        assert app_status(task)["pod_uid"] == first["pod_uid"]
        assert replica_set_uids() == initial_replica_sets
        PROOFS["initialApp"] = first
        PROOFS["initialTemplateSHA256"] = hashlib.sha256(canonical(initial_template["template"])).hexdigest()
        PROOFS["initialReplicaSetCount"] = len(initial_replica_sets)
        passed("initial Secret create and enabling rollout do not restart the existing envFrom app")
        demo = b64(os.urandom(32))
        base.SENSITIVE.extend([demo, metadata["initial_demo_value"], authority.owner_password, authority.db_password,
                               authority.jwt_secret, authority.fetch_token, b64(authority.read_key), pem(authority.node).decode(),
                               pem(authority.publisher).decode(), pem(authority.witness).decode()])
        second_envelope, second_hash = publish(session, authority, 2, metadata["initial_hash"], "updated", demo)
        new_revision = revision()
        assert re.fullmatch(r"[0-9a-f]{32}", new_revision)
        common.wait("one revision annotation applied", lambda: deployment()["spec"]["template"]["metadata"].get("annotations", {}).get(annotation) == new_revision)
        base.ready_deployment(infrastructure.APP_NS, APP)
        second = common.wait("new pod environment", lambda: value if (value := app_status(task)) and value["generation"] == "updated" else False)
        assert second["boot_id"] != first["boot_id"] and second["pod_uid"] != first["pod_uid"]
        updated_template = template_snapshot()
        assert updated_template["generation"] > initial_template["generation"]
        assert_only_restart_annotation_changed(initial_template, updated_template, annotation)
        updated_replica_sets = replica_set_uids()
        assert initial_replica_sets < updated_replica_sets and len(updated_replica_sets - initial_replica_sets) == 1
        common.wait("rollout completion reported", lambda: state_matches(True, True))
        PROOFS["initialApp"] = first
        PROOFS["updatedApp"] = second
        PROOFS["templateGenerationBeforeAfter"] = [initial_template["generation"], updated_template["generation"]]
        PROOFS["newReplicaSetsForOneDataChange"] = 1
        passed("one actual data change patches only the UID-scoped opaque revision and replaces the pod with new environment")
        for _ in range(3):
            poke()
        assert_frozen(updated_template)
        assert app_status(task)["pod_uid"] == second["pod_uid"]
        assert replica_set_uids() == updated_replica_sets
        passed("repeated reconciliation does not change pod template or restart the app again")
        third_envelope, third_hash = publish(session, authority, 3, second_hash, "updated", demo)
        assert revision() == new_revision
        assert_frozen(updated_template)
        assert app_status(task)["pod_uid"] == second["pod_uid"]
        assert replica_set_uids() == updated_replica_sets
        passed("equal plaintext in a new canonical ciphertext advances checkpoint without another rollout")
        check_forged_public_markers(updated_template)
        fork, fork_hash = authority.snapshot(3, second_hash, "forked", b64(os.urandom(32)))
        session.owner_request("POST", "/api/e2e2/views/" + authority.scope["view_id"] + "/envelopes", fork, (201,))
        session.witness.request("POST", "/v1/logs/" + authority.scope["log_id"] + "/commits", {
            "envelope_hash": fork_hash, "expected": {"witness_epoch": "1", "sequence": "2", "envelope_hash": second_hash, "publisher_policy_epoch": "1"},
        }, expected=(409,))
        passed("same-sequence competing publication is rejected by actual witness CAS")
        check_source_failures(session, authority, metadata, third_envelope, third_hash, updated_template)
        check_outages(session, authority, updated_template)
        pending_demo = b64(os.urandom(32))
        base.SENSITIVE.append(pending_demo)
        patch_resource("deployment", APP, [{"op": "add", "path": "/spec/paused", "value": True}])
        _, fourth_hash = publish(session, authority, 4, third_hash, "pending", pending_demo)
        pending_revision = revision()
        common.wait("paused Deployment blocks only rollout", lambda: state_matches(True, False))
        paused_template = template_snapshot()
        assert paused_template["template"] == updated_template["template"]
        stop_service(infrastructure.WITNESS_NS, "witness")
        poke()
        common.wait("pending intent has no current witness", lambda: state_matches(False, False))
        patch_resource("deployment", APP, [{"op": "replace", "path": "/spec/paused", "value": False}])
        frozen_pending = template_snapshot()
        frozen_replica_sets = replica_set_uids()
        assert_frozen(frozen_pending, seconds=8)
        restart_operator()
        common.wait("restarted pending worker remains fail closed", lambda: state_matches(False, False))
        assert_frozen(frozen_pending, seconds=8)
        assert app_status(task)["pod_uid"] == second["pod_uid"]
        assert replica_set_uids() == frozen_replica_sets
        passed("paused pending intent survives operator restart and stays frozen without live witness after unpause")
        restore_service(session, authority, infrastructure.WITNESS_NS, "witness")
        poke()
        common.wait("strict-current pending recovery", lambda: state_matches(True) and
                    deployment()["spec"]["template"]["metadata"].get("annotations", {}).get(annotation) == pending_revision)
        base.ready_deployment(infrastructure.APP_NS, APP)
        recovered = common.wait("pending new pod environment", lambda: value if (value := app_status(task)) and value["generation"] == "pending" else False)
        recovered_template = template_snapshot()
        assert recovered_template["generation"] > frozen_pending["generation"]
        assert_only_restart_annotation_changed(frozen_pending, recovered_template, annotation)
        recovered_replica_sets = replica_set_uids()
        assert frozen_replica_sets < recovered_replica_sets and len(recovered_replica_sets - frozen_replica_sets) == 1
        assert recovered["pod_uid"] != second["pod_uid"]
        PROOFS["recoveredPendingApp"] = recovered
        PROOFS["newReplicaSetsForPendingRecovery"] = 1
        common.wait("pending rollout completion", lambda: state_matches(True, True))
        passed("fresh strict-current sync resumes durable pending intent exactly once after witness recovery")
        check_denied_and_suspend(task, recovered_template)
        check_deployment_recreation(session, authority, fourth_hash, annotation, images["python"])
        check_state_loss_and_rbac(metadata)
        check_log_privacy()
        evidence = {"scope": "Real isolated Kubernetes + actual TLS panel/witness + envFrom Deployment",
                    "kubernetesVersion": json.loads(common.kube("version", "-o", "json").stdout)["serverVersion"]["gitVersion"],
                    "passed": PASSES, "proofs": PROOFS, "images": {**images, "operator": operator_image},
                    "limitations": ["Development filesystem witness does not prove production WORM/storage independence",
                                    "Administrative test fault injection and Deployment recreation are isolated to this run"]}
        (task / "results.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    finally:
        session.close()


def assert_only_restart_annotation_changed(before, after, annotation):
    old, new = copy.deepcopy(before["template"]), copy.deepcopy(after["template"])
    for value in (old, new):
        value["metadata"].setdefault("annotations", {}).pop(annotation, None)
    assert old == new


def workload_identities():
    resources = json.loads(common.kube("get", "pods,replicasets", "-n", infrastructure.APP_NS,
                                      "-l", "app=" + APP, "-o", "json").stdout)["items"]
    return sorted((item["kind"], item["metadata"]["uid"]) for item in resources
                  if not item["metadata"].get("deletionTimestamp"))


def replica_set_uids():
    deployment_uid = deployment()["metadata"]["uid"]
    resources = json.loads(common.kube("get", "replicasets", "-n", infrastructure.APP_NS,
                                      "-l", "app=" + APP, "-o", "json").stdout)["items"]
    return {item["metadata"]["uid"] for item in resources if any(
        owner.get("controller") and owner["uid"] == deployment_uid for owner in item["metadata"].get("ownerReferences", []))}


def check_forged_public_markers(snapshot):
    target = common.get("secret", base.TARGET, infrastructure.APP_NS)
    revision_key, intent_key = base.REVISION, "secrets.sekvyr.ru/rollout-intent"
    original = {key: target["metadata"]["annotations"][key] for key in (revision_key, intent_key)}
    forged = json.loads(original[intent_key])
    resource = child()
    store = common.get("sekvyrstore", base.STORE, infrastructure.APP_NS)
    assert forged["context"] == {
        "namespace": infrastructure.APP_NS, "crName": base.RESOURCE, "crUID": resource["metadata"]["uid"],
        "crGeneration": resource["metadata"]["generation"], "storeName": base.STORE, "storeUID": store["metadata"]["uid"],
        "storeGeneration": store["metadata"]["generation"], "bindingID": store["spec"]["bindings"][0]["id"],
        "bootstrapGeneration": 1, "targetName": base.TARGET, "targetUID": target["metadata"]["uid"],
    }
    forged_revision = os.urandom(16).hex()
    forged["revision"] = forged_revision
    forged["eligible"] = True
    identities = workload_identities()
    state_before = common.get("secret", "operator-state", infrastructure.APP_NS)["data"]

    def write(values):
        patch_resource("secret", base.TARGET, [{"op": "replace", "path": "/metadata/annotations/" +
                        key.replace("~", "~0").replace("/", "~1"), "value": value} for key, value in values.items()])

    write({revision_key: forged_revision, intent_key: canonical(forged).decode()})
    try:
        poke()
        common.wait("public marker forgery has no protected authorization", lambda: value if
                    (value := state_matches(True, False)) and any(item["type"] == "RolloutReady" and
                        item["reason"] == "RolloutStateAmbiguous" for item in value["status"]["conditions"]) else False)
        assert common.get("secret", base.TARGET, infrastructure.APP_NS)["data"] == target["data"]
        assert common.get("secret", "operator-state", infrastructure.APP_NS)["data"] == state_before
        assert_frozen(snapshot)
        assert workload_identities() == identities
    finally:
        write(original)
        poke()
    common.wait("restored original public markers reconcile safely", lambda: state_matches(True, True))
    assert_frozen(snapshot, seconds=1)
    assert workload_identities() == identities
    passed("valid public revision and intent forgery cannot authorize a rollout without protected state; exact restore does not restart")


def stop_service(namespace, name):
    common.kube("scale", "deployment", name, "-n", namespace, "--replicas=0")
    common.wait("isolated service stopped", lambda: common.get("deployment", name, namespace).get("status", {}).get("replicas", 0) == 0)


def restore_service(session, authority, namespace, name):
    common.kube("scale", "deployment", name, "-n", namespace, "--replicas=1")
    base.ready_deployment(namespace, name)
    ca = authority.root / ("panel-ca.crt" if name == "panel" else "witness-ca.crt")
    client = session.connect(name, namespace, "service/" + name, ca)
    if name == "panel":
        session.panel = client
        session.login()
        session.ensure_unsealed()
    else:
        session.witness = client


def restart_operator():
    pods = json.loads(common.kube("get", "pods", "-n", infrastructure.APP_NS, "-l", "app.kubernetes.io/instance=" + RELEASE, "-o", "json").stdout)["items"]
    assert len(pods) == 1
    old = pods[0]["metadata"]["uid"]
    common.kube("delete", "pod", pods[0]["metadata"]["name"], "-n", infrastructure.APP_NS)
    common.wait("new operator process", lambda: any(item["metadata"]["uid"] != old and
                item.get("status", {}).get("phase") == "Running" for item in json.loads(common.kube(
                    "get", "pods", "-n", infrastructure.APP_NS, "-l", "app.kubernetes.io/instance=" + RELEASE, "-o", "json").stdout)["items"]))
    poke()


def check_source_failures(session, authority, metadata, envelope, digest, snapshot):
    preserved = common.get("secret", base.TARGET, infrastructure.APP_NS)
    identities = workload_identities()
    bad_signature = copy.deepcopy(envelope)
    signature = bytearray(base64.urlsafe_b64decode(bad_signature["signature"] + "=="))
    signature[0] ^= 1
    bad_signature["signature"] = b64(bytes(signature))
    bad_cipher = copy.deepcopy(envelope)
    raw = bad_cipher["body"]["ciphertext"]
    ciphertext = bytearray(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    ciphertext[0] ^= 1
    bad_cipher["body"]["ciphertext"] = b64(bytes(ciphertext))
    bad_cipher["signature"] = b64(authority.publisher.sign(b"sekvyr-e2e2/publish/v1\0" + canonical(bad_cipher["body"])))
    for label, altered in (("bad signature", bad_signature), ("signed corrupt ciphertext", bad_cipher),
                            ("old signed snapshot replay", metadata["initial_envelope"])):
        payload = {"operation": "replace-envelope", "view_id": authority.scope["view_id"], "envelope_hash": digest, "envelope": altered}
        common.kube("exec", "-i", "deployment/panel", "-n", infrastructure.PANEL_NS, "--", "python", "-c", base.PANEL_FAULT, value=json.dumps(payload))
        poke()
        common.wait("invalid source blocks data and rollout", lambda: state_matches(False, False))
        base.assert_preserved(preserved)
        assert_frozen(snapshot, seconds=1)
        assert workload_identities() == identities
        payload["envelope"] = envelope
        common.kube("exec", "-i", "deployment/panel", "-n", infrastructure.PANEL_NS, "--", "python", "-c", base.PANEL_FAULT, value=json.dumps(payload))
        poke()
        common.wait("verified source recovery", lambda: state_matches(True, True))
        base.assert_preserved(preserved)
        assert_frozen(snapshot, seconds=1)
        assert workload_identities() == identities
        passed(label + " preserves Secret and Deployment template and recovers without a restart")
    previous_attempt = child().get("status", {}).get("lastAttemptTime")
    common.kube("exec", "-i", "deployment/panel", "-n", infrastructure.PANEL_NS, "--", "python", "-c", base.PANEL_FAULT,
                value=json.dumps({"operation": "old-index", "view_id": authority.scope["view_id"], "envelope_hash": metadata["initial_hash"]}))
    poke()
    common.wait("fresh witness overrides old panel pointer", lambda: value if (value := state_matches(True, True)) and
                value.get("status", {}).get("lastAttemptTime") != previous_attempt else False)
    assert base.checkpoint_sequence(authority, metadata) == "3"
    base.assert_preserved(preserved)
    assert_frozen(snapshot, seconds=1)
    assert workload_identities() == identities
    session.owner_request("POST", "/api/e2e2/views/" + authority.scope["view_id"] + "/index", {"envelope_hash": digest})
    passed("stale panel index and old bootstrap floor cannot cause a stale or duplicate rollout")


def check_outages(session, authority, snapshot):
    preserved = common.get("secret", base.TARGET, infrastructure.APP_NS)
    identities = workload_identities()
    for namespace, name in ((infrastructure.PANEL_NS, "panel"), (infrastructure.WITNESS_NS, "witness")):
        stop_service(namespace, name)
        poke()
        common.wait("source outage blocks data and rollout", lambda: state_matches(False, False))
        base.assert_preserved(preserved)
        assert_frozen(snapshot)
        assert workload_identities() == identities
        restore_service(session, authority, namespace, name)
        poke()
        common.wait("source outage recovery", lambda: state_matches(True, True))
        base.assert_preserved(preserved)
        assert_frozen(snapshot, seconds=1)
        assert workload_identities() == identities
        passed(name + " outage and recovery do not create a historical or duplicate restart")


def check_denied_and_suspend(task, snapshot):
    preserved = common.get("secret", base.TARGET, infrastructure.APP_NS)
    patch_resource("sekvyrsecret", base.RESOURCE, [{"op": "replace", "path": "/spec/rollout/deployments", "value": ["not-authorized"]}])
    common.wait("non-admin Deployment denied", lambda: state_matches(None, False))
    base.assert_preserved(preserved)
    assert_frozen(snapshot)
    patch_resource("sekvyrsecret", base.RESOURCE, [{"op": "replace", "path": "/spec/rollout/deployments", "value": [APP]}])
    common.wait("authorized rollout restored", lambda: state_matches(True, True))
    assert_frozen(snapshot, seconds=1)
    passed("a Deployment outside the independent administrative allowlist is never patched")
    patch_resource("sekvyrsecret", base.RESOURCE, [{"op": "replace", "path": "/spec/suspend", "value": True}])
    common.wait("suspend visible", lambda: state_matches(None, False))
    assert_frozen(snapshot)
    before = app_status(task)
    patch_resource("sekvyrsecret", base.RESOURCE, [{"op": "replace", "path": "/spec/suspend", "value": False}])
    common.wait("resume current state", lambda: state_matches(True, True))
    assert_frozen(snapshot)
    assert app_status(task)["pod_uid"] == before["pod_uid"]
    passed("suspend and resume with equal data do not restart the app")


def check_deployment_recreation(session, authority, previous_hash, annotation, python_image):
    patch_resource("deployment", APP, [{"op": "add", "path": "/spec/paused", "value": True}])
    demo = b64(os.urandom(32))
    base.SENSITIVE.append(demo)
    publish(session, authority, 5, previous_hash, "recreated", demo)
    common.wait("pending rollout bound to original Deployment", lambda: state_matches(True, False))
    original = deployment()
    previous_attempt = child().get("status", {}).get("lastAttemptTime")
    common.kube("delete", "deployment", APP, "-n", infrastructure.APP_NS, "--wait=true")
    specification = copy.deepcopy(original["spec"])
    specification["paused"] = False
    manifest = common.object_resource("Deployment", APP, infrastructure.APP_NS, specification, api="apps/v1")
    manifest["metadata"]["annotations"] = dict(RELOADER_OPTOUT)
    replacement = common.create(manifest)
    assert replacement["metadata"]["uid"] != original["metadata"]["uid"]
    snapshot = template_snapshot()
    poke()
    common.wait("same-name new UID does not authorize pending intent", lambda: value if
                (value := state_matches(None, False)) and value.get("status", {}).get("lastAttemptTime") != previous_attempt else False)
    assert_frozen(snapshot, seconds=8)
    assert deployment()["metadata"]["uid"] == replacement["metadata"]["uid"]
    PROOFS["recreatedDeploymentNotPatched"] = True
    passed("same-name Deployment recreation does not adopt or execute an old UID-pinned pending intent")


def check_state_loss_and_rbac(metadata):
    preserved = common.get("secret", base.TARGET, infrastructure.APP_NS)
    snapshot = template_snapshot()
    account = "system:serviceaccount:" + infrastructure.APP_NS + ":" + infrastructure.SA
    for verb, resource in (("list", "secrets"), ("watch", "secrets"), ("patch", "secrets"), ("delete", "secrets"),
                            ("list", "deployments"), ("watch", "deployments"), ("update", "deployments"),
                            ("patch", "deployments/scale"), ("delete", "pods")):
        assert common.kube("auth", "can-i", verb, resource, "-n", infrastructure.APP_NS, "--as=" + account, check=False).stdout.strip() == "no"
    for name, answer in ((APP, "yes"), ("not-authorized", "no")):
        assert common.kube("auth", "can-i", "patch", "deployment/" + name, "-n", infrastructure.APP_NS, "--as=" + account, check=False).stdout.strip() == answer
    assert common.kube("auth", "can-i", "patch", "deployment/" + APP, "-n", infrastructure.FOREIGN_NS, "--as=" + account, check=False).stdout.strip() == "no"
    passed("runtime RBAC allows only exact namespaced Deployment get/patch and denies scale, update, list/watch and pod deletion")
    old_state = common.get("secret", "operator-state", infrastructure.APP_NS)
    common.kube("delete", "secret", "operator-state", "-n", infrastructure.APP_NS)
    poke()
    common.wait("lost state blocks all mutations", lambda: failed_reason({"StateMissing"}))
    base.assert_preserved(preserved)
    assert_frozen(snapshot, seconds=1)
    replacement = common.object_resource("Secret", "operator-state", infrastructure.APP_NS)
    replacement.update(type="Opaque", data=old_state["data"])
    common.create(replacement)
    poke()
    common.wait("replaced state stays blocked", lambda: failed_reason({"StateReplaced", "BootstrapMismatch"}))
    base.assert_preserved(preserved)
    assert_frozen(snapshot, seconds=1)
    passed("missing or replaced durable state cannot apply a Secret or restart Deployment")


def failed_reason(reasons):
    value = state_matches(False, False)
    if not value:
        return False
    ready = next((item for item in value["status"]["conditions"] if item["type"] == "Ready"), {})
    return value if ready.get("reason") in reasons else False


def check_log_privacy():
    visible = json.dumps(child()) + json.dumps(common.get("sekvyrstore", base.STORE, infrastructure.APP_NS))
    for namespace, name in ((infrastructure.PANEL_NS, "panel"), (infrastructure.WITNESS_NS, "witness"),
                            (infrastructure.APP_NS, RELEASE + "-operator")):
        visible += common.kube("logs", "deployment/" + name, "-n", namespace).stdout
    pods = json.loads(common.kube("get", "pods", "-n", infrastructure.APP_NS, "-l", "app=" + APP, "-o", "json").stdout)["items"]
    for pod in pods:
        visible += common.kube("logs", pod["metadata"]["name"], "-n", infrastructure.APP_NS).stdout
    assert all(value not in visible for value in base.SENSITIVE if value)
    passed("component logs and CR status contain no credentials, node/read keys or demo plaintext")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--chart-path", type=Path, required=True)
    parser.add_argument("--driver", choices=("k0s",), default="k0s")
    parser.add_argument("--node-name", required=True)
    parser.add_argument("--expected-kubernetes", required=True)
    parser.add_argument("--storage-class", required=True)
    parser.add_argument("--phase", choices=("infrastructure", "bootstrap", "exercise"), required=True)
    for name in ("panel", "witness", "database", "python", "operator"):
        parser.add_argument("--" + name + "-image")
    args = parser.parse_args()
    task = Authority.safe_task(args.task_dir)
    global PROGRESS_TASK
    PROGRESS_TASK = task
    if not re.fullmatch(r"sekvyr-stage5-[0-9]{8}-[0-9a-f]{8}", task.name):
        raise RuntimeError("Stage-5 requires a new explicitly isolated test run")
    common.configure(args.driver, task, args.node_name)
    common.STORAGE_CLASS = args.storage_class
    infrastructure.configure(task.name, release=RELEASE)
    base.APP_NS, base.PANEL_NS, base.WITNESS_NS = infrastructure.APP_NS, infrastructure.PANEL_NS, infrastructure.WITNESS_NS
    base.CHART = args.chart_path.resolve()
    base.check_cluster(task, args.expected_kubernetes)
    if args.phase == "infrastructure":
        base.infrastructure_phase(task, args)
    elif args.phase == "bootstrap":
        base.bootstrap_phase(task)
        patch_resource("sekvyrstore", base.STORE, [{"op": "replace", "path": "/spec/bindings/0/rollout/allowedDeployments", "value": [APP]}])
    else:
        exercise(task, args.operator_image)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        print("FAIL " + type(error).__name__ + " at " + Path(frame.filename).name + ":" + str(frame.lineno) + ": " + str(error), file=sys.stderr)
        raise SystemExit(1)
