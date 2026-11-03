#!/usr/bin/env python3
"""Real isolated services + Kubernetes stage-4 acceptance; no production access."""

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import uuid

from authority import Authority, b64, ca_pin, canonical, key_id, pem, protected_write, public
from common import DOCKER, NODE, Forward, TLSClient, create, get, kube, object_resource, run, wait
from infrastructure import APP_NS, PANEL_NS, SA, WITNESS_NS, config_map, prepare_namespaces, prepare_panel, prepare_witness, secret, start_canary, start_witness
import common
import infrastructure

HERE = Path(__file__).resolve().parent
CHART = HERE.parents[1] / "charts" / "sekvyr-operator"
API = "secrets.sekvyr.ru/v1alpha1"
TARGET = "runtime-env"
STORE = "application-secrets"
RESOURCE = "runtime"
REVISION = "secrets.sekvyr.ru/revision"
RESULTS = []
SENSITIVE = []
PANEL_FAULT = """
import asyncio, json, sys
from app.config import get_settings
from app.db import create_engine_and_factory
from app.models import E2E2Envelope, E2E2View
from app.e2e2 import canonical
payload = json.load(sys.stdin)
async def main():
    engine, factory = create_engine_and_factory(get_settings().db_url)
    try:
        async with factory() as session:
            if payload['operation'] == 'replace-envelope':
                row = await session.get(E2E2Envelope, payload['envelope_hash'])
                if row is None or row.view_id != payload['view_id']:
                    raise RuntimeError('Test fixture row missing')
                row.canonical_envelope = canonical(payload['envelope']).decode()
            elif payload['operation'] == 'old-index':
                row = await session.get(E2E2View, payload['view_id'])
                if row is None:
                    raise RuntimeError('Test fixture view missing')
                row.indexed_sequence = '1'
                row.indexed_hash = payload['envelope_hash']
            else:
                raise RuntimeError('Unknown isolated fault')
            await session.commit()
    finally:
        await engine.dispose()
asyncio.run(main())
print('isolated_fault_applied')
"""


def passed(name):
    RESULTS.append(name)
    print("PASS " + name, flush=True)


def private_json(task, name, value):
    path = task / "private" / name
    protected_write(path, canonical(value))


def record_created_crd(task, identities, created):
    name, uid = created["metadata"]["name"], created["metadata"]["uid"]
    if name not in {"sekvyrstores.secrets.sekvyr.ru", "sekvyrsecrets.secrets.sekvyr.ru"} or name in identities or not uid:
        raise RuntimeError("Unexpected or repeated test CRD creation identity")
    private_json(task, "crd-uid-" + name + ".json", {name: uid})
    identities[name] = uid


def check_cluster(task, expected_version):
    Authority.safe_task(task)
    if common.DRIVER == "kind":
        label = run(DOCKER + ["inspect", "--format", '{{index .Config.Labels "io.x-k8s.kind.cluster"}}', NODE]).stdout.strip()
        if label != "sekvyr-stage4":
            raise RuntimeError("Not the isolated stage-4 cluster")
    version = json.loads(kube("version", "-o", "json").stdout)
    if not re.fullmatch(re.escape(expected_version) + r"(?:\+[^ ]+)?", version["serverVersion"]["gitVersion"]):
        raise RuntimeError("Unexpected Kubernetes test version")
    if common.DRIVER == "k0s":
        if not common.NODE_NAME:
            raise RuntimeError("k0s tests require an explicit approved node label")
        nodes = json.loads(kube("get", "nodes", "-l", "kubernetes.io/hostname=" + common.NODE_NAME, "-o", "json").stdout)["items"]
        if len(nodes) != 1 or not any(item["type"] == "Ready" and item["status"] == "True" for item in nodes[0].get("status", {}).get("conditions", [])):
            raise RuntimeError("The approved test node is not uniquely Ready")
        classes = json.loads(kube("get", "storageclasses", "-o", "json").stdout)["items"]
        if common.STORAGE_CLASS:
            if not any(item["metadata"]["name"] == common.STORAGE_CLASS for item in classes):
                raise RuntimeError("Approved StorageClass is missing")
        else:
            defaults = [item["metadata"]["name"] for item in classes if item["metadata"].get("annotations", {}).get("storageclass.kubernetes.io/is-default-class") == "true"]
            if len(defaults) > 1:
                raise RuntimeError("Ambiguous default StorageClass")
            if defaults:
                common.STORAGE_CLASS = defaults[0]
            else:
                common.HOSTPATH_MODE = True
    if not (task / "kubectl").exists():
        if common.DRIVER == "kind":
            run(DOCKER + ["cp", NODE + ":/usr/bin/kubectl", str(task / "kubectl")])
        else:
            protected_write(task / "kubectl", '#!/bin/sh\nexec sudo -n k0s kubectl "$@"\n')
        os.chmod(task / "kubectl", 0o755)
    if common.DRIVER == "k0s" and not (task / "kubeconfig").exists():
        protected_write(task / "kubeconfig", run(["sudo", "-n", "k0s", "kubeconfig", "admin"]).stdout)


def load_image(task, image):
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", image):
        raise RuntimeError("Every test image must be digest pinned")
    if common.DRIVER == "k0s":
        # The separately reviewed build/import job owns containerd mutations.
        # Never pull, prune or alter a shared cluster runtime from this helper.
        return
    run(["sudo", "-n", "env", "DOCKER_HOST=unix:///var/run/docker.sock", str(task / "kind"),
         "load", "docker-image", "--name", "sekvyr-stage4", image])


def ready_deployment(namespace, name):
    return wait("deployment " + name, lambda: get("deployment", name, namespace).get("status", {}).get("availableReplicas", 0) == 1, timeout=300)


def condition(expected_ready, reasons=None):
    value = get("sekvyrsecret", RESOURCE, APP_NS)
    conditions = {item["type"]: item for item in value.get("status", {}).get("conditions", [])}
    ready = conditions.get("Ready", {})
    data = conditions.get("DataCurrent", {})
    if ready.get("status") != ("True" if expected_ready else "False"):
        return False
    if data.get("status") != ("True" if expected_ready else "False"):
        return False
    if reasons and ready.get("reason") not in reasons:
        return False
    store = get("sekvyrstore", STORE, APP_NS)
    store_conditions = {item["type"]: item for item in store.get("status", {}).get("conditions", [])}
    if any(store_conditions.get(name, {}).get("status") != ("True" if expected_ready else "False")
           for name in ("Ready", "DataCurrent")):
        return False
    if expected_ready and (value.get("status", {}).get("observedStoreUID") != store["metadata"]["uid"] or
                           value.get("status", {}).get("observedStoreGeneration") != store["metadata"]["generation"]):
        return False
    return value


def poke():
    kube("annotate", "sekvyrsecret", RESOURCE, "-n", APP_NS, "stage4-test-reconcile=" + uuid.uuid4().hex, "--overwrite")


class Session:
    def __init__(self, task, authority):
        self.task, self.authority = task, authority
        self.forwards = {}
        self.panel = self.connect("panel", PANEL_NS, "service/panel", authority.root / "panel-ca.crt")
        self.witness = self.connect("witness", WITNESS_NS, "service/witness", authority.root / "witness-ca.crt")
        self.owner = None

    def connect(self, label, namespace, target, ca):
        if label in self.forwards:
            self.forwards[label].close()
        forward = Forward(self.task, namespace, target, 8443)
        self.forwards[label] = forward
        return TLSClient("https://localhost:" + str(forward.port), str(ca))

    def login(self):
        _, response = self.panel.request("POST", "/api/auth/login", {"username": "admin", "password": self.authority.owner_password})
        self.owner = response["access_token"]
        SENSITIVE.append(self.owner)

    def owner_request(self, method, path, body=None, expected=(200,)):
        return self.panel.request(method, path, body, self.owner, expected)

    def ensure_unsealed(self):
        """A planned panel restart keeps the real vault's explicit unseal gate."""
        _, vault = self.owner_request("GET", "/api/vault/status")
        if not vault["initialized"]:
            raise RuntimeError("Test vault is not initialized")
        if vault["sealed"]:
            path = self.task / "private" / "vault-key.json"
            if not path.is_file():
                raise RuntimeError("Explicit fixture unseal key is unavailable; fresh isolated bootstrap required")
            key = json.loads(path.read_text())["root_key"]
            SENSITIVE.append(key)
            _, result = self.owner_request("POST", "/api/vault/unseal", {"root_key": key})
            if result["sealed"]:
                raise RuntimeError("Explicit test vault unseal failed")

    def publish(self, envelope, digest, expected_sequence, expected_hash):
        view = self.authority.scope["view_id"]
        _, stage = self.owner_request("POST", "/api/e2e2/views/" + view + "/envelopes", envelope, (201,))
        assert stage["envelope_hash"] == digest
        self.witness.request("POST", "/v1/logs/" + self.authority.scope["log_id"] + "/commits", {
            "envelope_hash": digest, "expected": {"witness_epoch": "1", "sequence": str(expected_sequence),
            "envelope_hash": expected_hash, "publisher_policy_epoch": "0" if expected_sequence == 0 else "1"},
        })
        _, indexed = self.owner_request("POST", "/api/e2e2/views/" + view + "/index", {"envelope_hash": digest})
        assert indexed["envelope_hash"] == digest

    def close(self):
        for forward in self.forwards.values():
            forward.close()


def infrastructure_phase(task, args):
    images = {name: getattr(args, name + "_image") for name in ("panel", "witness", "database", "python")}
    if any(not image for image in images.values()):
        raise RuntimeError("Infrastructure phase needs four digest-pinned images")
    for image in images.values():
        load_image(task, image)
    authority = Authority(task, panel_namespace=PANEL_NS, witness_namespace=WITNESS_NS)
    private_json(task, "namespace-uids.json", prepare_namespaces())
    prepare_panel(authority, images["panel"], images["database"])
    ready_deployment(PANEL_NS, "database")
    ready_deployment(PANEL_NS, "panel")
    mounts, genesis_hash = prepare_witness(authority, images["witness"])
    wait("offline genesis registration", lambda: get("job", "witness-genesis", WITNESS_NS).get("status", {}).get("succeeded") == 1)
    start_witness(images["witness"], mounts)
    ready_deployment(WITNESS_NS, "witness")
    private_json(task, "images.json", images)
    private_json(task, "genesis-hash.json", {"hash": genesis_hash})
    session = Session(task, authority)
    try:
        wait("actual TLS panel health", lambda: session.panel.request("GET", "/api/health"))
        _, capabilities = wait("actual TLS witness capabilities", lambda: session.witness.request("GET", "/v1/capabilities"))
        assert capabilities
        passed("actual panel/PostgreSQL and explicit development-profile TLS witness started independently")
    finally:
        session.close()


def bootstrap_phase(task):
    authority = Authority.load(task)
    session = Session(task, authority)
    try:
        session.login()
        _, vault = session.owner_request("GET", "/api/vault/status")
        if not vault["initialized"]:
            _, initialized = session.owner_request("POST", "/api/vault/init", {"mode": "env"})
            private_json(task, "vault-key.json", {"root_key": initialized["root_key"]})
            SENSITIVE.append(initialized["root_key"])
        session.ensure_unsealed()
        _, project = session.owner_request("POST", "/api/projects", {"slug": "canary", "title": "Isolated canary", "environments": ["prod"]}, (201,))
        _, envs = session.owner_request("GET", "/api/projects/" + str(project["id"]) + "/environments")
        environment = next(item for item in envs if item["name"] == "prod")
        jwks = json.loads(kube("get", "--raw", "/openid/v1/jwks").stdout)
        discovery = json.loads(kube("get", "--raw", "/.well-known/openid-configuration").stdout)
        _, cluster = session.owner_request("POST", "/api/machines/clusters", {"name": "isolated-kind", "issuer": discovery["issuer"], "audience": "sekvyr", "jwks": json.dumps(jwks)}, (201,))
        _, machine = session.owner_request("POST", "/api/machines", {"name": "operator-reader", "cluster_id": cluster["id"], "k8s_namespace": APP_NS, "k8s_service_account": SA}, (201,))
        session.owner_request("POST", "/api/policies", {"subject_type": "machine", "subject_id": machine["id"], "project_id": project["id"],
                             "environment_id": environment["id"], "path_prefix": "/", "actions": ["list", "read"], "effect": "allow"}, (201,))
        projected = kube("create", "token", SA, "-n", APP_NS, "--audience=sekvyr", "--duration=10m").stdout.strip()
        SENSITIVE.append(projected)
        _, token = session.panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": projected})
        machine_token = token["access_token"]
        SENSITIVE.append(machine_token)
        session.panel.request("POST", "/api/v1/machine/report", {"public_key": base64.b64encode(authority.node_public).decode()}, machine_token)
        session.owner_request("POST", "/api/e2e2/views", {"project_id": project["id"], "environment_id": environment["id"],
                              "context": authority.scope, "publisher_keys": {key_id(authority.publisher): b64(public(authority.publisher))},
                              "read_key_epoch": "1", "publisher_policy_epoch": "1"}, (201,))
        initial_demo_value = b64(os.urandom(32))
        envelope, digest = authority.snapshot(1, "0" * 64, "initial", initial_demo_value)
        session.publish(envelope, digest, 0, "0" * 64)
        session.owner_request("POST", "/api/e2e2/views/" + authority.scope["view_id"] + "/readers", {"machine_id": machine["id"], "wrapper": authority.reader_wrap()})
        panel_ca = config_map(APP_NS, "panel-ca", {"ca.crt": authority.panel_ca.decode()})
        witness_ca = config_map(APP_NS, "witness-ca", {"ca.crt": authority.witness_ca.decode()})
        crd_uids = {}
        for path in sorted((CHART / "crds").glob("*.yaml")):
            if common.DRIVER == "k0s":
                name = path.stem
                if kube("get", "crd", name, "--ignore-not-found", "-o", "name").stdout.strip():
                    raise RuntimeError("Existing Sekvyr CRD found; refusing to replace it")
            created = json.loads(kube("apply", "--server-side", "-f", "-", "-o", "json", value=path.read_text()).stdout)
            record_created_crd(task, crd_uids, created)
        private_json(task, "crd-uids.json", crd_uids)
        store = object_resource("SekvyrStore", STORE, APP_NS, {
            "endpoint": {"url": authority.panel_origin, "caConfigMapRef": {"name": "panel-ca", "key": "ca.crt"}},
            "bindings": [{"id": authority.binding_id, "name": "runtime", "resourceName": RESOURCE,
                          "source": {"group": "", "project": "canary", "environment": "prod", "pathPrefix": "/runtime", "viewId": authority.scope["view_id"]},
                          "selection": {"mode": "All"}, "encryption": {"mode": "E2E", "protocol": "e2e2", "trustKey": "runtime-view", "freshness": {"mode": "WitnessCurrent"}},
                          "target": {"name": TARGET, "type": "Opaque", "deletionPolicy": "Retain", "allowEmpty": False},
                          "rollout": {"allowedDeployments": []}}],
        }, api=API)
        store = create(store)
        identity = secret(APP_NS, "operator-identity", {"node.key": pem(authority.node)})
        trust = secret(APP_NS, "operator-trust", {"trust.json": canonical(authority.trust_bundle(store["metadata"]["uid"], digest, APP_NS, SA))})
        state = secret(APP_NS, "operator-state", {
            "installation.json": canonical({"installationID": authority.installation_id, "bootstrapGeneration": 1}),
            "state.json": canonical({"version": 1, "installationID": authority.installation_id, "bootstrapGeneration": 1,
                                     "trustBundleUID": trust["metadata"]["uid"], "nodeFingerprint": authority.node_fingerprint, "bindings": {}}),
        }, immutable=False)
        metadata = {"project_id": project["id"], "environment_id": environment["id"], "machine_id": machine["id"],
                    "namespace_uids": json.loads((task / "private" / "namespace-uids.json").read_text()), "crd_uids": crd_uids,
                    "store_uid": store["metadata"]["uid"], "initial_envelope": envelope, "initial_hash": digest, "initial_demo_value": initial_demo_value,
                    "identity_uid": identity["metadata"]["uid"], "trust_uid": trust["metadata"]["uid"], "state_uid": state["metadata"]["uid"],
                    "panel_ca_uid": panel_ca["metadata"]["uid"], "witness_ca_uid": witness_ca["metadata"]["uid"]}
        private_json(task, "bootstrap.json", metadata)
        passed("actual owner APIs register view, cluster JWKS identity, whole-view policy and independently signed wrapper")
        passed("initial signed snapshot staged, witness committed and fresh-proof indexed over separate TLS roots")
    finally:
        session.close()


def chart_values(authority, metadata, operator_image):
    repository, digest = operator_image.split("@", 1)
    return {"image": {"repository": repository, "digest": digest, "pullPolicy": "Never"}, "sync": {"enabled": True},
            "nodeSelector": {"kubernetes.io/hostname": common.NODE_NAME} if common.NODE_NAME else {},
            "installation": {"installationID": authority.installation_id, "namespace": APP_NS, "serviceAccount": SA, "bootstrapGeneration": 1,
                             "allowedPanelOrigins": [authority.panel_origin], "allowedWitnessOrigins": [authority.witness_origin],
                             "identityKeySecret": {"name": "operator-identity", "uid": metadata["identity_uid"], "key": "node.key"},
                             "trustBundleSecret": {"name": "operator-trust", "uid": metadata["trust_uid"], "key": "trust.json"},
                             "stateSecret": {"name": "operator-state", "uid": metadata["state_uid"], "key": "installation.json"},
                             "allowedTargetSecrets": [TARGET], "protectedSecretNames": [], "protectedSecretUIDs": [],
                             "protectedPrefixes": ["sh.helm.release.v1."],
                             "witnessCAConfigMapRef": {"name": "witness-ca", "key": "ca.crt"},
                             "caConfigMaps": [{"name": "panel-ca", "uid": metadata["panel_ca_uid"], "key": "ca.crt", "derSetSHA256": ca_pin(authority.panel_ca)},
                                              {"name": "witness-ca", "uid": metadata["witness_ca_uid"], "key": "ca.crt", "derSetSHA256": ca_pin(authority.witness_ca)}]}}


def assert_preserved(before):
    current = get("secret", TARGET, APP_NS)
    assert current["metadata"]["uid"] == before["metadata"]["uid"]
    assert current["data"] == before["data"]
    assert current["metadata"]["annotations"][REVISION] == before["metadata"]["annotations"][REVISION]
    return current


def read_canary(forward):
    with urllib.request.urlopen("http://127.0.0.1:" + str(forward.port) + "/status", timeout=3) as response:
        return json.loads(response.read())


def checkpoint_sequence(authority, metadata):
    current = get("secret", "operator-state", APP_NS)
    state = json.loads(base64.b64decode(current["data"]["state.json"]))
    record = state["bindings"][metadata["store_uid"] + "/" + authority.binding_id]
    return record["head"]["Sequence"]


def exercise_phase(task, operator_image):
    authority = Authority.load(task)
    metadata = json.loads((task / "private" / "bootstrap.json").read_text())
    images = json.loads((task / "private" / "images.json").read_text())
    if not operator_image:
        raise RuntimeError("Exercise needs a fresh digest-pinned operator image")
    load_image(task, operator_image)
    values = chart_values(authority, metadata, operator_image)
    values_path = task / "operator-values.json"
    protected_write(values_path, canonical(values))
    bootstrap_session = Session(task, authority)
    try:
        bootstrap_session.login()
        bootstrap_session.ensure_unsealed()
    finally:
        bootstrap_session.close()
    helm = os.environ.get("HELM_BIN", "helm")
    run([helm, "lint", str(CHART), "-n", APP_NS, "-f", str(values_path)])
    foreign = secret(APP_NS, TARGET, {"KEEP": b64(os.urandom(24))}, immutable=False)
    run([helm, "upgrade", "--install", "stage4", str(CHART), "--namespace", APP_NS, "--kubeconfig", str(task / "kubeconfig"),
         "-f", str(values_path), "--wait", "--timeout", "180s"])
    create(object_resource("SekvyrSecret", RESOURCE, APP_NS, {"storeRef": {"name": STORE, "uid": metadata["store_uid"]},
                    "binding": "runtime", "refreshIntervalSeconds": 30, "suspend": False, "rollout": {"enabled": False, "deployments": []}}, api=API))
    wait("foreign target blocked", lambda: condition(False, {"OwnershipConflict", "TargetConflict"}))
    blocked = get("secret", TARGET, APP_NS)
    assert blocked["metadata"]["resourceVersion"] == foreign["metadata"]["resourceVersion"]
    assert blocked["data"] == foreign["data"]
    passed("foreign preexisting target is never adopted or changed")
    kube("delete", "secret", TARGET, "-n", APP_NS)
    poke()
    wait("initial verified data", lambda: condition(True))
    initial_target = get("secret", TARGET, APP_NS)
    assert set(initial_target["data"]) == {"GENERATION", "DEMO_VALUE"}
    start_canary(images["python"], TARGET)
    wait("running canary pod", lambda: get("pod", "canary", APP_NS).get("status", {}).get("phase") == "Running")
    canary = Forward(task, APP_NS, "pod/canary", 8080)
    session = Session(task, authority)
    try:
        session.login()
        first = wait("canary initial configuration", lambda: (value if (value := read_canary(canary))["generation"] == "initial" else False))
        passed("initial full E2E2 view reaches actual mounted Kubernetes Secret and running app")
        changed_value = b64(os.urandom(32))
        SENSITIVE.extend([changed_value, metadata["initial_demo_value"], authority.owner_password, authority.db_password, authority.jwt_secret, authority.fetch_token,
                          b64(authority.read_key), authority.root_key, pem(authority.node).decode(), pem(authority.publisher).decode(), pem(authority.witness).decode()])
        second_envelope, second_hash = authority.snapshot(2, metadata["initial_hash"], "updated", changed_value)
        session.publish(second_envelope, second_hash, 1, metadata["initial_hash"])
        poke()
        wait("updated verified data", lambda: condition(True) and checkpoint_sequence(authority, metadata) == "2")
        second = wait("app live reload", lambda: (value if (value := read_canary(canary))["generation"] == "updated" else False))
        assert second["boot_id"] == first["boot_id"] and second["pid"] == first["pid"]
        assert second["reload_count"] == first["reload_count"] + 1
        target2 = get("secret", TARGET, APP_NS)
        assert target2["metadata"]["annotations"][REVISION] != initial_target["metadata"]["annotations"][REVISION]
        passed("live v1-to-v2 secret update reloads app with unchanged boot ID and PID")
        third_envelope, third_hash = authority.snapshot(3, second_hash, "updated", changed_value)
        session.publish(third_envelope, third_hash, 2, second_hash)
        poke()
        wait("equivalent plaintext checkpoint", lambda: condition(True) and checkpoint_sequence(authority, metadata) == "3")
        assert_preserved(target2)
        assert read_canary(canary)["reload_count"] == second["reload_count"]
        passed("new canonical ciphertext for equal plaintext advances checkpoint without data revision or app reload")
        fork, fork_hash = authority.snapshot(3, second_hash, "forged", b64(os.urandom(32)))
        session.owner_request("POST", "/api/e2e2/views/" + authority.scope["view_id"] + "/envelopes", fork, (201,))
        session.witness.request("POST", "/v1/logs/" + authority.scope["log_id"] + "/commits", {
            "envelope_hash": fork_hash, "expected": {"witness_epoch": "1", "sequence": "2", "envelope_hash": second_hash, "publisher_policy_epoch": "1"}}, expected=(409,))
        assert_preserved(target2)
        passed("real witness CAS rejects same-sequence fork publication")
        # Test privileged compromise of the disposable panel's blob/index store.
        # Owner staging rejects invalid signatures, so fault injection bypasses
        # that API deliberately while keeping the actual panel/data path in use.
        invalid_signature = copy.deepcopy(third_envelope)
        signature = bytearray(base64.urlsafe_b64decode(invalid_signature["signature"] + "=="))
        signature[0] ^= 1
        invalid_signature["signature"] = b64(bytes(signature))
        invalid_ciphertext = copy.deepcopy(third_envelope)
        ciphertext = bytearray(base64.urlsafe_b64decode(invalid_ciphertext["body"]["ciphertext"] + "=" * (-len(invalid_ciphertext["body"]["ciphertext"]) % 4)))
        ciphertext[0] ^= 1
        invalid_ciphertext["body"]["ciphertext"] = b64(bytes(ciphertext))
        invalid_ciphertext["signature"] = b64(authority.publisher.sign(b"sekvyr-e2e2/publish/v1\x00" + canonical(invalid_ciphertext["body"])))
        for name, altered in (("corrupted publisher signature", invalid_signature),
                              ("corrupted ciphertext with valid publisher signature", invalid_ciphertext),
                              ("old signed envelope replayed at current hash", metadata["initial_envelope"])):
            payload = {"operation": "replace-envelope", "view_id": authority.scope["view_id"], "envelope_hash": third_hash, "envelope": altered}
            kube("exec", "-i", "deployment/panel", "-n", PANEL_NS, "--", "python", "-c", PANEL_FAULT, value=json.dumps(payload))
            poke()
            wait(name + " rejected", lambda: condition(False))
            assert_preserved(target2)
            payload["envelope"] = third_envelope
            kube("exec", "-i", "deployment/panel", "-n", PANEL_NS, "--", "python", "-c", PANEL_FAULT, value=json.dumps(payload))
            poke()
            wait(name + " recovery", lambda: condition(True))
            assert_preserved(target2)
            passed(name + " fails closed through actual panel and recovers without stale fallback")
        attempt_before = get("sekvyrsecret", RESOURCE, APP_NS).get("status", {}).get("lastAttemptTime")
        kube("exec", "-i", "deployment/panel", "-n", PANEL_NS, "--", "python", "-c", PANEL_FAULT,
             value=json.dumps({"operation": "old-index", "view_id": authority.scope["view_id"], "envelope_hash": metadata["initial_hash"]}))
        poke()
        wait("old panel pointer ignored", lambda: (value if (value := condition(True)) and value["status"].get("lastAttemptTime") != attempt_before else False))
        assert checkpoint_sequence(authority, metadata) == "3"
        assert_preserved(target2)
        session.owner_request("POST", "/api/e2e2/views/" + authority.scope["view_id"] + "/index", {"envelope_hash": third_hash})
        passed("stale panel index and old bootstrap floor cannot override fresh canonical witness head")
        for namespace, name in ((PANEL_NS, "panel"), (WITNESS_NS, "witness")):
            kube("scale", "deployment", name, "-n", namespace, "--replicas=0")
            wait(name + " stopped", lambda n=namespace, resource=name: get("deployment", resource, n).get("status", {}).get("replicas", 0) == 0)
            poke()
            wait(name + " outage fails closed", lambda: condition(False))
            assert_preserved(target2)
            kube("scale", "deployment", name, "-n", namespace, "--replicas=1")
            ready_deployment(namespace, name)
            if name == "panel":
                session.panel = session.connect("panel", PANEL_NS, "service/panel", authority.root / "panel-ca.crt")
                session.login()
                session.ensure_unsealed()
            else:
                session.witness = session.connect("witness", WITNESS_NS, "service/witness", authority.root / "witness-ca.crt")
            poke()
            wait(name + " recovery", lambda: condition(True))
            assert checkpoint_sequence(authority, metadata) == "3"
            assert_preserved(target2)
            passed(name + " outage preserves target, marks data stale and recovers current head")
        pods = json.loads(kube("get", "pods", "-n", APP_NS, "-l", "app.kubernetes.io/instance=stage4", "-o", "json").stdout)["items"]
        assert len(pods) == 1
        old_pod = pods[0]["metadata"]["uid"]
        kube("delete", "pod", pods[0]["metadata"]["name"], "-n", APP_NS)
        wait("operator restarted", lambda: any(item["metadata"]["uid"] != old_pod and item.get("status", {}).get("phase") == "Running" for item in json.loads(kube("get", "pods", "-n", APP_NS, "-l", "app.kubernetes.io/instance=stage4", "-o", "json").stdout)["items"]))
        poke()
        wait("restart retained authority", lambda: condition(True))
        assert checkpoint_sequence(authority, metadata) == "3"
        assert_preserved(target2)
        assert read_canary(canary)["boot_id"] == first["boot_id"]
        passed("operator restart retains node identity, canonical checkpoint and app process")
        for verb, resource in (("list", "secrets"), ("watch", "secrets"), ("patch", "secrets"), ("delete", "secrets"),
                               ("patch", "deployments"), ("delete", "pods")):
            denied = kube("auth", "can-i", verb, resource, "-n", APP_NS, "--as=system:serviceaccount:" + APP_NS + ":" + SA, check=False)
            assert denied.stdout.strip() == "no"
        passed("sync RBAC has no Secret list/watch/patch/delete or Deployment rollout permission")
        old_state = get("secret", "operator-state", APP_NS)
        kube("delete", "secret", "operator-state", "-n", APP_NS)
        poke()
        wait("missing state closed", lambda: condition(False, {"StateMissing"}))
        assert_preserved(target2)
        replacement = object_resource("Secret", "operator-state", APP_NS)
        replacement.update(type="Opaque", data=old_state["data"])
        create(replacement)
        poke()
        wait("replaced state closed", lambda: condition(False, {"BootstrapMismatch", "StateReplaced"}))
        assert_preserved(target2)
        passed("lost and same-name replaced state never reset trust or overwrite target")
        visible = json.dumps(get("sekvyrsecret", RESOURCE, APP_NS)) + json.dumps(get("sekvyrstore", STORE, APP_NS))
        for namespace, name in ((PANEL_NS, "panel"), (WITNESS_NS, "witness"), (APP_NS, "stage4-operator")):
            visible += kube("logs", "deployment/" + name, "-n", namespace).stdout
        visible += kube("logs", "canary", "-n", APP_NS).stdout
        assert all(value not in visible for value in SENSITIVE if value)
        passed("component logs and public CR status contain no credentials, read keys or demo plaintext")
    finally:
        session.close()
        canary.close()
    report = {"scope": "Real isolated Kubernetes + actual panel/PostgreSQL + TLS development-profile witness + operator/app",
              "passed": RESULTS, "limitations": ["Development filesystem journal is not WORM and does not prove independent production storage",
              "No stage-5 Deployment rollout is implemented or authorized", "This harness does not connect to production"]}
    (task / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--driver", choices=("kind", "k0s"), default="kind")
    parser.add_argument("--expected-kubernetes", default="v1.37.0")
    parser.add_argument("--run-id")
    parser.add_argument("--node-name", default="")
    parser.add_argument("--chart-path", type=Path)
    parser.add_argument("--storage-class", default="")
    parser.add_argument("--phase", choices=("infrastructure", "bootstrap", "exercise"), required=True)
    for name in ("panel", "witness", "database", "python", "operator"):
        parser.add_argument("--" + name + "-image")
    args = parser.parse_args()
    global CHART
    if args.chart_path:
        CHART = args.chart_path.resolve()
    if not (CHART / "Chart.yaml").is_file():
        raise RuntimeError("Reviewed chart source is missing")
    common.configure(args.driver, args.task_dir, args.node_name)
    common.STORAGE_CLASS = args.storage_class
    if args.driver == "k0s":
        run_id = args.run_id or args.task_dir.name.removeprefix("sekvyr-stage4-")
        if not re.fullmatch(r"[0-9]{8}-[0-9a-f]{8}", run_id):
            raise RuntimeError("Invalid isolated run ID")
        infrastructure.configure("sekvyr-stage4-" + run_id)
        global PANEL_NS, WITNESS_NS, APP_NS
        PANEL_NS, WITNESS_NS, APP_NS = infrastructure.PANEL_NS, infrastructure.WITNESS_NS, infrastructure.APP_NS
    check_cluster(args.task_dir, args.expected_kubernetes)
    if args.phase == "infrastructure":
        infrastructure_phase(args.task_dir, args)
    elif args.phase == "bootstrap":
        bootstrap_phase(args.task_dir)
    else:
        exercise_phase(args.task_dir, args.operator_image)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("FAIL " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        raise SystemExit(1)
