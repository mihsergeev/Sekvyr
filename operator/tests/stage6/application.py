"""Actual trial application/HA helpers, driven by the stage6 coordinator.

This module never owns namespaces, storage, gateway, witness or relay lifecycle.
Every create goes through Cluster.create; mutations require creation UID + RV.
The provider owns publish/enrollment/journal/recovery CLI transport, not crypto
validation. A helper returning successfully is not a claim that all E2E ran.
"""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from fixture import canonical, pem, write_private
from forward import Forward
from journal_client import JournalClient, NoRedirect
from manifests import LABEL, object_resource
from protocol import key_descriptor, signed

API = "secrets.sekvyr.ru/v1alpha1"
APP, TARGET, STORE, RESOURCE = "environment-app", "runtime-env", "application-secrets", "runtime"
SA, FENCER_SA, LEASE, RELEASE = "sekvyr-operator", "sekvyr-fencer", "sekvyr-operator-leader", "stage6"
REVISION, CHECKPOINT = "secrets.sekvyr.ru/revision", "secrets.sekvyr.ru/checkpoint"
RELOADER_OPTOUT = {name: "false" for name in ("reloader.stakater.com/auto",
    "secret.reloader.stakater.com/auto", "configmap.reloader.stakater.com/auto")}
IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def write_values_once(path, raw):
    """Resume a failed render with identical values; never replace a fixture."""
    try:
        write_private(path, raw)
    except FileExistsError:
        require(not path.is_symlink() and path.is_file(), "Existing application values path is unsafe")
        with path.open("rb") as stream:
            existing = stream.read(len(raw) + 1)
        require(existing == raw, "Existing application values differ; overwrite refused")


def wait(check, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.4)
    raise RuntimeError("Trial application wait expired")


def ca_hash(raw):
    certificate = x509.load_pem_x509_certificate(raw)
    der = certificate.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(len(der).to_bytes(4, "big") + der).hexdigest()


def node_fingerprint(protocol):
    raw = protocol.node.public_key().public_bytes(serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    return "p256-sha256:" + hashlib.sha256(raw).hexdigest()


def binding_identity(binding):
    """Exact fixed Go bindingIdentity input, not JCS (Go struct field order)."""
    encryption = {"mode": binding["encryption"]["mode"]}
    for name in ("protocol", "trustKey", "freshness"):
        if binding["encryption"].get(name):
            encryption[name] = binding["encryption"][name]
    source = {name: "" for name in ("group", "project", "environment", "pathPrefix")}
    if binding["source"].get("viewId"):
        source["viewId"] = binding["source"]["viewId"]
    value = {"ID": binding["id"], "Name": binding["name"], "ResourceName": binding["resourceName"],
        "Source": source, "Encryption": encryption, "TargetName": binding["target"]["name"],
        "Type": binding["target"].get("type", "Opaque"), "Policy": binding["target"].get("deletionPolicy", "Retain")}
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for before, after in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                          ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        raw = raw.replace(before, after)
    return hashlib.sha256(raw.encode()).hexdigest()


def application_manifest(namespace, python_image, source_name="environment-app-source"):
    if IMAGE.fullmatch(python_image) is None:
        raise ValueError("Application image must be digest pinned")
    labels = {LABEL: "application", "app": APP}
    return object_resource("Deployment", APP, namespace, {"replicas": 0,
        "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "app", "image": python_image, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "/app/app.py"], "envFrom": [{"secretRef": {"name": TARGET}}],
                "ports": [{"containerPort": 8080}],
                "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 1},
                "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True}]}],
            "volumes": [{"name": "source", "configMap": {"name": source_name}}]}}}, "apps/v1") | {
        "metadata": {"name": APP, "namespace": namespace, "annotations": dict(RELOADER_OPTOUT)}}


class Application:
    def __init__(self, cluster, protocol):
        self.cluster, self.protocol, self.task = cluster, protocol, cluster.task
        self.namespace = cluster.fixture["namespaces"]["apps"]
        self.namespace_uid = cluster.namespace_pins()[self.namespace]
        self.state_name, self.trust_name, self.generation = "operator-state", "operator-trust", 1
        self.node_secret_name, self.fencer_signer_secret_name = "operator-node", "fencer-signing"
        self.fencer_tls_secret_name = "fencer-tls"
        self._context_bytes = None
        self.created = {}
        for path in cluster.pins.glob("*.json"):
            pin = json.loads(path.read_text())
            if pin["namespace"] == self.namespace:
                self.created[(pin["kind"], pin["name"])] = pin
        context_file = self.task / "private" / "application-context.json"
        if context_file.exists():
            require(not context_file.is_symlink() and context_file.is_file(), "Application context path unsafe")
            self._context_bytes = context_file.read_bytes()
            require(len(self._context_bytes) <= 16384, "Application context too large")
            self._load_context(json.loads(self._context_bytes))
        self._fixture_overrides()

    def __repr__(self):
        return "<stage6 trial application [redacted]>"

    def _load_context(self, value):
        require(set(value) == {"format", "installationID", "namespaceUID", "bootstrapGeneration", "refs"}
            and value["format"] == "sekvyr-stage6-application-context-v1"
            and value["installationID"] == self.protocol.installation_id and value["namespaceUID"] == self.namespace_uid
            and type(value["bootstrapGeneration"]) is int and 1 <= value["bootstrapGeneration"] <= 9007199254740991,
            "Application context identity mismatch")
        fields = {"node": "node_secret_name", "trust": "trust_name", "state": "state_name",
            "fencerSigner": "fencer_signer_secret_name", "fencerTLS": "fencer_tls_secret_name"}
        require(set(value["refs"]) == set(fields), "Application context references invalid")
        for role, attribute in fields.items():
            ref = value["refs"][role]
            require(set(ref) == {"name", "uid"} and isinstance(ref["name"], str)
                and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", ref["name"]), "Application context reference invalid")
            pin = self.created.get(("Secret", ref["name"]))
            require(pin is not None and pin["uid"] == ref["uid"], "Application context lacks exact creation UID")
            setattr(self, attribute, ref["name"])
        self.generation = value["bootstrapGeneration"]

    def remember_context(self):
        """Atomic private resume metadata: references and generation, no keys."""
        names = {"node": self.node_secret_name, "trust": self.trust_name, "state": self.state_name,
            "fencerSigner": self.fencer_signer_secret_name, "fencerTLS": self.fencer_tls_secret_name}
        value = {"format": "sekvyr-stage6-application-context-v1", "installationID": self.protocol.installation_id,
            "namespaceUID": self.namespace_uid, "bootstrapGeneration": self.generation,
            "refs": {role: {"name": name, "uid": self.get("Secret", name)["metadata"]["uid"]} for role, name in names.items()}}
        raw = canonical(value)
        path = self.task / "private" / "application-context.json"
        if path.exists():
            require(not path.is_symlink() and path.is_file(), "Application context path unsafe")
            current = path.read_bytes()
            if current == raw:
                self._context_bytes = raw
                return value
            require(self._context_bytes is not None and current == self._context_bytes, "Application context changed concurrently")
        else:
            require(self._context_bytes is None, "Application context disappeared")
        history = path.with_name("application-context-" + hashlib.sha256(raw).hexdigest() + ".json")
        write_values_once(history, raw)
        temporary = path.with_name(".application-context-" + uuid.uuid4().hex + ".tmp")
        write_private(temporary, raw)
        os.replace(temporary, path)
        self._context_bytes = raw
        return value

    def _fixture_overrides(self):
        path = self.task / "private" / "fixture-overrides.json"
        if not path.exists():
            return
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 8192, "Fixture overrides path unsafe")
        overrides = json.loads(path.read_bytes())
        require(set(overrides).issubset({"fencerTLS", "relayTLSLabel"}), "Unknown fixture override")
        if "fencerTLS" not in overrides:
            return
        ref = overrides["fencerTLS"]
        require(set(ref) == {"name", "uid", "label"}
            and re.fullmatch(r"[a-z][a-z0-9-]{0,40}", ref["label"]) is not None, "Fixture TLS override label invalid")
        pin = self.created.get(("Secret", ref["name"]))
        require(pin is not None and pin["uid"] == ref["uid"], "Fixture TLS override lacks creation UID")
        value = self.get("Secret", ref["name"])
        require(value.get("immutable") is True and value.get("type") == "Opaque", "Fixture TLS override material mutable")
        for key, suffix in (("tls.crt", ".crt"), ("tls.key", ".key")):
            source = path.with_name(ref["label"] + suffix)
            require(not source.is_symlink() and source.is_file() and source.stat().st_size <= 65536,
                "Fixture TLS override material path unsafe")
            require(base64.b64decode(value["data"][key]) == source.read_bytes(), "Fixture TLS override bytes differ from pinned Secret")
        self.fencer_tls_secret_name = ref["name"]

    def namespace_guard(self):
        value = json.loads(self.cluster.kube("get", "namespace", self.namespace, "-o", "json").stdout)
        require(value["metadata"]["uid"] == self.namespace_uid, "Application namespace replaced")

    def create(self, resource):
        self.namespace_guard()
        require(resource["metadata"].get("namespace") == self.namespace, "Application create outside owned namespace")
        value = self.cluster.create(resource)
        self.created[(value["kind"], value["metadata"]["name"])] = {
            "apiVersion": value["apiVersion"], "kind": value["kind"], "name": value["metadata"]["name"],
            "namespace": self.namespace, "uid": value["metadata"]["uid"]}
        return value

    def get(self, kind, name):
        self.namespace_guard()
        pin = self.created.get((kind, name))
        require(pin is not None, "Application object lacks creation UID")
        value = json.loads(self.cluster.kube("get", kind, name, "-n", self.namespace, "-o", "json").stdout)
        require(value["metadata"]["uid"] == pin["uid"] and not value["metadata"].get("deletionTimestamp"),
            "Application object replaced or deleting")
        return value

    def patch(self, kind, name, operations):
        value = self.get(kind, name)
        for operation in operations:
            path = operation.get("path", "")
            require(path not in ("", "/", "/metadata", "/metadata/uid", "/metadata/name", "/metadata/namespace",
                "/metadata/resourceVersion") and operation.get("op") in ("add", "replace", "remove", "test"),
                "Unsafe application patch")
        patch = [{"op": "test", "path": "/metadata/uid", "value": value["metadata"]["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": value["metadata"]["resourceVersion"]}] + copy.deepcopy(operations)
        result = json.loads(self.cluster.kube("patch", kind, name, "-n", self.namespace, "--type=json",
            "-p", json.dumps(patch), "-o", "json").stdout)
        require(result["metadata"]["uid"] == value["metadata"]["uid"], "Application mutation UID mismatch")
        return result

    def secret(self, name, values, immutable=True):
        value = object_resource("Secret", name, self.namespace)
        value.update(type="Opaque", immutable=immutable,
            data={key: base64.b64encode(raw).decode() for key, raw in values.items()})
        return self.create(value)

    def config_map(self, name, values):
        value = object_resource("ConfigMap", name, self.namespace)
        value.update(immutable=True, data=values)
        return self.create(value)

    def ref(self, kind, name, wire=False):
        value = self.get(kind, name)
        return {("api_version" if wire else "apiVersion"): value["apiVersion"], "kind": kind,
            "namespace": self.namespace, "name": name, "uid": value["metadata"]["uid"]}

    def prepare(self, python_image, panel_origin, witness_origin, initial_snapshot, materials):
        """Creates app reservations only; coordinator first installs reviewed CRDs.

        materials: panel_ca, witness_ca, journal_ca, fencer_ca,
        fencer_tls_cert/key, operator_client_cert/key, fencer_client_cert/key bytes.
        Certificate generation remains in the offline coordinator fixture.
        """
        p = self.protocol
        require(initial_snapshot["sequence"] != "0", "Signed initialization needs a positive canonical snapshot")
        self.panel_origin, self.witness_origin = panel_origin, witness_origin
        for name in (SA, FENCER_SA):
            resource = object_resource("ServiceAccount", name, self.namespace)
            resource["automountServiceAccountToken"] = False
            self.create(resource)
        self.create(object_resource("Lease", LEASE, self.namespace, {}, "coordination.k8s.io/v1"))
        self.secret(TARGET, {"GENERATION": b"reserved", "DEMO_VALUE": b"public-trial-reservation"}, False)
        source = Path(__file__).resolve().parent.parent / "stage5" / "app.py"
        self.config_map("environment-app-source", {"app.py": source.read_text(encoding="utf-8")})
        self.create(application_manifest(self.namespace, python_image))
        for label in ("panel", "witness", "journal", "fencer"):
            self.config_map(label + "-ca", {"ca.crt": materials[label + "_ca"].decode()})
        self.secret("operator-node", {"node.pem": pem(p.node)})
        self.secret("fencer-signing", {"key.pem": pem(p.fencer)})
        for label, prefix in (("fencer-tls", "fencer_tls"), ("operator-gateway", "operator_client"), ("fencer-gateway", "fencer_client")):
            self.secret(label, {"tls.crt": materials[prefix + "_cert"], "tls.key": materials[prefix + "_key"]})
        binding = {"id": p.binding_id, "name": "runtime", "resourceName": RESOURCE,
            "source": {"group": "trial", "project": "trial", "environment": "trial", "pathPrefix": "/runtime", "viewId": p.scope["view_id"]},
            "selection": {"mode": "All"}, "encryption": {"mode": "E2E", "protocol": "e2e2", "trustKey": "runtime-view", "freshness": {"mode": "WitnessCurrent"}},
            "target": {"name": TARGET, "type": "Opaque", "deletionPolicy": "Retain", "allowEmpty": False},
            "rollout": {"allowedDeployments": [APP]}}
        store = self.create(object_resource("SekvyrStore", STORE, self.namespace, {"endpoint": {
            "url": panel_origin, "caConfigMapRef": {"name": "panel-ca", "key": "ca.crt"}}, "bindings": [binding]}, API))
        self.create(object_resource("SekvyrSecret", RESOURCE, self.namespace, {"storeRef": {"name": STORE, "uid": store["metadata"]["uid"]},
            "binding": "runtime", "refreshIntervalSeconds": 30, "suspend": False,
            "rollout": {"enabled": True, "deployments": [APP]}}, API))
        self.binding = binding
        publisher, witness = key_descriptor(p.publisher), key_descriptor(p.witness)
        trust = {"schemaVersion": 2, "installationID": p.installation_id, "bootstrapGeneration": 1,
            "namespace": self.namespace, "serviceAccount": SA, "panelOrigin": panel_origin, "nodePublicKeyFingerprint": node_fingerprint(p),
            "viewTrust": [{"trustKey": "runtime-view", "storeUID": store["metadata"]["uid"], "bindingID": p.binding_id,
                **{name + "ID": p.scope[name + "_id"] for name in ("realm", "project", "environment", "view", "log")},
                "publisherPolicyEpoch": p.authority["publisher_policy_epoch"], "publisherPublicKey": publisher["public_key"],
                "publisherKeyFingerprint": publisher["key_id"], "witness": {"origin": witness_origin, "epoch": p.authority["witness_epoch"],
                    "publicKey": witness["public_key"], "keyFingerprint": witness["key_id"]},
                "minimumCheckpoint": {"sequence": initial_snapshot["sequence"], "envelopeHash": initial_snapshot["envelope_hash"]}}]}
        self.secret("operator-trust", {"trust.json": canonical(trust)})
        self.secret("operator-state", {"installation.json": canonical({"installationID": p.installation_id, "bootstrapGeneration": 1})}, False)
        self.materials = materials
        self.remember_context()
        return self.enrollment()

    def enrollment(self, generation=None):
        generation = self.generation if generation is None else generation
        return {"installation_id": self.protocol.installation_id, "bootstrap_generation": generation,
            "namespace": self.namespace, "namespace_uid": self.namespace_uid,
            "operator_service_account": SA, "operator_service_account_uid": self.get("ServiceAccount", SA)["metadata"]["uid"],
            "fencer_service_account": FENCER_SA, "fencer_service_account_uid": self.get("ServiceAccount", FENCER_SA)["metadata"]["uid"],
            "lease": self.ref("Lease", LEASE, True), "node_fingerprint": node_fingerprint(self.protocol),
            "identity_key_secret_uid": self.get("Secret", self.node_secret_name)["metadata"]["uid"],
            "trust_bundle_secret_uid": self.get("Secret", self.trust_name)["metadata"]["uid"],
            "allowed_objects": sorted([self.ref("Secret", name, True) for name in (TARGET, self.state_name)] + [self.ref("Deployment", APP, True)],
                key=lambda value: "|".join(value[key] for key in ("api_version", "kind", "namespace", "name")))}

    def recovery_plan(self, current, generation=None, previous_generation=0, previous_state_uid="", allow_rollout=False):
        generation = self.generation if generation is None else generation
        cr, store, state = self.get("SekvyrSecret", RESOURCE), self.get("SekvyrStore", STORE), self.get("Secret", self.state_name)
        raw = base64.b64decode(state.get("data", {}).get("state.json", ""))
        body = {"format": "sekvyr-checkpoint-recovery-v1", "operation": "initialize" if previous_generation == 0 else "recover",
            "recovery_id": str(uuid.uuid4()), "installation_id": self.protocol.installation_id,
            "previous_bootstrap_generation": previous_generation, "previous_state_secret_uid": previous_state_uid,
            "bootstrap_generation": generation, "state_secret_name": self.state_name, "state_secret_uid": state["metadata"]["uid"],
            "identity_key_secret_uid": self.get("Secret", self.node_secret_name)["metadata"]["uid"],
            "trust_bundle_secret_uid": self.get("Secret", self.trust_name)["metadata"]["uid"], "node_fingerprint": node_fingerprint(self.protocol),
            "scope": self.protocol.scope, "genesis_hash": self.protocol.genesis_hash,
            "cursor": current["cursor"], "snapshot": current["snapshot"],
            "binding": {"store_name": STORE, "store_uid": store["metadata"]["uid"], "cr_name": RESOURCE, "cr_uid": cr["metadata"]["uid"],
                "binding_id": self.protocol.binding_id, "view_id": self.protocol.scope["view_id"], "target_name": TARGET,
                "target_uid": self.get("Secret", TARGET)["metadata"]["uid"], "cr_generation": cr["metadata"]["generation"],
                "store_generation": store["metadata"]["generation"], "identity": binding_identity(store["spec"]["bindings"][0])},
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expected_state_sha256": hashlib.sha256(raw).hexdigest(), "allow_rollout": bool(allow_rollout)}
        return signed("sekvyr-e2e2/checkpoint-recovery/v1", body, self.protocol.admin)

    def chart_values(self, image, bootstrap_subject, gateway_origin, webhook_ca, node_name="", relay_service=""):
        require(IMAGE.fullmatch(image) is not None, "Operator image must be digest pinned")
        repository, digest = image.split("@")
        pins = lambda name, key: {"name": name, "uid": self.get("Secret", name)["metadata"]["uid"], "key": key}
        ca_pins = [{"name": label + "-ca", "uid": self.get("ConfigMap", label + "-ca")["metadata"]["uid"], "key": "ca.crt",
            "derSetSHA256": ca_hash(self.materials[label + "_ca"])} for label in ("panel", "witness", "journal", "fencer")]
        enrollment = self.enrollment()
        return {"image": {"repository": repository, "digest": digest, "pullPolicy": "IfNotPresent"}, "replicas": 2,
            "nodeSelector": {"kubernetes.io/hostname": node_name} if node_name else {},
            "sync": {"enabled": True}, "rollout": {"enabled": True, "allowedDeployments": [APP]}, "leaderElection": {"id": LEASE},
            "installation": {"installationID": self.protocol.installation_id, "namespace": self.namespace, "serviceAccount": SA,
                "bootstrapGeneration": self.generation, "allowedPanelOrigins": [self.panel_origin], "allowedWitnessOrigins": [self.witness_origin],
                "identityKeySecret": pins(self.node_secret_name, "node.pem"), "trustBundleSecret": pins(self.trust_name, "trust.json"),
                "stateSecret": pins(self.state_name, "installation.json"), "protectedSecretNames": [], "protectedSecretUIDs": [],
                "protectedPrefixes": ["sh.helm.release.v1."], "caConfigMaps": ca_pins, "allowedTargetSecrets": [TARGET],
                "witnessCAConfigMapRef": {"name": "witness-ca", "key": "ca.crt"}},
            "ha": {"enabled": True, "trial": True, "namespaceUID": self.namespace_uid,
                "operatorServiceAccountUID": enrollment["operator_service_account_uid"], "leaseUID": enrollment["lease"]["uid"],
                "managedObjects": [{"apiVersion": ref["api_version"], **{key: ref[key] for key in ("kind", "namespace", "name", "uid")}}
                    for ref in enrollment["allowed_objects"]],
                "config": {"trial": True, "fencerOrigin": "https://" + RELEASE + "-fencer." + self.namespace + ".svc.cluster.local:9443",
                    "allowedFencerOrigins": ["https://" + RELEASE + "-fencer." + self.namespace + ".svc.cluster.local:9443"],
                    "fencerCAConfigMapRef": {"name": "fencer-ca", "key": "ca.crt"}, "gatewayOrigin": gateway_origin,
                    "gatewayCAConfigMapRef": {"name": "journal-ca", "key": "ca.crt"}, "gatewayClientSecret": pins("operator-gateway", "tls.crt"),
                    "gatewayClientKeyKey": "tls.key", "journal": self.protocol.registration},
                "fencer": {"replicas": 2, "serviceAccount": {"name": FENCER_SA, "uid": enrollment["fencer_service_account_uid"]},
                    "signingKeySecret": pins(self.fencer_signer_secret_name, "key.pem"), "tlsSecret": {"name": self.fencer_tls_secret_name, "uid": pins(self.fencer_tls_secret_name, "tls.crt")["uid"]},
                    "gatewayClientSecret": pins("fencer-gateway", "tls.crt"), "gatewayClientKeyKey": "tls.key", "bootstrapSubjects": [bootstrap_subject]},
                "webhook": {"caBundle": base64.b64encode(webhook_ca).decode(), "serviceName": relay_service}}}

    def install_chart(self, values, helm, chart):
        """Render Helm, review exact cluster objects, create with UID checkpoints.

        Precreated SA/Lease retain their original creation UID; no Helm adoption,
        apply, upgrade or new release Secret can mutate an unreviewed object.
        """
        import yaml
        path = self.task / "private" / "application-values.json"
        write_values_once(path, canonical(values))
        command = [str(helm), "template", RELEASE, str(chart), "-n", self.namespace, "-f", str(path)]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        require(process.returncode == 0, "Trial Helm rendering failed")
        resources = [value for value in yaml.safe_load_all(process.stdout) if value]
        cluster_resources = [value for value in resources if not value["metadata"].get("namespace")]
        self.cluster.review_cluster_manifests(cluster_resources)
        for value in resources:
            kind, name = value["kind"], value["metadata"]["name"]
            if kind in ("ServiceAccount", "Lease") and (kind, name) in self.created:
                current = self.get(kind, name)
                if kind == "ServiceAccount":
                    require(name in (SA, FENCER_SA) and current.get("automountServiceAccountToken") is False
                        and value.get("automountServiceAccountToken") is False
                        and not current.get("secrets") and not current.get("imagePullSecrets"),
                        "Precreated ServiceAccount differs from reviewed configuration")
                else:
                    require(name == LEASE and current.get("spec", {}) == value.get("spec", {}) == {},
                        "Precreated Lease differs from reviewed configuration")
                continue
            if value["metadata"].get("namespace"):
                self.create(value)
            else:
                self.cluster.create(value)
        return {"chartRendered": True, "operatorReplicas": 2, "fencerReplicas": 2}

    def start_application_after_initialize(self):
        state = self.get("Secret", self.state_name)
        try:
            progress = json.loads(base64.b64decode(state.get("data", {}).get("state.json", "")))
        except (ValueError, TypeError):
            raise RuntimeError("Application requires completed signed initialization") from None
        require(progress.get("recovery", {}).get("phase") == "complete", "Application requires completed signed initialization")
        target = self.get("Secret", TARGET)
        require(CHECKPOINT in target.get("metadata", {}).get("annotations", {}) and
            REVISION in target["metadata"]["annotations"], "Application target lacks verified checkpoint")
        deployment = self.get("Deployment", APP)
        require(deployment["spec"]["replicas"] == 0 and not deployment["spec"]["template"]["metadata"].get("annotations"),
            "Application was started or restarted before initialization")
        self.patch("Deployment", APP, [{"op": "replace", "path": "/spec/replicas", "value": 1}])
        return wait(self.status)

    def remove_state_for_recovery(self):
        """Explicit fault injection only; replacement uses a NEW name and UID."""
        value = self.get("Secret", self.state_name)
        body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {
            "uid": value["metadata"]["uid"], "resourceVersion": value["metadata"]["resourceVersion"]}}
        self.cluster.kube("delete", "--raw", "/api/v1/namespaces/" + self.namespace + "/secrets/" + self.state_name,
            "-f", "-", data=json.dumps(body))
        return value["metadata"]["uid"]

    def prepare_recovery_reservations(self, generation):
        require(isinstance(generation, int) and generation > self.generation, "Recovery generation must increase")
        old_trust = self.get("Secret", self.trust_name)
        trust = json.loads(base64.b64decode(old_trust["data"]["trust.json"]))
        trust["bootstrapGeneration"] = generation
        state_name, trust_name = "operator-state-r" + str(generation), "operator-trust-r" + str(generation)
        self.secret(trust_name, {"trust.json": canonical(trust)})
        self.secret(state_name, {"installation.json": canonical({"installationID": self.protocol.installation_id,
            "bootstrapGeneration": generation})}, False)
        self.state_name, self.trust_name, self.generation = state_name, trust_name, generation
        self.remember_context()
        return self.enrollment()

    def recovery_baseline(self):
        target = self.get("Secret", TARGET)
        return {"footprint": self.footprint(), "boot_id": self.status()["boot_id"],
            "revision": target["metadata"]["annotations"][REVISION], "data": copy.deepcopy(target["data"])}

    def assert_recovery_no_old_intent(self, before):
        """After coordinator's signed same-byte recovery, inspect protected auth."""
        target, state = self.get("Secret", TARGET), self.get("Secret", self.state_name)
        recovered = json.loads(base64.b64decode(state["data"]["state.json"]))
        require(recovered["recovery"]["phase"] == "complete", "Recovery remains incomplete")
        record = recovered["bindings"][self.get("SekvyrStore", STORE)["metadata"]["uid"] + "/" + self.protocol.binding_id]
        require(not record["rollout"]["intent"]["eligible"], "Recovery restored old rollout eligibility")
        require(target["data"] == before["data"] and target["metadata"]["annotations"][REVISION] == before["revision"],
            "Same-byte recovery changed target data or revision")
        self.frozen(before["footprint"])
        require(self.status()["boot_id"] == before["boot_id"], "Recovery replayed an old application restart")
        return {"sameByteSignedRecoveryNoOldRollout": True}

    def operator_pod(self):
        deployment = self.get("Deployment", RELEASE + "-operator")
        selector = deployment["spec"]["selector"]["matchLabels"]
        query = ",".join(key + "=" + value for key, value in sorted(selector.items()))
        pods = json.loads(self.cluster.kube("get", "pods", "-n", self.namespace, "-l", query, "-o", "json").stdout)["items"]
        lease = self.get("Lease", LEASE)
        holder = lease.get("spec", {}).get("holderIdentity", "")
        matching = [pod for pod in pods if holder.startswith(pod["metadata"]["name"] + "_")
            and pod["spec"].get("serviceAccountName") == SA and not pod["metadata"].get("deletionTimestamp")]
        require(len(matching) == 1, "No unique bound operator leader pod")
        return matching[0], holder

    def projected_token(self, pod, audience="sekvyr-fence", bound=True):
        """Admin fixture TokenRequest; bearer stays in memory, never in argv/logs."""
        self.namespace_guard()
        self.get("ServiceAccount", SA)
        require(pod["metadata"]["namespace"] == self.namespace and pod["spec"].get("serviceAccountName") == SA,
            "TokenRequest pod scope mismatch")
        name, uid = pod["metadata"]["name"], pod["metadata"]["uid"]
        current = json.loads(self.cluster.kube("get", "pod", name, "-n", self.namespace, "-o", "json").stdout)
        require(current["metadata"]["uid"] == uid and not current["metadata"].get("deletionTimestamp"), "TokenRequest pod replaced")
        spec = {"expirationSeconds": 600}
        if audience is not None:
            spec["audiences"] = [audience]
        if bound:
            spec["boundObjectRef"] = {"apiVersion": "v1", "kind": "Pod", "name": name, "uid": uid}
        resource = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": spec}
        path = "/api/v1/namespaces/" + self.namespace + "/serviceaccounts/" + SA + "/token"
        result = json.loads(self.cluster.kube("create", "--raw", path, "-f", "-", data=json.dumps(resource)).stdout)
        token = result["status"]["token"]
        require(isinstance(token, str) and len(token) <= 16384, "Invalid projected fixture token")
        return token

    def late_write_body(self, grant_hash):
        require(re.fullmatch(r"[0-9a-f]{64}", grant_hash) is not None, "Invalid fixed session grant hash")
        target = self.get("Secret", TARGET)
        target["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/write-session"] = grant_hash
        target["metadata"]["annotations"]["stage6-trial-late-write"] = "held-request"
        return target

    def token_update_target(self, token, body):
        """Real external API write: cancellation of old manager cannot abort it.

        Coordinator may hold the real admission response through its relay. This
        function deliberately retains the supplied OLD RV; no GET/rebase/retry.
        Only a precreated owned target is permitted, never another Kube route.
        """
        import yaml
        self.namespace_guard()
        pin = self.created[("Secret", TARGET)]
        meta = body.get("metadata", {})
        require(body.get("kind") == "Secret" and body.get("apiVersion") == "v1" and meta.get("name") == TARGET
            and meta.get("namespace") == self.namespace and meta.get("uid") == pin["uid"] and meta.get("resourceVersion"),
            "External write target identity mismatch")
        raw = self.cluster.config.read_bytes()
        require(len(raw) <= 1 << 20, "Scoped kubeconfig too large")
        config = yaml.safe_load(raw)
        contexts = [value["context"] for value in config["contexts"] if value["name"] == config["current-context"]]
        require(len(contexts) == 1, "Ambiguous scoped kubeconfig context")
        clusters = [value["cluster"] for value in config["clusters"] if value["name"] == contexts[0]["cluster"]]
        require(len(clusters) == 1, "Ambiguous scoped kubeconfig cluster")
        cluster = clusters[0]
        origin = cluster["server"]
        parsed = urllib.parse.urlsplit(origin)
        require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
            and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
            and not cluster.get("insecure-skip-tls-verify") and cluster.get("certificate-authority-data"),
            "Verified fixed Kubernetes TLS origin required")
        ca = base64.b64decode(cluster["certificate-authority-data"], validate=True).decode("ascii")
        context = ssl.create_default_context(cadata=ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        url = origin.rstrip("/") + "/api/v1/namespaces/" + self.namespace + "/secrets/" + TARGET
        request = urllib.request.Request(url, data=canonical(body), method="PUT",
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, ssl.SSLError, OSError):
            raise RuntimeError("External trial API write transport failed") from None
        with response:
            require(len(response.read((1 << 20) + 1)) <= 1 << 20, "External trial API response too large")
            require(response.status in (200, 401, 403, 409), "Unexpected external trial API status")
            return response.status

    def assert_late_write_conflicted(self, status):
        require(status == 409, "Late already-approved write must conflict in Kubernetes storage")
        require("stage6-trial-late-write" not in self.get("Secret", TARGET)["metadata"].get("annotations", {}),
            "Stale external write reached the target")
        return {"alreadyApprovedOldWriterStorageCAS409": True}

    def fencer_call(self, origin, ca_file, token, operation, body):
        require(operation in ("acquire", "barriers", "ready"), "Unknown trial fencer operation")
        client = JournalClient(origin, ca_file)
        return client.request("POST", "/v1/installations/" + self.protocol.installation_id + "/" + operation,
            canonical(body), {"Content-Type": "application/json", "Authorization": "Bearer " + token},
            expected=(200, 401, 403, 409, 503), maximum=256 << 10)

    def tokenreview_cases(self, fencer_origin, ca_file):
        pod, holder = self.operator_pod()
        body = {"bootstrap_generation": self.generation, "expected_lease_holder_identity": holder}
        for audience, bound in (("wrong-trial-audience", True), ("sekvyr-fence", False)):
            token = self.projected_token(pod, audience, bound)
            status, _, _ = self.fencer_call(fencer_origin, ca_file, token, "acquire", body)
            require(status == 401, "Fencer accepted unbound or wrong-audience token")
        token = self.projected_token(pod)
        status, _, _ = self.fencer_call(fencer_origin, ca_file, token, "acquire", body)
        require(status == 200, "Fencer rejected current bound leader token")
        return {"wrongAudienceRejected": True, "UnboundTokenRejected": True, "currentBoundLeaderAccepted": True}

    def old_process_denied(self, fencer_origin, ca_file, old_pod, old_holder, token):
        current, holder = self.operator_pod()
        require(current["metadata"]["uid"] == old_pod["metadata"]["uid"] and holder != old_holder,
            "Same-Pod new process was not established by coordinator")
        status, _, _ = self.fencer_call(fencer_origin, ca_file, token, "acquire",
            {"bootstrap_generation": self.generation, "expected_lease_holder_identity": old_holder})
        require(status == 409, "Old process adopted replacement Lease holder")
        return {"samePodNewProcessOldHolderDenied": True}

    def rbac_cases(self):
        self.get("ServiceAccount", SA)
        actor = "system:serviceaccount:" + self.namespace + ":" + SA
        cases = [("get", "secret/" + TARGET, True), ("update", "secret/" + TARGET, True),
            ("list", "secrets", False), ("watch", "secrets", False), ("create", "secrets", False),
            ("delete", "secret/" + TARGET, False), ("get", "secret/fencer-signing", False),
            ("get", "secret/fencer-gateway", False), ("get", "deployment/" + APP, True),
            ("patch", "deployment/" + APP, True), ("patch", "deployment/" + RELEASE + "-fencer", False),
            ("update", "deployment/" + APP, False), ("delete", "pods", False),
            ("create", "tokenreviews.authentication.k8s.io", False)]
        for verb, resource, expected in cases:
            result = self.cluster.kube("auth", "can-i", verb, resource, "-n", self.namespace, "--as", actor, check=False)
            require(result.returncode in (0, 1) and result.stdout.strip() in ("yes", "no"), "RBAC probe transport failed")
            require((result.stdout.strip() == "yes") == expected, "Operator RBAC exceeded or lacked exact permission")
        return {"operatorRBACTestedOperations": len(cases), "secretCreateListWatchDeleteDenied": True,
            "fencerPrivateMaterialDenied": True, "fencerDeploymentPatchDenied": True}

    def current(self, snapshot, rollout_ready=None):
        cr = self.get("SekvyrSecret", RESOURCE)
        status = cr.get("status", {})
        conditions = {item["type"]: item for item in status.get("conditions", [])}
        if status.get("observedGeneration") != cr["metadata"]["generation"] or conditions.get("DataCurrent", {}).get("status") != "True":
            return False
        if status.get("lastVerifiedCheckpoint") != {"sequence": snapshot["sequence"], "envelopeHash": snapshot["envelope_hash"]}:
            return False
        if rollout_ready is not None and conditions.get("RolloutReady", {}).get("status") != ("True" if rollout_ready else "False"):
            return False
        return cr

    def poke(self):
        cr = self.get("SekvyrSecret", RESOURCE)
        annotations = dict(cr["metadata"].get("annotations", {}))
        annotations["stage6-trial-reconcile"] = uuid.uuid4().hex
        return self.patch("SekvyrSecret", RESOURCE,
            [{"op": "add", "path": "/metadata/annotations", "value": annotations}])

    def unavailable(self):
        cr = self.get("SekvyrSecret", RESOURCE)
        status = cr.get("status", {})
        conditions = {item["type"]: item for item in status.get("conditions", [])}
        return status.get("observedGeneration") == cr["metadata"]["generation"] and conditions.get("DataCurrent", {}).get("status") == "False"

    def pod(self):
        self.get("Deployment", APP)
        values = json.loads(self.cluster.kube("get", "pods", "-n", self.namespace, "-l", "app=" + APP, "-o", "json").stdout)["items"]
        ready = [value for value in values if not value["metadata"].get("deletionTimestamp") and any(
            item["type"] == "Ready" and item["status"] == "True" for item in value.get("status", {}).get("conditions", []))]
        return ready[0] if len(ready) == 1 else False

    def status(self):
        pod = self.pod()
        if not pod:
            return False
        with Forward(self.cluster, self.namespace, "pod/" + pod["metadata"]["name"], 8080) as forward:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open("http://127.0.0.1:" + str(forward.port) + "/status", timeout=5) as response:
                value = json.loads(response.read(4097))
        require(set(value) == {"generation", "boot_id", "pid", "value_digest"}, "Unexpected application status fields")
        require(UUID.fullmatch(value["boot_id"]) is not None and isinstance(value["pid"], int), "Invalid application boot proof")
        return dict(value, pod_uid=pod["metadata"]["uid"])

    def footprint(self):
        deployment = self.get("Deployment", APP)
        sets = json.loads(self.cluster.kube("get", "replicasets", "-n", self.namespace, "-l", "app=" + APP, "-o", "json").stdout)["items"]
        uid = deployment["metadata"]["uid"]
        require(all(any(ref["uid"] == uid and ref["kind"] == "Deployment" for ref in value["metadata"].get("ownerReferences", [])) for value in sets),
            "Application ReplicaSet has foreign owner")
        return {"deployment_uid": uid, "template": deployment["spec"]["template"],
            "replica_sets": sorted(value["metadata"]["uid"] for value in sets)}

    def frozen(self, before, seconds=7):
        deadline = time.monotonic() + seconds
        while True:
            require(self.footprint() == before, "Unexpected application template or ReplicaSet change")
            if time.monotonic() >= deadline:
                return True
            time.sleep(0.5)

    def basic_rollout_cases(self, provider):
        """Provider: current(), publish(generation,demo)->snapshot, fault context.

        It must enroll + signed-initialize before this call. Fault injection and
        recovery are coordinator-owned contexts; no service lifecycle here.
        """
        initial = provider.current()["snapshot"]
        wait(lambda: self.current(initial, True))
        before_start = self.footprint()
        require(not before_start["template"]["metadata"].get("annotations"), "Initialization requested a historical restart")
        require(self.get("Deployment", APP)["spec"]["replicas"] == 1,
            "Coordinator must start initialized application before the operator")
        first = wait(self.status)
        before = self.footprint()
        require(len(before["replica_sets"]) == 1, "Initial app has ambiguous ReplicaSet history")
        generation, demo = "changed-" + uuid.uuid4().hex, uuid.uuid4().hex
        snapshot = provider.publish(generation, demo)
        wait(lambda: self.current(snapshot, True))
        changed = wait(lambda: value if (value := self.status()) and value["generation"] == generation else False)
        after = self.footprint()
        require(changed["boot_id"] != first["boot_id"] and changed["pod_uid"] != first["pod_uid"], "Data change did not replace the app pod")
        require(changed["value_digest"] == hashlib.sha256(demo.encode()).hexdigest(), "New pod did not consume changed bytes")
        require(len(set(after["replica_sets"]) - set(before["replica_sets"])) == 1, "Changed value created an unexpected ReplicaSet count")
        expected = copy.deepcopy(before["template"])
        key = "secrets.sekvyr.ru/restart-" + self.get("Secret", TARGET)["metadata"]["uid"]
        expected["metadata"].setdefault("annotations", {})[key] = self.get("Secret", TARGET)["metadata"]["annotations"][REVISION]
        require(after["template"] == expected, "Rollout changed another pod-template field")
        revision = self.get("Secret", TARGET)["metadata"]["annotations"][REVISION]
        equal = provider.publish(generation, demo)
        wait(lambda: self.current(equal, True))
        require(self.get("Secret", TARGET)["metadata"]["annotations"][REVISION] == revision, "Equal plaintext changed the data revision")
        self.frozen(after)
        require(self.status()["boot_id"] == changed["boot_id"], "Equal plaintext restarted the app")
        checks = ["signed-initialize-no-historical-rollout", "changed-data-one-new-pod-and-replicaset", "equal-plaintext-no-extra-rollout"]
        for label in ("panel", "witness", "fencer"):
            with provider.outage(label):
                self.poke()
                wait(self.unavailable)
                self.frozen(after)
                require(self.status()["boot_id"] == changed["boot_id"], "Dependency outage restarted the app")
            self.poke()
            wait(lambda: self.current(equal, True))
            self.frozen(after, seconds=1)
            checks.append(label + "-outage-no-extra-rollout")
        # No claim about stale writers/TokenReview/relay/recovery is emitted here.
        return {"production": False, "passed": checks, "appProof": {
            "oldBootID": first["boot_id"], "newBootID": changed["boot_id"], "oldPodUID": first["pod_uid"],
            "newPodUID": changed["pod_uid"], "newReplicaSetCount": 1, "podTemplateOnlyOwnRestartAnnotation": True}}
