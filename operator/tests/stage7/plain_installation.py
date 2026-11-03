"""Explicit non-HA Plain installation; no action or trust discovery on import.

The coordinator owns CRDs, namespaces, transport, panel lifecycle and cleanup.
prepare creates only pinned administrative materials, never a target Secret.
Actual Helm runs only through an explicit install/upgrade/uninstall call.
"""

import base64
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app_modes import IMAGE, NAME, OwnedNamespace, require, resource
from helm_lifecycle import HelmLifecycle, canonical, private_exact

API = "secrets.sekvyr.ru/v1alpha1"
REVISION = "secrets.sekvyr.ru/revision"
CHECKPOINT = "secrets.sekvyr.ru/checkpoint"


def der_set_hash(raw):
    certs = x509.load_pem_x509_certificates(raw)
    values = sorted({cert.public_bytes(serialization.Encoding.DER) for cert in certs})
    require(bool(values), "Explicit Plain panel CA required")
    return hashlib.sha256(b"".join(len(value).to_bytes(4, "big") + value for value in values)).hexdigest()


def binding_identity(binding):
    """Exact Go struct JSON order for the Plain protected record identity."""
    require(binding["encryption"] == {"mode": "Plain"}, "Plain identity cannot include E2E fields")
    value = {"ID": binding["id"], "Name": binding["name"], "ResourceName": binding["resourceName"],
        "Source": {key: binding["source"][key] for key in ("group", "project", "environment", "pathPrefix")},
        "Encryption": {"mode": "Plain"}, "TargetName": binding["target"]["name"],
        "Type": binding["target"]["type"], "Policy": binding["target"]["deletionPolicy"]}
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for before, after in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        raw = raw.replace(before, after)
    return hashlib.sha256(raw.encode()).hexdigest()


def strict_client_schema(schema):
    schema = copy.deepcopy(schema)
    def walk(value):
        if isinstance(value, dict):
            if value.get("type") == "object" and "properties" in value:
                value["additionalProperties"] = False
            for child in list(value.values()):
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(schema)
    return schema


class PlainInstallation:
    def __init__(self, coordinator, provider, image, helm, chart, namespace=None, panel_ca=None):
        self.c, self.provider, self.cluster = coordinator, provider, coordinator.cluster
        self.namespace = namespace or self.cluster.fixture["namespaces"]["isolation"]
        require(self.namespace == self.cluster.fixture["namespaces"]["isolation"], "Plain installation requires its reserved isolation namespace")
        require(IMAGE.fullmatch(image) is not None, "Explicit reviewed Plain operator digest required")
        self.image, self.helm, self.chart = image, helm, Path(chart)
        self.owned = OwnedNamespace(self.cluster, self.namespace)
        self.root = self.cluster.task / "private" / "stage7" / "plain-installation"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not self.root.is_symlink(), "Unsafe Plain installation context")
        if panel_ca is None:
            panel_ca = coordinator.app.materials["panel_ca"]
        require(isinstance(panel_ca, bytes) and len(panel_ca) <= 64 << 10, "Bounded explicit panel CA bytes required")
        self.ca, self.ca_hash = panel_ca, der_set_hash(panel_ca)
        self.sa, self.lease, self.release = "plain-operator", "plain-operator-leader", "stage7-plain"
        self.identity_name, self.trust_name, self.state_name, self.ca_name = "plain-node", "plain-trust", "plain-state", "plain-panel-ca"
        self.store_name, self.cr_name, self.binding_name = "plain-store", "plain-runtime", "runtime"
        self.lifecycle, self.values, self.binding = None, None, None
        origin = urllib.parse.urlsplit(coordinator.panel_origin)
        require(origin.scheme == "https" and origin.hostname and not origin.username and not origin.password
            and origin.path == "" and not origin.query and not origin.fragment, "Exact HTTPS panel origin required")
        self.origin = coordinator.panel_origin
        context = self.root / "context.json"
        if context.exists():
            require(not context.is_symlink(), "Unsafe Plain identity context")
            self.context = json.loads(context.read_bytes())
            require(set(self.context) == {"format", "installationID", "bindingID", "namespace", "namespaceUID", "image", "panelOrigin", "caHash"}
                and self.context["format"] == "sekvyr-stage7-plain-context-v1" and self.context["namespace"] == self.namespace
                and self.context["namespaceUID"] == self.owned.namespace_uid and self.context["image"] == image
                and self.context["panelOrigin"] == self.origin and self.context["caHash"] == self.ca_hash, "Reviewed Plain context changed on resume")
            for key in ("installationID", "bindingID"):
                require(str(uuid.UUID(self.context[key])) == self.context[key], "Invalid Plain identity context")
            require((self.root / "node.pem").is_file(), "Plain node material lost; explicit repair required")
        else:
            require(not (self.root / "node.pem").exists(), "Partial Plain identity preparation requires explicit review")
            node = ec.generate_private_key(ec.SECP256R1())
            private_exact(self.root / "node.pem", node.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            self.context = {"format": "sekvyr-stage7-plain-context-v1", "installationID": str(uuid.uuid4()), "bindingID": str(uuid.uuid4()),
                "namespace": self.namespace, "namespaceUID": self.owned.namespace_uid, "image": image,
                "panelOrigin": self.origin, "caHash": self.ca_hash}
            private_exact(context, canonical(self.context))
        require(not (self.root / "node.pem").is_symlink(), "Unsafe Plain node material")
        self.node_pem = (self.root / "node.pem").read_bytes()
        node = serialization.load_pem_private_key(self.node_pem, None)
        require(isinstance(node, ec.EllipticCurvePrivateKey) and isinstance(node.curve, ec.SECP256R1), "Plain node must be P256 PKCS8")
        self.fingerprint = "p256-sha256:" + hashlib.sha256(node.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).hexdigest()

    def __repr__(self):
        return "<stage7 isolated Plain installation [redacted]>"

    def _ensure(self, value, mutable_state=False):
        self.owned.reload_pins()
        kind, name = value["kind"], value["metadata"]["name"]
        if (kind, name) not in self.owned.pins:
            return self.owned.create(value)
        current = self.owned.get(kind, name)
        if kind == "Lease":
            require(value["spec"] == {} and set(current.get("spec", {})).issubset({"holderIdentity", "leaseDurationSeconds", "acquireTime", "renewTime", "leaseTransitions", "strategy", "preferredHolder"}), "Plain Lease differs from its explicit reservation")
        elif mutable_state:
            require(current.get("type") == "Opaque" and current.get("immutable") is False
                and current.get("data", {}).get("installation.json") == value["data"]["installation.json"], "Plain state marker or mutability changed")
            data = json.loads(base64.b64decode(current["data"]["state.json"], validate=True))
            initial = json.loads(base64.b64decode(value["data"]["state.json"], validate=True))
            require(all(data.get(key) == initial[key] for key in ("version", "installationID", "bootstrapGeneration", "trustBundleUID", "nodeFingerprint"))
                and isinstance(data.get("bindings"), dict), "Plain state bootstrap changed")
        else:
            for key in ("data", "binaryData", "type", "immutable", "automountServiceAccountToken"):
                require(current.get(key) == value.get(key), "Prepared Plain object differs from its reviewed input")
            require(not current.get("secrets") and not current.get("imagePullSecrets"), "Unexpected Plain SA credential references")
        return current

    def _secret(self, name, data, immutable=True, mutable_state=False):
        value = resource("Secret", name, self.namespace)
        value.update(type="Opaque", immutable=immutable, data={key: base64.b64encode(raw).decode() for key, raw in data.items()})
        return self._ensure(value, mutable_state)

    def prepare(self):
        account = resource("ServiceAccount", self.sa, self.namespace)
        account["automountServiceAccountToken"] = False
        self._ensure(account)
        self._ensure(resource("Lease", self.lease, self.namespace, {}, "coordination.k8s.io/v1"))
        self.route = self.provider.prepare_plain(self.sa, namespace=self.namespace)
        require(self.route["path"] == "/runtime" and self.route["source_config"]["SEKVYR_URL"] == self.origin, "Plain source routing differs from pinned origin/path")
        self._secret(self.identity_name, {"node.pem": self.node_pem})
        trust = {"schemaVersion": 1, "protocol": "plain-v1", "installationID": self.context["installationID"], "bootstrapGeneration": 1,
            "namespace": self.namespace, "serviceAccount": self.sa, "panelOrigin": self.origin, "nodePublicKeyFingerprint": self.fingerprint}
        self._secret(self.trust_name, {"trust.json": canonical(trust)})
        marker = {"installationID": self.context["installationID"], "bootstrapGeneration": 1}
        state = {"version": 1, **marker, "trustBundleUID": self.owned.get("Secret", self.trust_name)["metadata"]["uid"],
            "nodeFingerprint": self.fingerprint, "bindings": {}}
        self._secret(self.state_name, {"installation.json": canonical(marker), "state.json": canonical(state)}, False, True)
        ca = resource("ConfigMap", self.ca_name, self.namespace)
        ca.update(immutable=True, data={"ca.crt": self.ca.decode("ascii")})
        self._ensure(ca)
        self._prepared = True
        return {"route": copy.deepcopy(self.route), "namespace": self.namespace, "serviceAccount": self.sa,
            "externalRefs": self.external_refs(), "installationID": self.context["installationID"], "caRef": {"name": self.ca_name, "key": "ca.crt"}}

    def external_refs(self):
        return [{"kind": kind, "name": name, "uid": self.owned.get(kind, name)["metadata"]["uid"]}
            for kind, name in (("ServiceAccount", self.sa), ("Lease", self.lease), ("Secret", self.identity_name),
                ("Secret", self.trust_name), ("Secret", self.state_name), ("ConfigMap", self.ca_name))]

    def prepare_store(self, target="plain-runtime-env", selection=None, rollout_deployments=()):
        require(getattr(self, "_prepared", False), "Plain administrative materials must be prepared first")
        require(isinstance(target, str) and NAME.fullmatch(target) is not None, "Exact Plain target required")
        require(target not in {self.identity_name, self.trust_name, self.state_name} and not target.startswith(("sh.helm.release.v1.", "kube-api-access-")), "Protected Plain target is forbidden")
        deployments = list(rollout_deployments)
        require(len(deployments) == len(set(deployments)) and len(deployments) <= 16, "Exact bounded Plain rollout list required")
        for name in deployments:
            require(name != self.release + "-operator", "Operator cannot be its own rollout target")
            self.owned.get("Deployment", name)
        binding = {"id": self.context["bindingID"], "name": self.binding_name, "resourceName": self.cr_name,
            "source": {"group": self.route["group"], "project": self.route["project"], "environment": self.route["environment"], "pathPrefix": "/runtime"},
            "selection": copy.deepcopy(selection) if selection is not None else {"mode": "All"}, "encryption": {"mode": "Plain"},
            "target": {"name": target, "type": "Opaque", "deletionPolicy": "Retain", "allowEmpty": False},
            "rollout": {"allowedDeployments": deployments}}
        store = resource("SekvyrStore", self.store_name, self.namespace, {"endpoint": {"url": self.origin,
            "caConfigMapRef": {"name": self.ca_name, "key": "ca.crt"}}, "bindings": [binding]}, API)
        cr = resource("SekvyrSecret", self.cr_name, self.namespace, {"storeRef": {"name": self.store_name, "uid": ""},
            "binding": self.binding_name, "refreshIntervalSeconds": 30, "suspend": False,
            "rollout": {"enabled": bool(deployments), "deployments": deployments}}, API)
        # Validation before any CREATE catches shape drift in the real CRDs.
        from jsonschema import Draft7Validator, Draft202012Validator
        design = json.loads((self.chart.parents[1] / "design" / "resource.schema.json").read_bytes())
        for value in (store, cr):
            path = self.chart / "crds" / ("sekvyrstores.secrets.sekvyr.ru.yaml" if value["kind"] == "SekvyrStore" else "sekvyrsecrets.secrets.sekvyr.ru.yaml")
            import yaml
            schema = yaml.safe_load(path.read_text(encoding="utf-8"))["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
            # Placeholder only during shape validation; actual store UID comes
            # from its durably captured create response below.
            checked = copy.deepcopy(value)
            if value["kind"] == "SekvyrSecret":
                checked["spec"]["storeRef"]["uid"] = self.context["bindingID"]
            Draft7Validator(strict_client_schema(schema)).validate(checked)
            Draft202012Validator(design).validate(checked)
        private_exact(self.root / "store-plan.json", canonical({"store": store, "cr": cr}))
        created = self._ensure_custom(store)
        cr["spec"]["storeRef"]["uid"] = created["metadata"]["uid"]
        self._ensure_custom(cr)
        self.binding = binding
        self.values = self._values(target, deployments)
        private_exact(self.root / "values.json", canonical(self.values))
        return {"binding": copy.deepcopy(binding), "values": copy.deepcopy(self.values), "externalRefs": self.external_refs()}

    def _ensure_custom(self, value):
        self.owned.reload_pins()
        kind, name = value["kind"], value["metadata"]["name"]
        if (kind, name) not in self.owned.pins:
            return self.owned.create(value)
        current = self.owned.get(kind, name)
        require(current["spec"] == value["spec"], "Prepared Plain custom resource differs from explicit plan")
        return current

    def _values(self, target, deployments):
        pin = lambda name, key: {"name": name, "uid": self.owned.get("Secret", name)["metadata"]["uid"], "key": key}
        repository, digest = self.image.split("@")
        return {"image": {"repository": repository, "digest": digest, "pullPolicy": "IfNotPresent"}, "replicas": 1,
            "serviceAccount": {"create": False, "uid": self.owned.get("ServiceAccount", self.sa)["metadata"]["uid"]},
            "leaderElection": {"id": self.lease, "create": False, "uid": self.owned.get("Lease", self.lease)["metadata"]["uid"]},
            "configuration": {"retain": True}, "auth": {"tokenExpirationSeconds": 600}, "sync": {"enabled": True},
            "rollout": {"enabled": bool(deployments), "allowedDeployments": deployments}, "ha": {"enabled": False},
            "resources": {"requests": {"cpu": "25m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "192Mi"}},
            "installation": {"installationID": self.context["installationID"], "namespace": self.namespace, "serviceAccount": self.sa,
                "bootstrapGeneration": 1, "allowedPanelOrigins": [self.origin], "allowedWitnessOrigins": [],
                "identityKeySecret": pin(self.identity_name, "node.pem"), "trustBundleSecret": pin(self.trust_name, "trust.json"),
                "stateSecret": pin(self.state_name, "installation.json"), "protectedSecretNames": [], "protectedSecretUIDs": [],
                "protectedPrefixes": ["sh.helm.release.v1.", "kube-api-access-"], "allowedTargetSecrets": [target],
                "caConfigMaps": [{"name": self.ca_name, "uid": self.owned.get("ConfigMap", self.ca_name)["metadata"]["uid"],
                    "key": "ca.crt", "derSetSHA256": self.ca_hash}]}}

    def install(self):
        require(self.values is not None and self.lifecycle is None, "Prepared Plain installation can be installed once per explicit lifecycle")
        self.lifecycle = HelmLifecycle(self.cluster, self.helm, self.chart, self.release, self.namespace, self.external_refs())
        return self.lifecycle.install(self.values)

    def current(self, after_success=None):
        require(self.binding is not None, "Plain Store must be explicitly prepared")
        cr = self.owned.get("SekvyrSecret", self.cr_name)
        store = self.owned.get("SekvyrStore", self.store_name)
        status, conditions = cr.get("status", {}), {item["type"]: item for item in cr.get("status", {}).get("conditions", [])}
        if status.get("observedGeneration") != cr["metadata"]["generation"] or status.get("observedStoreUID") != store["metadata"]["uid"] or status.get("observedStoreGeneration") != store["metadata"]["generation"]:
            return False
        data, witness = conditions.get("DataCurrent", {}), conditions.get("WitnessReady", {})
        if data.get("status") != "True" or data.get("observedGeneration") != cr["metadata"]["generation"]:
            return False
        require(witness.get("status") == "Unknown" and witness.get("reason") == "NotApplicablePlain"
            and not status.get("lastVerifiedCheckpoint"), "Plain status must not claim witness/checkpoint verification")
        require(status.get("lastSuccessfulSyncTime") and status.get("lastSuccessfulSyncTime") == status.get("lastAttemptTime"), "Plain success observation is stale")
        if after_success is not None:
            try:
                current_time = datetime.fromisoformat(status["lastSuccessfulSyncTime"].replace("Z", "+00:00"))
                previous_time = datetime.fromisoformat(after_success.replace("Z", "+00:00"))
                require(current_time.tzinfo is not None and previous_time.tzinfo is not None, "Plain success timestamps require timezone")
            except (TypeError, ValueError, AttributeError):
                raise RuntimeError("Plain success timestamps invalid") from None
            if current_time <= previous_time:
                return False
        return cr

    def target_ref(self, generation=None, demo_value=None, after_success=None):
        cr = self.current(after_success)
        require(cr, "Plain target proof needs current successful status")
        state = self.owned.get("Secret", self.state_name)
        body = json.loads(base64.b64decode(state["data"]["state.json"], validate=True))
        require(body.get("version") == 1 and body.get("installationID") == self.context["installationID"] and body.get("bootstrapGeneration") == 1
            and body.get("trustBundleUID") == self.owned.get("Secret", self.trust_name)["metadata"]["uid"]
            and body.get("nodeFingerprint") == self.fingerprint and not body.get("recovery"), "Plain protected state bootstrap differs")
        store = self.owned.get("SekvyrStore", self.store_name)
        key = store["metadata"]["uid"] + "/" + self.context["bindingID"]
        record = body.get("bindings", {}).get(key, {})
        require(record.get("mode") == "Plain" and "head" in record and record["head"] is None
            and record.get("crUID") == cr["metadata"]["uid"] and record.get("crName") == self.cr_name
            and record.get("storeUID") == store["metadata"]["uid"] and record.get("bindingID") == self.context["bindingID"]
            and record.get("identity") == binding_identity(self.binding) and record.get("targetName") == self.binding["target"]["name"]
            and isinstance(record.get("targetUID"), str) and bool(record["targetUID"]), "Plain protected target binding differs")
        reference = {"name": record["targetName"], "uid": record["targetUID"]}
        target = json.loads(self.cluster.kube("get", "Secret", reference["name"], "-n", self.namespace, "-o", "json").stdout)
        meta, annotations = target["metadata"], target["metadata"].get("annotations", {})
        require(target["kind"] == "Secret" and meta["namespace"] == self.namespace and meta["name"] == reference["name"] and meta["uid"] == reference["uid"]
            and not meta.get("deletionTimestamp") and target.get("type") == "Opaque" and not target.get("immutable")
            and CHECKPOINT not in annotations and re.fullmatch(r"[0-9a-f]{32}", annotations.get(REVISION, ""))
            and annotations[REVISION] == cr["status"].get("lastAppliedRevision"), "Plain target UID/revision/mode differs")
        for name, expected in (("GENERATION", generation), ("DEMO_VALUE", demo_value)):
            if expected is not None:
                require(base64.b64decode(target["data"][name], validate=True) == expected.encode("utf-8"), "Plain target value did not reach expected generation")
        require(self.owned.get("Secret", self.state_name)["metadata"]["resourceVersion"] == state["metadata"]["resourceVersion"], "Plain protected state changed during target proof")
        return reference
