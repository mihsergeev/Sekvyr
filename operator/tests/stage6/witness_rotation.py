"""Explicit isolated-trial witness and panel pin replacement callback.

No operation runs on import. Only the live coordinator calls rotate_witness.
The prepared private plan and creation UID pins make retries exact; this module
never edits the operator's independent trust or the original genesis pin.
"""

import base64
import copy
import hashlib
import json
import re

from cryptography.hazmat.primitives import serialization

from fixture import canonical, pem, write_private
from forward import Forward
from journal_client import JournalClient
from manifests import object_resource
from protocol import key_descriptor
from witness import config as witness_config


BASE_KEYS = {"journal-ca.crt", "tls.crt", "tls.key", "client.crt", "client.key", "fetch-token", "witness.key"}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


class Owned:
    def __init__(self, cluster, namespace):
        self.cluster, self.namespace = cluster, namespace
        self.namespace_uid = cluster.namespace_pins()[namespace]

    def pin(self, kind, name):
        values = [json.loads(path.read_bytes()) for path in self.cluster.pins.glob("*.json")]
        matches = [item for item in values if item["namespace"] == self.namespace and item["kind"] == kind and item["name"] == name]
        require(len(matches) <= 1, "Ambiguous witness resource creation identity")
        return matches[0] if matches else None

    def guard(self):
        value = json.loads(self.cluster.kube("get", "namespace", self.namespace, "-o", "json").stdout)
        require(value["metadata"]["uid"] == self.namespace_uid and not value["metadata"].get("deletionTimestamp"), "Witness fixture namespace replaced")

    def get(self, kind, name):
        self.guard()
        pin = self.pin(kind, name)
        require(pin is not None, "Witness object lacks creation UID")
        value = json.loads(self.cluster.kube("get", kind, name, "-n", self.namespace, "-o", "json").stdout)
        require(value["metadata"]["uid"] == pin["uid"] and not value["metadata"].get("deletionTimestamp"), "Witness fixture resource replaced")
        return value

    def create_exact(self, value):
        self.guard()
        require(value["metadata"]["namespace"] == self.namespace, "Witness creation outside owned namespace")
        kind, name = value["kind"], value["metadata"]["name"]
        if self.pin(kind, name) is None:
            created = self.cluster.create(copy.deepcopy(value))
        else:
            created = self.get(kind, name)
        require(created["apiVersion"] == value["apiVersion"] and created.get("immutable") is True
            and created.get("data") == value.get("data") and created.get("type") == value.get("type"),
            "Existing witness material differs from exact prepared input")
        return created

    def replace_volumes(self, name, old_spec, new_spec):
        value = self.get("Deployment", name)
        if value["spec"] == new_spec:
            return
        require(value["spec"] == old_spec, "Witness Deployment changed outside prepared replacement")
        operations = [{"op": "test", "path": "/metadata/uid", "value": value["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": value["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/spec", "value": old_spec},
            {"op": "replace", "path": "/spec/template/spec/volumes", "value": new_spec["template"]["spec"]["volumes"]}]
        self.cluster.kube("patch", "Deployment", name, "-n", self.namespace, "--type=json", "-p", json.dumps(operations), "-o", "json")


def materials(coordinator, protocol, state):
    original = coordinator.protocol
    require(protocol.scope == original.scope and protocol.genesis_hash == original.genesis_hash
        and protocol.registration == original.registration and protocol.genesis_record == original.genesis_record,
        "Witness rotation cannot replace original journal registration")
    require(state["scope"] == protocol.scope and state["genesis_hash"] == protocol.genesis_hash
        and state["authority"] == protocol.authority and state["authority"]["witness_key"] == key_descriptor(protocol.witness),
        "Witness rotation differs from offline reviewed current authority")
    epoch = protocol.authority["witness_epoch"]
    require(isinstance(epoch, str) and re.fullmatch(r"[1-9][0-9]{0,19}", epoch) and int(epoch) <= 18446744073709551615,
        "Witness epoch invalid")
    diagnostic = original.fault_logs["replica-cas"]
    try:
        old_pem = (coordinator.private / "protocol" / "witness.key").read_bytes()
        old_key = serialization.load_pem_private_key(old_pem, password=None)
        require(key_descriptor(old_key) == diagnostic["record"]["genesis"]["body"]["authority"]["witness_key"],
            "Diagnostic witness key does not match its immutable genesis")
    except (ValueError, TypeError, AttributeError):
        raise RuntimeError("Diagnostic witness key invalid") from None
    require(key_descriptor(old_key) != key_descriptor(protocol.witness), "New witness key must differ from diagnostic signer")
    return epoch, old_pem


def prepare(coordinator, protocol, state, owned):
    epoch, old_pem = materials(coordinator, protocol, state)
    replicas = []
    for replica in ("witness-a", "witness-b"):
        old_files = owned.get("Secret", replica + "-files")
        require(old_files.get("immutable") is True and old_files.get("type") == "Opaque" and set(old_files.get("data", {})) == BASE_KEYS,
            "Unexpected original witness secret shape")
        expected_files = {"journal-ca.crt": (coordinator.private / "journal-ca.crt").read_bytes(),
            "tls.crt": (coordinator.private / "witness-server.crt").read_bytes(), "tls.key": (coordinator.private / "witness-server.key").read_bytes(),
            "client.crt": (coordinator.private / (replica + ".crt")).read_bytes(), "client.key": (coordinator.private / (replica + ".key")).read_bytes(),
            "fetch-token": (coordinator.private / "fetch-token").read_bytes(), "witness.key": old_pem}
        require(old_files["data"] == {name: base64.b64encode(raw).decode() for name, raw in expected_files.items()},
            "Original witness material differs from private fixture")
        old_config = owned.get("ConfigMap", replica + "-config")
        cfg = witness_config(coordinator.protocol, coordinator.namespaces, replica)
        require(old_config.get("immutable") is True and old_config.get("data") == {"config.json": canonical(cfg).decode()},
            "Original witness configuration differs from fixture")
        cfg["signing_key_files"] = ["/files/witness.key", "/files/diagnostic-witness.key"]
        key_suffix = key_descriptor(protocol.witness)["key_id"][-12:]
        files_name = replica + "-files-w" + epoch + "-" + key_suffix
        expected_files["witness.key"], expected_files["diagnostic-witness.key"] = pem(protocol.witness), old_pem
        secret = object_resource("Secret", files_name, owned.namespace)
        secret.update(type="Opaque", immutable=True, data={name: base64.b64encode(raw).decode() for name, raw in expected_files.items()})
        config_name = replica + "-config-w" + epoch + "-" + hashlib.sha256(canonical(cfg)).hexdigest()[:12]
        config = object_resource("ConfigMap", config_name, owned.namespace)
        config.update(immutable=True, data={"config.json": canonical(cfg).decode()})
        deployment = owned.get("Deployment", replica)
        old_spec = copy.deepcopy(deployment["spec"])
        require(deployment.get("apiVersion") == "apps/v1" and old_spec.get("replicas") == 1, "Unexpected witness Deployment shape")
        pod = old_spec["template"]["spec"]
        require(len(pod["containers"]) == 1 and pod["containers"][0]["name"] == "witness"
            and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", pod["containers"][0]["image"]), "Witness image must remain immutable")
        new_spec = copy.deepcopy(old_spec)
        volumes = new_spec["template"]["spec"]["volumes"]
        files = [item for item in volumes if item["name"] == "files"]
        configs = [item for item in volumes if item["name"] == "config"]
        require(len(files) == len(configs) == 1 and files[0]["secret"]["secretName"] == replica + "-files"
            and configs[0]["configMap"]["name"] == replica + "-config", "Witness base volume references changed")
        files[0]["secret"]["secretName"], configs[0]["configMap"]["name"] = files_name, config_name
        replicas.append({"name": replica, "uid": deployment["metadata"]["uid"], "secret": secret, "config": config,
            "old_spec": old_spec, "new_spec": new_spec})
    panel = coordinator.panel
    panel.protocol = protocol
    deployment = panel.get("Deployment", "panel")
    old_panel_spec = copy.deepcopy(deployment["spec"])
    revision = panel.revision + 1
    panel_name = "panel-files-rotation-" + str(revision)
    new_panel_spec = copy.deepcopy(old_panel_spec)
    volumes = new_panel_spec["template"]["spec"]["volumes"]
    fixture = [item for item in volumes if item["name"] == "fixture"]
    require(len(fixture) == 1 and fixture[0]["secret"]["secretName"] == panel.files_name, "Panel base pin volume changed")
    fixture[0]["secret"]["secretName"] = panel_name
    return {"scope": protocol.scope, "genesis_hash": protocol.genesis_hash, "authority": protocol.authority,
        "input_cursor": state["cursor"], "witness_namespace_uid": owned.namespace_uid,
        "replicas": replicas, "panel_uid": deployment["metadata"]["uid"], "panel_old_spec": old_panel_spec,
        "panel_new_spec": new_panel_spec, "panel_files_name": panel_name, "panel_revision": revision,
        "panel_files": {name: base64.b64encode(raw).decode() for name, raw in panel.file_materials(coordinator.witness_origin).items()}}


def validate_prepared(coordinator, protocol, state, owned, plan):
    epoch, old_pem = materials(coordinator, protocol, state)
    require(plan["scope"] == protocol.scope and plan["genesis_hash"] == protocol.genesis_hash
        and plan["authority"] == protocol.authority and plan["input_cursor"] == state["cursor"]
        and plan["witness_namespace_uid"] == owned.namespace_uid, "Witness retry differs from exact prepared input")
    require([item["name"] for item in plan["replicas"]] == ["witness-a", "witness-b"], "Prepared witness replicas differ")
    for item in plan["replicas"]:
        replica = item["name"]
        cfg = witness_config(coordinator.protocol, coordinator.namespaces, replica)
        cfg["signing_key_files"] = ["/files/witness.key", "/files/diagnostic-witness.key"]
        data = item["secret"].get("data", {})
        expected = {"journal-ca.crt": (coordinator.private / "journal-ca.crt").read_bytes(),
            "tls.crt": (coordinator.private / "witness-server.crt").read_bytes(), "tls.key": (coordinator.private / "witness-server.key").read_bytes(),
            "client.crt": (coordinator.private / (replica + ".crt")).read_bytes(), "client.key": (coordinator.private / (replica + ".key")).read_bytes(),
            "fetch-token": (coordinator.private / "fetch-token").read_bytes(), "witness.key": pem(protocol.witness), "diagnostic-witness.key": old_pem}
        require(data == {name: base64.b64encode(raw).decode() for name, raw in expected.items()}
            and item["config"].get("data") == {"config.json": canonical(cfg).decode()}, "Prepared witness credentials or configuration changed")
        require(item["secret"].get("kind") == "Secret" and item["secret"].get("type") == "Opaque" and item["secret"].get("immutable") is True
            and item["config"].get("kind") == "ConfigMap" and item["config"].get("immutable") is True
            and item["secret"]["metadata"]["namespace"] == owned.namespace and item["config"]["metadata"]["namespace"] == owned.namespace,
            "Prepared witness resource scope changed")
        expected_spec = copy.deepcopy(item["old_spec"])
        volumes = expected_spec["template"]["spec"]["volumes"]
        for name, field, reference in (("files", "secret", item["secret"]["metadata"]["name"]),
                                       ("config", "configMap", item["config"]["metadata"]["name"])):
            entries = [entry for entry in volumes if entry["name"] == name]
            require(len(entries) == 1, "Prepared witness volume ambiguous")
            entries[0][field]["secretName" if field == "secret" else "name"] = reference
        require(expected_spec == item["new_spec"], "Prepared witness replacement changes other Deployment fields")
    panel = copy.copy(coordinator.panel)
    panel.protocol = protocol
    require(plan["panel_files"] == {name: base64.b64encode(raw).decode() for name, raw in panel.file_materials(coordinator.witness_origin).items()},
        "Prepared independent panel pin changed")
    expected = copy.deepcopy(plan["panel_old_spec"])
    fixture = [item for item in expected["template"]["spec"]["volumes"] if item["name"] == "fixture"]
    require(len(fixture) == 1 and plan["panel_files_name"] == "panel-files-rotation-" + str(plan["panel_revision"]), "Prepared panel pin reference ambiguous")
    fixture[0]["secret"]["secretName"] = plan["panel_files_name"]
    require(expected == plan["panel_new_spec"], "Prepared panel replacement changes other Deployment fields")


def rotate_witness(coordinator, new_protocol, current_state):
    owned = Owned(coordinator.cluster, coordinator.namespaces["witness"])
    epoch, _ = materials(coordinator, new_protocol, current_state)
    directory = coordinator.private / ("witness-rotation-" + epoch)
    directory.mkdir(mode=0o700, exist_ok=True)
    plan_path = directory / "prepared.json"
    if plan_path.exists():
        plan = json.loads(plan_path.read_bytes())
    else:
        plan = prepare(coordinator, new_protocol, current_state, owned)
        write_private(plan_path, canonical(plan))
    validate_prepared(coordinator, new_protocol, current_state, owned, plan)
    app_protocol = coordinator.app.protocol
    for item in plan["replicas"]:
        require(owned.get("Deployment", item["name"])["metadata"]["uid"] == item["uid"], "Witness Deployment creation UID changed")
        owned.create_exact(item["secret"])
        owned.create_exact(item["config"])
        owned.replace_volumes(item["name"], item["old_spec"], item["new_spec"])
    for item in plan["replicas"]:
        coordinator.cluster.kube("rollout", "status", "deployment/" + item["name"], "-n", owned.namespace, "--timeout=240s")
        value = owned.get("Deployment", item["name"])
        require(value["spec"] == item["new_spec"] and value.get("status", {}).get("readyReplicas") == 1
            and value.get("status", {}).get("observedGeneration", 0) >= value["metadata"]["generation"], "Witness replacement is not current and ready")
    coordinator.witness_forward.close()
    coordinator.witness_forward = Forward(coordinator.cluster, owned.namespace, "service/witness", 8443)
    coordinator.client = JournalClient(coordinator.witness_forward.origin, coordinator.private / "journal-ca.crt",
        coordinator.private / "admin.crt", coordinator.private / "admin.key")
    panel = coordinator.panel
    panel.witness_client, panel.protocol = coordinator.client, new_protocol
    current_panel = panel.get("Deployment", "panel")
    require(current_panel["metadata"]["uid"] == plan["panel_uid"], "Panel Deployment creation UID changed")
    require(current_panel["spec"] in (plan["panel_old_spec"], plan["panel_new_spec"]), "Panel changed outside prepared pin replacement")
    panel_owned = Owned(coordinator.cluster, panel.namespace)
    if panel_owned.pin("Secret", plan["panel_files_name"]) is None:
        require(panel.revision == plan["panel_revision"] - 1, "Panel replacement counter differs from prepared pin")
        panel.replace_witness_pin(coordinator.witness_origin)
    else:
        value = panel_owned.get("Secret", plan["panel_files_name"])
        require(value.get("immutable") is True and value.get("data") == plan["panel_files"], "Prepared panel authority material changed")
        panel_owned.replace_volumes("panel", plan["panel_old_spec"], plan["panel_new_spec"])
        panel.files_name, panel.revision = plan["panel_files_name"], plan["panel_revision"]
    require(panel_owned.get("Secret", plan["panel_files_name"])["data"] == plan["panel_files"], "Panel independent pin differs from prepared material")
    coordinator.cluster.kube("rollout", "status", "deployment/panel", "-n", panel.namespace, "--timeout=240s")
    require(panel.get("Deployment", "panel")["spec"] == plan["panel_new_spec"], "Panel changed beyond independent pin replacement")
    panel.connect()
    panel.login()
    panel.unseal()
    require(coordinator.app.protocol is app_protocol, "Witness lifecycle changed operator trust implicitly")
    result = {"bothWitnessReplicasReconfigured": True, "panelIndependentPinUpdated": True,
        "originalRegistrationPreserved": True, "operatorTrustChanged": False, "production": False}
    completed = directory / "complete.json"
    if completed.exists():
        require(json.loads(completed.read_bytes()) == result, "Witness completion receipt differs")
    else:
        write_private(completed, canonical(result))
    return result
