"""Explicit coordinator-driven trial reconfiguration. No live action on import.

The caller supplies reviewed old/new Helm values and all new trust material.
No panel key discovery, apply, adoption, automatic enrollment or recovery runs.
Kubernetes mutations remain creation-UID/resourceVersion guarded and resumable.
"""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from cryptography.hazmat.primitives import serialization

from application import (APP, FENCER_SA, RELEASE, SA, STORE, RESOURCE, TARGET,
    REVISION, node_fingerprint, require, wait, write_values_once)
from fixture import canonical, pem, write_private
from protocol import key_descriptor


def _structural(value):
    return {key: copy.deepcopy(value.get(key)) for key in ("apiVersion", "kind", "spec", "rules", "roleRef", "subjects", "webhooks")}


def _role_shape(rules):
    """Resource names may change; an existing broad rule cannot be broadened."""
    result = []
    for rule in rules:
        normalized = copy.deepcopy(rule)
        if "resourceNames" in normalized:
            require(bool(normalized["resourceNames"]), "Empty RBAC resource-name restriction")
            require(len(normalized["resourceNames"]) == len(set(normalized["resourceNames"])), "Duplicate RBAC resource names")
            normalized["resourceNames"] = ["EXACT_ADMIN_NAMES"]
        result.append(canonical(normalized))
    return sorted(result)


def next_trust_bundle(app, protocol, generation, snapshot):
    """Offline fixture keys are explicit authority; never import remote keys."""
    old = app.get("Secret", app.trust_name)
    value = json.loads(base64.b64decode(old["data"]["trust.json"]))
    require(len(value["viewTrust"]) == 1 and snapshot["sequence"] != "0", "One positive reviewed trust view required")
    publisher, witness = key_descriptor(protocol.publisher), key_descriptor(protocol.witness)
    value["bootstrapGeneration"], value["nodePublicKeyFingerprint"] = generation, node_fingerprint(protocol)
    view = value["viewTrust"][0]
    view.update(publisherPolicyEpoch=protocol.authority["publisher_policy_epoch"], publisherPublicKey=publisher["public_key"],
        publisherKeyFingerprint=publisher["key_id"], minimumCheckpoint={"sequence": snapshot["sequence"], "envelopeHash": snapshot["envelope_hash"]})
    view["witness"].update(epoch=protocol.authority["witness_epoch"], publicKey=witness["public_key"], keyFingerprint=witness["key_id"])
    return value


class Reconfiguration:
    def __init__(self, app, helm, chart, expected_values, operation_id):
        require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", operation_id) is not None, "Explicit reconfiguration ID required")
        self.app, self.cluster = app, app.cluster
        self.helm, self.chart = str(helm), Path(chart)
        self.directory = app.task / "private" / ("reconfigure-" + operation_id)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        require(not self.directory.is_symlink(), "Reconfiguration directory symlink refused")
        self.expected_values = copy.deepcopy(expected_values)
        require(expected_values["installation"]["namespace"] == app.namespace
            and expected_values["installation"]["installationID"] == app.protocol.installation_id,
            "Reconfiguration installation mismatch")
        write_values_once(self.directory / "expected-values.json", canonical(expected_values))
        self.old = self._render(expected_values, "expected")
        self.plan_path, self._plan_bytes = self.directory / "progress.json", None
        if self.plan_path.exists():
            require(not self.plan_path.is_symlink(), "Reconfiguration progress symlink refused")
            self._plan_bytes = self.plan_path.read_bytes()
            require(len(self._plan_bytes) <= 1 << 20, "Reconfiguration progress too large")
            self.plan = json.loads(self._plan_bytes)
            require(self.plan["format"] == "sekvyr-stage6-reconfigure-v1"
                and self.plan["namespaceUID"] == app.namespace_uid
                and self.plan["installationID"] == app.protocol.installation_id
                and self.plan["expectedValuesHash"] == hashlib.sha256(canonical(expected_values)).hexdigest(),
                "Reconfiguration progress identity mismatch")
        else:
            self.plan = {"format": "sekvyr-stage6-reconfigure-v1", "namespaceUID": app.namespace_uid,
                "installationID": app.protocol.installation_id, "expectedValuesHash": hashlib.sha256(canonical(expected_values)).hexdigest(),
                "phase": "new", "expected": {}}

    def __repr__(self):
        return "<explicit trial reconfiguration [redacted]>"

    def _save(self):
        raw = canonical(self.plan)
        if self.plan_path.exists():
            require(not self.plan_path.is_symlink() and self.plan_path.read_bytes() == self._plan_bytes,
                "Reconfiguration progress changed concurrently")
        else:
            require(self._plan_bytes is None, "Reconfiguration progress disappeared")
        write_values_once(self.directory / ("progress-" + hashlib.sha256(raw).hexdigest() + ".json"), raw)
        temporary = self.directory / (".progress-" + uuid.uuid4().hex)
        write_private(temporary, raw)
        os.replace(temporary, self.plan_path)
        self._plan_bytes = raw

    def _render(self, values, label):
        import yaml
        path = self.directory / (label + "-values.json")
        write_values_once(path, canonical(values))
        try:
            result = subprocess.run([self.helm, "template", RELEASE, str(self.chart), "-n", self.app.namespace,
                "-f", str(path)], text=True, capture_output=True, timeout=60)
        except (subprocess.TimeoutExpired, OSError):
            raise RuntimeError("Reconfiguration Helm unavailable") from None
        require(result.returncode == 0, "Reconfiguration Helm rendering failed")
        resources = {}
        for value in yaml.safe_load_all(result.stdout):
            if not value:
                continue
            key = value["kind"], value["metadata"]["name"]
            require(key not in resources and value["metadata"].get("namespace", self.app.namespace) == self.app.namespace,
                "Reconfiguration render scope or duplicate mismatch")
            resources[key] = value
        return resources

    def _normalized(self, desired, current):
        """API dry-run supplies real defaults without adopting the live spec."""
        value = copy.deepcopy(desired)
        value["metadata"]["uid"] = current["metadata"]["uid"]
        value["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
        result = self.cluster.kube("replace", "--dry-run=server", "-f", "-", "-o", "json", data=json.dumps(value))
        normalized = json.loads(result.stdout)
        require(normalized["metadata"]["uid"] == current["metadata"]["uid"], "Dry-run returned a different UID")
        return normalized

    def _normalized_spec(self, desired, current):
        return self._normalized(desired, current)["spec"]

    def _application_invariant(self):
        target = self.app.get("Secret", TARGET)
        cr, store = self.app.get("SekvyrSecret", RESOURCE), self.app.get("SekvyrStore", STORE)
        return {"targetUID": target["metadata"]["uid"], "dataHash": hashlib.sha256(canonical(target.get("data", {}))).hexdigest(),
            "revision": target["metadata"].get("annotations", {}).get(REVISION), "application": self.app.footprint(),
            "crUID": cr["metadata"]["uid"], "crGeneration": cr["metadata"]["generation"],
            "storeUID": store["metadata"]["uid"], "storeGeneration": store["metadata"]["generation"]}

    def _preserve(self):
        require(self._application_invariant() == self.plan["applicationInvariant"],
            "Reconfiguration changed application data, revision, template or identities")

    def _no_operator_pods(self):
        deployment = self.app.get("Deployment", RELEASE + "-operator")
        labels = deployment["spec"]["selector"]["matchLabels"]
        selector = ",".join(key + "=" + value for key, value in sorted(labels.items()))
        sets = json.loads(self.cluster.kube("get", "replicasets", "-n", self.app.namespace, "-l", selector, "-o", "json").stdout)["items"]
        require(all(any(ref.get("uid") == deployment["metadata"]["uid"] and ref.get("kind") == "Deployment"
            for ref in value["metadata"].get("ownerReferences", [])) for value in sets), "Operator ReplicaSet owner mismatch")
        uids = {value["metadata"]["uid"] for value in sets}
        pods = json.loads(self.cluster.kube("get", "pods", "-n", self.app.namespace, "-l", selector, "-o", "json").stdout)["items"]
        require(all(any(ref.get("uid") in uids and ref.get("kind") == "ReplicaSet"
            for ref in value["metadata"].get("ownerReferences", [])) for value in pods), "Operator Pod owner mismatch")
        return deployment["spec"]["replicas"] == 0 and not pods

    def _deployment(self, name, replicas=None, template=None):
        key = "Deployment/" + name
        current = self.app.get("Deployment", name)
        expected = self.plan["expected"][key]
        require(current["metadata"]["uid"] == expected["uid"], "Deployment creation UID changed")
        desired = copy.deepcopy(current)
        desired["spec"] = copy.deepcopy(expected["spec"])
        if replicas is not None:
            desired["spec"]["replicas"] = replicas
        if template is not None:
            desired["spec"]["template"] = copy.deepcopy(template)
        normalized = self._normalized_spec(desired, current)
        if current["spec"] != normalized:
            require(current["spec"] == expected["spec"], "Deployment prior spec changed")
            operations = [{"op": "test", "path": "/spec", "value": expected["spec"]}]
            if template is not None:
                operations.append({"op": "replace", "path": "/spec/template", "value": template})
            if replicas is not None:
                operations.append({"op": "replace", "path": "/spec/replicas", "value": replicas})
            updated = self.app.patch("Deployment", name, operations)
            require(updated["spec"] == normalized, "Deployment server mutation differs from reviewed dry-run")
        self.plan["expected"][key] = {"uid": current["metadata"]["uid"], "spec": normalized}
        self._save()

    def stop_operator(self):
        if self.plan["phase"] == "new":
            self.plan["applicationInvariant"] = self._application_invariant()
            for key, desired in self.old.items():
                kind, name = key
                if kind == "Role":
                    current = self.app.get(kind, name)
                    require(current.get("rules", []) == desired.get("rules", []), "Role differs from explicit previous Helm rules")
                    self.plan["expected"][kind + "/" + name] = {"uid": current["metadata"]["uid"], "rules": current.get("rules", [])}
                elif kind == "Deployment":
                    require(name in (RELEASE + "-operator", RELEASE + "-fencer"), "Unreviewed Deployment in chart")
                    current = self.app.get(kind, name)
                    require(current["spec"] == self._normalized_spec(desired, current), "Deployment differs from explicit previous Helm spec")
                    self.plan["expected"][kind + "/" + name] = {"uid": current["metadata"]["uid"], "spec": current["spec"]}
                elif kind == "ValidatingWebhookConfiguration":
                    pins = [pin for pin in self.cluster.cluster_creation_pins() if pin["kind"] == kind and pin["name"] == name]
                    require(len(pins) == 1, "Webhook lacks exact creation identity")
                    current = json.loads(self.cluster.kube("get", kind, name, "-o", "json").stdout)
                    require(current["metadata"]["uid"] == pins[0]["uid"] and self.cluster.guard_hash(current) ==
                        self.cluster.active_cluster_guard(pins[0]), "Webhook prior UID or approved structure changed")
                    expected = self._normalized(desired, current)
                    require(len(current["webhooks"]) == len(expected["webhooks"]) == 1, "Expected one exact trial webhook")
                    require({k: v for k, v in current["webhooks"][0].items() if k != "matchConditions"} ==
                        {k: v for k, v in expected["webhooks"][0].items() if k != "matchConditions"}, "Webhook differs from explicit prior service/trust/rules")
                    self.plan["webhook"] = current
            self.plan["phase"] = "stopping"
            self._save()
        require(self.plan["phase"] in ("stopping", "stopped", "prepared", "applying", "applied"), "Reconfiguration already resumed")
        self._deployment(RELEASE + "-operator", replicas=0)
        wait(self._no_operator_pods)
        self._preserve()
        if self.plan["phase"] in ("stopping", "stopped"):
            self.plan["phase"] = "stopped"
            self._save()
        return {"operatorStopped": True}

    def prepare(self, generation, protocol, node_private, trust_bundle, fencer_private):
        require(self.plan["phase"] in ("stopped", "prepared") and self._no_operator_pods(), "Stop operator before new bootstrap preparation")
        require(type(generation) is int and generation > self.expected_values["installation"]["bootstrapGeneration"],
            "New bootstrap generation must increase")
        require(protocol.installation_id == self.app.protocol.installation_id and protocol.scope == self.app.protocol.scope
            and protocol.genesis_hash == self.app.protocol.genesis_hash, "New protocol identity changed")
        require(pem(node_private) == pem(protocol.node) and pem(fencer_private) == pem(protocol.fencer), "Explicit key material does not match reviewed protocol")
        require(trust_bundle["bootstrapGeneration"] == generation and trust_bundle["installationID"] == protocol.installation_id
            and trust_bundle["namespace"] == self.app.namespace and trust_bundle["serviceAccount"] == SA
            and trust_bundle["nodePublicKeyFingerprint"] == node_fingerprint(protocol)
            and len(trust_bundle["viewTrust"]) == 1, "Explicit trust bundle identity mismatch")
        view = trust_bundle["viewTrust"][0]
        require(view["storeUID"] == self.app.get("SekvyrStore", STORE)["metadata"]["uid"]
            and view["bindingID"] == protocol.binding_id
            and all(view[name + "ID"] == protocol.scope[name + "_id"] for name in ("realm", "project", "environment", "view", "log")),
            "Explicit trust bundle view mismatch")
        publisher, witness = key_descriptor(protocol.publisher), key_descriptor(protocol.witness)
        require(view["publisherKeyFingerprint"] == publisher["key_id"] and view["publisherPublicKey"] == publisher["public_key"]
            and view["publisherPolicyEpoch"] == protocol.authority["publisher_policy_epoch"]
            and view["witness"]["publicKey"] == witness["public_key"] and view["witness"]["keyFingerprint"] == witness["key_id"]
            and view["witness"]["epoch"] == protocol.authority["witness_epoch"], "Explicit trust bundle authority mismatch")
        prepared = {"generation": generation, "trustHash": hashlib.sha256(canonical(trust_bundle)).hexdigest(),
            "nodeFingerprint": node_fingerprint(protocol), "fencerKeyID": key_descriptor(fencer_private)["key_id"]}
        if self.plan["phase"] == "prepared":
            require(self.plan["prepared"] == prepared, "Prepared bootstrap inputs changed after partial progress")
            self._preserve()
            return self.app.enrollment()
        names = {"node": "operator-node-r" + str(generation), "trust": "operator-trust-r" + str(generation),
            "state": "operator-state-r" + str(generation), "signer": "fencer-signing-r" + str(generation)}
        specifications = {names["node"]: ({"node.pem": pem(node_private)}, True), names["trust"]: ({"trust.json": canonical(trust_bundle)}, True),
            names["signer"]: ({"key.pem": pem(fencer_private)}, True), names["state"]: ({"installation.json": canonical({
                "installationID": protocol.installation_id, "bootstrapGeneration": generation})}, False)}
        for name, (data, immutable) in specifications.items():
            if ("Secret", name) not in self.app.created:
                self.app.secret(name, data, immutable)
            else:
                existing = self.app.get("Secret", name)
                require(existing.get("type") == "Opaque" and existing.get("immutable", False) == immutable
                    and existing.get("data") == {key: base64.b64encode(raw).decode() for key, raw in data.items()},
                    "Previously created bootstrap bytes changed")
        self.app.protocol = protocol
        self.app.generation, self.app.node_secret_name = generation, names["node"]
        self.app.trust_name, self.app.state_name = names["trust"], names["state"]
        self.app.fencer_signer_secret_name = names["signer"]
        self.app.remember_context()
        self.plan["prepared"], self.plan["phase"] = prepared, "prepared"
        self._save()
        self._preserve()
        return self.app.enrollment()

    def apply(self, next_values, current_state):
        require(self.plan["phase"] in ("prepared", "applying", "applied") and self._no_operator_pods(),
            "Prepared stopped operator is required before reconfiguration")
        enrollment = self.app.enrollment()
        require(current_state["scope"] == self.app.protocol.scope and current_state["genesis_hash"] == self.app.protocol.genesis_hash
            and current_state["enrollments"][self.app.protocol.installation_id] == enrollment,
            "New exact enrollment has not been independently committed")
        require(key_descriptor(self.app.protocol.fencer) in current_state["authority"]["fencer_keys"], "New fencer key is not authorized")
        require(next_values["installation"]["bootstrapGeneration"] == self.app.generation
            and next_values["installation"]["identityKeySecret"]["name"] == self.app.node_secret_name
            and next_values["installation"]["trustBundleSecret"]["name"] == self.app.trust_name
            and next_values["installation"]["stateSecret"]["name"] == self.app.state_name
            and next_values["ha"]["fencer"]["signingKeySecret"]["name"] == self.app.fencer_signer_secret_name
            and next_values["ha"]["fencer"]["tlsSecret"]["name"] == self.app.fencer_tls_secret_name,
            "Rendered next bootstrap references differ from explicit preparation")
        new = self._render(next_values, "next")
        old_non_config = {key for key in self.old if key[0] != "ConfigMap"}
        require({key for key in new if key[0] != "ConfigMap"} == old_non_config, "Reconfiguration changes resource ownership set")
        installations = [json.loads(value["data"]["installation.json"]) for key, value in new.items()
            if key[0] == "ConfigMap" and "installation.json" in value.get("data", {})]
        require(len(installations) == 1, "Ambiguous normalized next installation")
        if self.plan["phase"] == "applied":
            for name in (RELEASE + "-operator", RELEASE + "-fencer"):
                require(self.app.get("Deployment", name)["spec"] == self.plan["expected"]["Deployment/" + name]["spec"],
                    "Applied Deployment changed before recovery retry")
            self._preserve()
            return installations[0]
        self.plan["phase"] = "applying"
        self._save()
        self._deployment(RELEASE + "-fencer", replicas=0)
        for key, value in new.items():
            kind, name = key
            previous = self.old.get(key)
            if kind == "ConfigMap":
                require(previous is None and value.get("immutable") is True, "Next configuration must be NEW and immutable")
                if key in self.app.created:
                    existing = self.app.get(kind, name)
                    require(existing.get("immutable") is True and existing.get("data") == value.get("data"), "New ConfigMap content changed")
                else:
                    self.app.create(value)
            elif kind == "Role":
                require(_role_shape(previous.get("rules", [])) == _role_shape(value.get("rules", [])), "Reconfiguration broadens RBAC capability shape")
                current = self.app.get(kind, name)
                expected = self.plan["expected"][kind + "/" + name]
                if current.get("rules", []) != value.get("rules", []):
                    require(current["metadata"]["uid"] == expected["uid"] and current.get("rules", []) == expected["rules"], "Role prior UID/rules changed")
                    self.app.patch(kind, name, [{"op": "test", "path": "/rules", "value": expected["rules"]},
                        {"op": "replace", "path": "/rules", "value": value.get("rules", [])}])
                self.plan["expected"][kind + "/" + name] = {"uid": current["metadata"]["uid"], "rules": value.get("rules", [])}
                self._save()
            elif kind == "Deployment":
                self._deployment(name, replicas=0, template=value["spec"]["template"])
            elif kind == "ValidatingWebhookConfiguration":
                # Keep historical exact state names guarded until trial cleanup.
                approved_before = self.plan["webhook"]
                saved = self.directory / "next-webhook.json"
                if saved.exists():
                    require(not saved.is_symlink(), "Saved webhook approval symlink refused")
                    proposed = json.loads(saved.read_bytes())
                else:
                    fresh = json.loads(self.cluster.kube("get", kind, name, "-o", "json").stdout)
                    require(fresh["metadata"]["uid"] == approved_before["metadata"]["uid"]
                        and self.cluster.guard_hash(fresh) == self.cluster.guard_hash(approved_before), "Webhook changed before reviewed update")
                    proposed = self._normalized(value, fresh)
                    old_hook, new_hook = approved_before["webhooks"][0], proposed["webhooks"][0]
                    require({k: v for k, v in old_hook.items() if k != "matchConditions"} ==
                        {k: v for k, v in new_hook.items() if k != "matchConditions"}, "Unreviewed webhook service, trust or rules change")
                    before = old_hook["matchConditions"][0]["expression"]
                    after = new_hook["matchConditions"][0]["expression"]
                    new_hook["matchConditions"][0]["expression"] = "(" + before + ") || (" + after + ")"
                    # Approval is structural, not tied to the dry-run's old RV.
                    proposed["metadata"] = {"name": name}
                    write_values_once(saved, canonical(proposed))
                self.cluster.update_cluster_webhook(proposed)
            else:
                require(_structural(previous) == _structural(value), "Unreviewed chart resource mutation")
        self._deployment(RELEASE + "-fencer", replicas=2)
        self.cluster.kube("-n", self.app.namespace, "rollout", "status", "deployment/" + RELEASE + "-fencer", "--timeout=180s")
        self._preserve()
        self.plan["phase"] = "applied"
        self._save()
        return installations[0]

    def resume_operator(self):
        require(self.plan["phase"] in ("applied", "resumed"), "Apply bootstrap and signed recovery before resuming operator")
        state = self.app.get("Secret", self.app.state_name)
        recovered = json.loads(base64.b64decode(state["data"]["state.json"]))
        require(recovered.get("installationID") == self.app.protocol.installation_id
            and recovered.get("bootstrapGeneration") == self.app.generation and recovered.get("recovery", {}).get("phase") == "complete",
            "Signed bootstrap recovery is not complete")
        self._preserve()
        self._deployment(RELEASE + "-operator", replicas=2)
        self.cluster.kube("-n", self.app.namespace, "rollout", "status", "deployment/" + RELEASE + "-operator", "--timeout=180s")
        self.app.remember_context()
        self.plan["phase"] = "resumed"
        self._save()
        return {"operatorResumed": True, "replicas": 2, "processReadinessOnly": True}
