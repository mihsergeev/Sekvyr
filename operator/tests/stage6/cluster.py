"""Explicit, kubeconfig-scoped trial mutations and creation-time UID cleanup."""

import hashlib
import copy
import json
from pathlib import Path
import re
import subprocess

from fixture import canonical, safe_task, write_private


class Cluster:
    def __init__(self, task):
        self.task = safe_task(task)
        self.kubectl = self.task / "kubectl"
        self.config = self.task / "kubeconfig"
        for path in (self.kubectl, self.config):
            if not path.is_file() or path.is_symlink():
                raise ValueError("Exact isolated kubectl/kubeconfig required")
        self.fixture = json.loads((self.task / "private" / "fixture.json").read_text(encoding="utf-8"))
        self.namespaces = set(self.fixture["namespaces"].values())
        self.pins = self.task / "private" / "creation-uids"
        self.pins.mkdir(mode=0o700, exist_ok=True)

    def __repr__(self):
        return "<isolated stage6 cluster client [redacted]>"

    def kube(self, *args, data=None, check=True):
        timeout = 90
        for argument in args:
            if re.fullmatch(r"--timeout=[1-9][0-9]{0,2}s", argument):
                seconds = int(argument.removeprefix("--timeout=").removesuffix("s"))
                if seconds > 300:
                    raise ValueError("Trial Kubernetes deadline exceeds bounded limit")
                timeout = max(timeout, seconds + 10)
        try:
            result = subprocess.run([str(self.kubectl), "--kubeconfig", str(self.config), *args],
                input=data, text=True, capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            # TimeoutExpired string includes argv, which may contain a Secret
            # patch or TokenRequest. Keep all subprocess failures constant.
            raise RuntimeError("Isolated Kubernetes operation unavailable") from None
        if check and result.returncode:
            # kubectl stderr can contain credentials, payloads or real endpoints.
            raise RuntimeError("Isolated Kubernetes operation failed")
        return result

    def create(self, resource):
        kind, meta = resource["kind"], resource["metadata"]
        name, namespace = meta["name"], meta.get("namespace", "")
        if kind == "Namespace":
            if namespace or name not in self.namespaces:
                raise ValueError("Namespace outside this trial")
        elif namespace == "" and kind in self.cluster_paths():
            allowed = self.reviewed_cluster_manifests()
            identity = resource["apiVersion"] + "/" + kind + "/" + name
            if allowed.get(identity) != hashlib.sha256(canonical(resource)).hexdigest():
                raise ValueError("Cluster resource differs from explicitly reviewed manifest")
        elif namespace not in self.namespaces:
            raise ValueError("Only trial namespaced resources may be created")
        for path in self.pins.glob("*.json"):
            existing = json.loads(path.read_text(encoding="utf-8"))
            if (existing["kind"], existing["name"], existing["namespace"]) == (kind, name, namespace):
                raise RuntimeError("Repeated resource creation is refused")
        result = json.loads(self.kube("create", "-f", "-", "-o", "json", data=json.dumps(resource)).stdout)
        # Save immediately after creation. No name-only cleanup if this fails.
        uid = result["metadata"]["uid"]
        if not isinstance(uid, str) or not uid:
            raise RuntimeError("Creation response lacks UID")
        record = {"apiVersion": result["apiVersion"], "kind": kind, "name": name, "namespace": namespace, "uid": uid}
        if namespace == "" and kind != "Namespace":
            record["guardHash"] = self.guard_hash(result)
        key = hashlib.sha256(canonical(record)).hexdigest()
        write_private(self.pins / (key + ".json"), canonical(record))
        return result

    @staticmethod
    def cluster_paths():
        return {
            "ValidatingWebhookConfiguration": "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/",
            "ClusterRoleBinding": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/",
            "ClusterRole": "/apis/rbac.authorization.k8s.io/v1/clusterroles/",
            "CustomResourceDefinition": "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/",
        }

    @staticmethod
    def guard_hash(resource):
        # Hash only non-secret structural configuration, never application data.
        guarded = {key: resource.get(key) for key in ("apiVersion", "kind", "spec", "rules", "roleRef", "subjects", "webhooks")}
        return hashlib.sha256(canonical(guarded)).hexdigest()

    def review_cluster_manifests(self, resources):
        approved = {}
        for resource in resources:
            kind, meta = resource["kind"], resource["metadata"]
            if kind not in self.cluster_paths() or meta.get("namespace"):
                raise ValueError("Only explicit trial cluster resources may be registered")
            name = meta["name"]
            if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", name):
                raise ValueError("Invalid cluster resource name")
            identity = resource["apiVersion"] + "/" + kind + "/" + name
            if identity in approved:
                raise ValueError("Duplicate cluster resource manifest")
            approved[identity] = hashlib.sha256(canonical(resource)).hexdigest()
        previous = self.reviewed_cluster_manifests()
        if any(identity in previous and previous[identity] != digest for identity, digest in approved.items()):
            raise ValueError("Previously reviewed cluster manifest changed")
        raw = canonical(approved)
        target = self.task / "private" / ("cluster-allowlist-" + hashlib.sha256(raw).hexdigest() + ".json")
        if target.exists():
            if target.is_symlink() or target.read_bytes() != raw:
                raise ValueError("Cluster manifest approval changed")
        else:
            write_private(target, raw)

    def reviewed_cluster_manifests(self):
        approved = {}
        # Earlier phases may have reviewed CRDs before the chart exists. Keep
        # every approval exclusive/immutable; never replace the old registry.
        for path in sorted((self.task / "private").glob("cluster-allowlist*.json")):
            if path.is_symlink():
                raise ValueError("Cluster approval symlink refused")
            values = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(values, dict):
                raise ValueError("Invalid cluster approval registry")
            for identity, digest in values.items():
                if identity in approved and approved[identity] != digest:
                    raise ValueError("Conflicting cluster manifest approval")
                approved[identity] = digest
        return approved

    def cluster_creation_pins(self):
        records = []
        for path in self.pins.glob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value["namespace"] == "" and value["kind"] != "Namespace":
                records.append(value)
        return records

    def active_cluster_guard(self, pin):
        return self._active_cluster_guard_state(pin)[0]

    def _active_cluster_guard_state(self, pin):
        current, previous_receipt, consumed = pin["guardHash"], "0" * 64, 0
        directory = self.task / "private" / "cluster-update-receipts"
        receipts = {}
        for path in sorted(directory.glob("*.json")):
            raw = path.read_bytes()
            if path.is_symlink() or path.stem != hashlib.sha256(raw).hexdigest():
                raise RuntimeError("Invalid cluster update receipt")
            value = json.loads(raw)
            if not isinstance(value, dict) or set(value) != {"kind", "name", "uid", "before", "after", "approval", "previousReceipt"} or any(
                not isinstance(value[key], str) or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
                for key in ("before", "after", "approval", "previousReceipt")):
                raise RuntimeError("Invalid cluster update receipt shape")
            if value.get("name") != pin["name"]:
                continue
            if value.get("uid") != pin["uid"] or value.get("kind") != pin["kind"]:
                raise RuntimeError("Cluster update receipt identity mismatch")
            approval_file = self.task / "private" / "cluster-update-approvals" / (value["approval"] + ".json")
            if approval_file.is_symlink():
                raise RuntimeError("Cluster approval symlink refused")
            approved_raw = approval_file.read_bytes()
            approval = json.loads(approved_raw)
            if approval_file.is_symlink() or hashlib.sha256(approved_raw).hexdigest() != value["approval"] or any(
                approval.get(key) != value.get(key) for key in ("name", "uid", "kind", "before", "after", "previousReceipt")):
                raise RuntimeError("Cluster update lacks its exact prior approval")
            if value["previousReceipt"] in receipts or value["before"] == value["after"]:
                raise RuntimeError("Cluster update receipt fork")
            value["receiptHash"] = path.stem
            receipts[value["previousReceipt"]] = value
        while previous_receipt in receipts:
            receipt = receipts[previous_receipt]
            if receipt["before"] != current:
                raise RuntimeError("Cluster update guard chain gap")
            current, previous_receipt = receipt["after"], receipt["receiptHash"]
            consumed += 1
            if consumed > len(receipts):
                raise RuntimeError("Cluster update receipt cycle")
        if consumed != len(receipts):
            raise RuntimeError("Cluster update receipt chain gap")
        return current, previous_receipt

    def update_cluster_webhook(self, new_manifest):
        """Explicit reviewed OWN-webhook change, with durable guard receipts.

        Only exact managed names and the two reviewed same-namespace service
        names may change. TLS CA, rules, fail policy and all other fields stay
        fixed. A changed live resource never becomes its own authorization.
        """
        kind, name = new_manifest["kind"], new_manifest["metadata"]["name"]
        if kind != "ValidatingWebhookConfiguration" or new_manifest.get("apiVersion") != "admissionregistration.k8s.io/v1":
            raise ValueError("Only the owned validating webhook can be updated")
        matches = [p for p in self.cluster_creation_pins() if p["kind"] == kind and p["name"] == name]
        if len(matches) != 1:
            raise RuntimeError("Webhook lacks an unambiguous creation pin")
        pin = matches[0]
        current = json.loads(self.kube("get", kind, name, "-o", "json").stdout)
        before, previous_receipt = self._active_cluster_guard_state(pin)
        if current["metadata"]["uid"] != pin["uid"] or self.guard_hash(current) != before:
            raise RuntimeError("Webhook differs from its previously approved structure")
        webhooks = copy.deepcopy(new_manifest.get("webhooks", []))
        if len(webhooks) != len(current.get("webhooks", [])) or len(webhooks) != 1:
            raise ValueError("Exact single webhook required")
        namespace = self.fixture["namespaces"]["apps"]
        for old, new in zip(current["webhooks"], webhooks):
            for default in ("namespaceSelector", "objectSelector"):
                if default not in new and old.get(default) == {}:
                    new[default] = {}
            service = new.get("clientConfig", {}).get("service", {})
            if service.get("namespace") != namespace or service.get("name") not in ("stage6-fencer", "admission-relay"):
                raise ValueError("Webhook service escaped the reviewed installation")
            conditions = new.get("matchConditions", [])
            if len(conditions) != 1 or conditions[0].get("name") != "exact-installation-and-managed-names":
                raise ValueError("Exact immutable request scope condition required")
            expression = conditions[0].get("expression", "")
            pattern = (r'^request\.namespace == ("[^"\\]+") && \(\(request\.resource\.group == \'\' && request\.resource\.resource == \'secrets\' && request\.name in (\[[^\]]+\])\) \|\| '
                       r'\(request\.resource\.group == \'apps\' && request\.resource\.resource == \'deployments\' && request\.name in (\[[^\]]+\])\)\)$')
            def scope_leaves(text, depth=0):
                parsed = re.fullmatch(pattern, text)
                if parsed is not None:
                    return [parsed]
                if depth >= 4:
                    raise ValueError("Webhook scope union nesting exceeds trial limit")
                level, quoted, escaped, split = 0, "", False, []
                for index, char in enumerate(text):
                    if quoted:
                        if escaped:
                            escaped = False
                        elif char == "\\":
                            escaped = True
                        elif char == quoted:
                            quoted = ""
                        continue
                    if char in ("'", '"'):
                        quoted = char
                    elif char == "(":
                        level += 1
                    elif char == ")":
                        level -= 1
                    elif level == 0 and text[index:index + 4] == " || ":
                        split.append(index)
                    if level < 0:
                        raise ValueError("Unbalanced webhook scope")
                if quoted or level != 0 or len(split) != 1:
                    raise ValueError("Unreviewed webhook scope expression")
                left, right = text[:split[0]], text[split[0] + 4:]
                if not all(part.startswith("(") and part.endswith(")") for part in (left, right)):
                    raise ValueError("Exact parenthesized scope branches required")
                return scope_leaves(left[1:-1], depth + 1) + scope_leaves(right[1:-1], depth + 1)
            leaves = scope_leaves(expression)
            if any(json.loads(parsed[1]) != namespace for parsed in leaves):
                raise ValueError("Webhook request namespace scope widened")
            owned = {(p["kind"], p["name"]) for p in (json.loads(x.read_text()) for x in self.pins.glob("*.json"))
                     if p["namespace"] == namespace}
            for parsed in leaves:
                for object_kind, raw_names in (("Secret", parsed[2]), ("Deployment", parsed[3])):
                    names = json.loads(raw_names)
                    if not isinstance(names, list) or not 1 <= len(names) <= 64 or any(not isinstance(n, str) for n in names) or len(set(names)) != len(names) or any(
                        (object_kind, n) not in owned for n in names):
                        raise ValueError("Webhook managed names lack creation pins")
            old_fixed, new_fixed = copy.deepcopy(old), copy.deepcopy(new)
            for value in (old_fixed, new_fixed):
                value.pop("matchConditions", None)
                value["clientConfig"]["service"].pop("name", None)
            if old_fixed != new_fixed:
                raise ValueError("Webhook change affected another admission guard")
        candidate = copy.deepcopy(current)
        candidate["webhooks"] = webhooks
        after = self.guard_hash(candidate)
        if after == before:
            return current
        approval = {"kind": kind, "name": name, "uid": pin["uid"], "before": before, "after": after,
            "previousReceipt": previous_receipt,
            "expectedResourceVersion": current["metadata"]["resourceVersion"], "webhooks": webhooks}
        approvals, receipts = [self.task / "private" / name for name in ("cluster-update-approvals", "cluster-update-receipts")]
        for directory in (approvals, receipts):
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.is_symlink():
                raise RuntimeError("Cluster update registry symlink refused")
        raw = canonical(approval)
        approval_hash = hashlib.sha256(raw).hexdigest()
        write_private(approvals / (approval_hash + ".json"), raw)
        patch = [{"op": "test", "path": "/metadata/uid", "value": pin["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
            {"op": "replace", "path": "/webhooks", "value": webhooks}]
        updated = json.loads(self.kube("patch", kind, name, "--type=json", "-p", json.dumps(patch), "-o", "json").stdout)
        if updated["metadata"]["uid"] != pin["uid"] or self.guard_hash(updated) != after:
            raise RuntimeError("Webhook update response differs from its prior approval")
        receipt = {key: approval[key] for key in ("kind", "name", "uid", "before", "after", "previousReceipt")}
        receipt["approval"] = approval_hash
        raw_receipt = canonical(receipt)
        write_private(receipts / (hashlib.sha256(raw_receipt).hexdigest() + ".json"), raw_receipt)
        return updated

    def cleanup_cluster_resources(self, phase, execute=False):
        if phase not in ("before-namespaces", "after-namespaces"):
            raise ValueError("Explicit cleanup order required")
        order = {"ValidatingWebhookConfiguration": 0, "ClusterRoleBinding": 1, "ClusterRole": 2, "CustomResourceDefinition": 3}
        pins = sorted(self.cluster_creation_pins(), key=lambda item: order[item["kind"]])
        selected = [pin for pin in pins if (pin["kind"] == "CustomResourceDefinition") == (phase == "after-namespaces")]
        if phase == "after-namespaces":
            for name in self.namespaces:
                if self.kube("get", "namespace", name, "--ignore-not-found", "-o", "name").stdout.strip():
                    raise RuntimeError("Remove all exact trial namespaces before deleting CRDs")
        for pin in selected:
            response = self.kube("get", pin["kind"], pin["name"], "--ignore-not-found", "-o", "json").stdout.strip()
            if not response:
                continue
            current = json.loads(response)
            if current["metadata"]["uid"] != pin["uid"] or self.guard_hash(current) != self.active_cluster_guard(pin):
                raise RuntimeError("Cluster resource UID/config changed; cleanup refused")
            if execute:
                if pin["kind"] == "CustomResourceDefinition":
                    records = json.loads(self.kube("get", pin["name"], "-A", "-o", "json").stdout)["items"]
                    if records:
                        raise RuntimeError("Remaining custom resources prevent CRD deletion")
                body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": pin["uid"]}}
                self.kube("delete", "--raw", self.cluster_paths()[pin["kind"]] + pin["name"], "-f", "-", data=json.dumps(body))
        return {"phase": phase, "guardedClusterResources": len(selected), "deleteRequested": execute, "completed": False}

    def namespace_pins(self):
        records = [json.loads(path.read_text(encoding="utf-8")) for path in self.pins.glob("*.json")]
        namespace_records = [record for record in records if record["kind"] == "Namespace"]
        pins = {record["name"]: record["uid"] for record in namespace_records}
        if len(pins) != len(namespace_records):
            raise RuntimeError("Ambiguous namespace creation pins")
        if set(pins) != self.namespaces or any(not value for value in pins.values()):
            raise RuntimeError("All creation-time namespace UID pins are required")
        return pins

    def cleanup_namespaces(self, execute=False, acknowledge_trial_storage_destruction=False):
        for pin in self.cluster_creation_pins():
            if pin["kind"] == "CustomResourceDefinition":
                continue
            if self.kube("get", pin["kind"], pin["name"], "--ignore-not-found", "-o", "name").stdout.strip():
                raise RuntimeError("Remove UID-pinned trial webhook/cluster RBAC before namespaces")
        pins = self.namespace_pins()
        for name, uid in pins.items():
            current = json.loads(self.kube("get", "namespace", name, "-o", "json").stdout)
            if current["metadata"]["uid"] != uid:
                raise RuntimeError("Namespace replaced; cleanup refused")
        if not execute:
            return {"guardedNamespaceCount": len(pins), "deleted": False}
        if not acknowledge_trial_storage_destruction:
            raise ValueError("Deleting trial PVC bypasses the storage retention boundary; explicit acknowledgement required")
        for name, uid in pins.items():
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
                raise ValueError("Invalid exact namespace")
            body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "propagationPolicy": "Background"}
            self.kube("delete", "--raw", "/api/v1/namespaces/" + name, "-f", "-", data=json.dumps(body))
        # Accepted DELETE is not an assertion of completed cleanup. The caller
        # separately waits for NS/PV absence and verifies the baseline remains.
        return {"guardedNamespaceCount": len(pins), "deleteRequestsAccepted": True, "completed": False}
