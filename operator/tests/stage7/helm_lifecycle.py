"""Real Helm lifecycle in an exclusively reserved trial namespace.

No CRD installation/removal, resource adoption, forced ownership or rollback
across protocol versions. Native Helm operations are not a multi-object CAS;
the coordinator must keep other administrative writers out of this fixture.
"""

import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess

import yaml

from app_modes import OwnedNamespace, require


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def identity(value):
    meta = value["metadata"]
    return value["apiVersion"], value["kind"], meta.get("namespace", ""), meta["name"]


def normalization_input(manifest, current):
    desired = copy.deepcopy(manifest)
    desired["metadata"].update(uid=current["metadata"]["uid"], resourceVersion=current["metadata"]["resourceVersion"])
    if desired["kind"] == "Lease":
        # Election state changes while install --wait is running. It is not
        # chart configuration, and must never be cleared by a dry-run guard.
        allowed = {"holderIdentity", "leaseDurationSeconds", "acquireTime", "renewTime", "leaseTransitions", "strategy", "preferredHolder"}
        require(desired.get("spec") == {} and set(current.get("spec", {})).issubset(allowed), "Unexpected chart Lease configuration")
        desired["spec"] = copy.deepcopy(current.get("spec", {}))
    elif desired["kind"] == "Service":
        # The API allocates these immutable fields. Preserve only omitted
        # allocations; selector, ports and requested type still compare exact.
        for field in ("clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy", "healthCheckNodePort"):
            if field not in desired["spec"] and field in current.get("spec", {}):
                desired["spec"][field] = copy.deepcopy(current["spec"][field])
    return desired


def private_exact(path, raw):
    require(not path.is_symlink(), "Unsafe Helm lifecycle artifact")
    if path.exists():
        require(path.read_bytes() == raw, "Helm lifecycle input changed on resume")
        return path
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(0o600)
    return path


class HelmLifecycle:
    NAMESPACED = {"ServiceAccount", "Lease", "Role", "RoleBinding", "Deployment", "Service", "ConfigMap"}
    CLUSTER = {"ClusterRole", "ClusterRoleBinding", "ValidatingWebhookConfiguration"}

    def __init__(self, cluster, helm, chart, release, namespace, external_pins=()):
        require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,52}", release) is not None, "Exact bounded Helm release required")
        self.cluster, self.owned = cluster, OwnedNamespace(cluster, namespace)
        self.helm, self.chart = Path(helm), Path(chart)
        require(self.helm.is_file() and not self.helm.is_symlink() and self.chart.is_dir()
            and not self.chart.is_symlink() and (self.chart / "Chart.yaml").is_file(), "Explicit Helm executable and chart required")
        self.release, self.namespace = release, namespace
        self.directory = cluster.task / "private" / ("helm-lifecycle-" + release)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        require(not self.directory.is_symlink(), "Unsafe Helm lifecycle directory")
        self.external = copy.deepcopy(list(external_pins))
        require(len({(pin["kind"], pin["name"]) for pin in self.external}) == len(self.external), "Duplicate external Helm pin")
        for pin in self.external:
            require(set(pin) == {"kind", "name", "uid"} and bool(pin["uid"]), "Explicit external UID pins required")
        self._external_guard()
        self.managed = {}
        self.retained = {}

    def __repr__(self):
        return "<stage7 scoped Helm lifecycle [redacted]>"

    def _run(self, *args, check=True):
        self.owned.guard()
        try:
            result = subprocess.run([str(self.helm), *args, "--kubeconfig", str(self.cluster.config),
                "--namespace", self.namespace], text=True, capture_output=True, timeout=210)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("Scoped Helm operation unavailable") from None
        if check and result.returncode:
            raise RuntimeError("Scoped Helm operation failed")
        return result

    def _get(self, manifest, absent=False):
        _, kind, namespace, name = identity(manifest)
        args = ["get", kind, name, "-o", "json"]
        if namespace:
            args += ["-n", namespace]
        if absent:
            args += ["--ignore-not-found"]
        raw = self.cluster.kube(*args).stdout
        return json.loads(raw) if raw.strip() else None

    def _external_guard(self):
        self.owned.reload_pins()
        for pin in self.external:
            current = self.owned.get(pin["kind"], pin["name"])
            require(current["metadata"]["uid"] == pin["uid"], "External Helm resource UID changed")
            # External resources must not acquire release ownership.
            require("meta.helm.sh/release-name" not in current["metadata"].get("annotations", {}), "External resource carries Helm release ownership")

    def _retained_guard(self):
        for saved in self.retained.values():
            current = self._get(saved["manifest"])
            self._owned(current, saved["uid"])
            require(current.get("immutable") is True and current.get("data") == saved["data"], "Retained configuration revision changed")

    def render(self, values, kube_version=None):
        raw = canonical(values)
        values_path = private_exact(self.directory / ("values-" + hashlib.sha256(raw).hexdigest() + ".json"), raw)
        args = ["template", self.release, str(self.chart), "--values", str(values_path)]
        if kube_version:
            require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", kube_version) is not None, "Exact Kubernetes render version required")
            args += ["--kube-version", kube_version]
        rendered = [value for value in yaml.safe_load_all(self._run(*args).stdout) if value]
        require(rendered and len(rendered) <= 40 and len({identity(value) for value in rendered}) == len(rendered), "Invalid Helm resource set")
        external = {(pin["kind"], pin["name"]) for pin in self.external}
        for value in rendered:
            _, kind, namespace, name = identity(value)
            require((kind in self.NAMESPACED and namespace == self.namespace)
                or (kind in self.CLUSTER and namespace == ""), "Helm rendered a resource outside reviewed scope")
            require((kind, name) not in external and not value["metadata"].get("annotations", {}).get("helm.sh/hook"), "Helm may not own external resources or hooks")
            require(not {"uid", "resourceVersion"}.intersection(value["metadata"]), "Rendered identity cannot be server-populated")
        return rendered, values_path

    def _owned(self, current, uid):
        meta = current["metadata"]
        require(meta["uid"] == uid and not meta.get("deletionTimestamp")
            and meta.get("annotations", {}).get("meta.helm.sh/release-name") == self.release
            and meta.get("annotations", {}).get("meta.helm.sh/release-namespace") == self.namespace
            and meta.get("labels", {}).get("app.kubernetes.io/managed-by") == "Helm", "Helm managed identity or ownership changed")

    def _matches(self, current, manifest):
        desired = normalization_input(manifest, current)
        normalized = json.loads(self.cluster.kube("replace", "--dry-run=server", "-f", "-", "-o", "json", data=json.dumps(desired)).stdout)
        fields = ("apiVersion", "kind", "spec", "rules", "roleRef", "subjects", "webhooks", "data", "binaryData", "type", "immutable", "automountServiceAccountToken")
        require(all(normalized.get(key) == current.get(key) for key in fields), "Helm result differs from reviewed normalized manifest")

    def _preflight(self, rendered, action):
        self._external_guard()
        self._retained_guard()
        if action == "install":
            # Helm 4 lists every release status by default; --all was removed.
            releases = json.loads(self._run("list", "--filter", "^" + self.release + "$", "--output", "json").stdout)
            require(not releases and not self.managed, "Helm install cannot reuse a release")
        else:
            require(self.managed, "Helm upgrade requires this helper's captured installation")
        incoming = {identity(value): value for value in rendered}
        for key, saved in self.managed.items():
            current = self._get(saved["manifest"])
            self._owned(current, saved["uid"])
            self._matches(current, saved["manifest"])
            if key not in incoming:
                require(saved["manifest"]["kind"] == "ConfigMap" and saved["manifest"]["metadata"].get("annotations", {}).get("helm.sh/resource-policy") == "keep",
                    "Upgrade may remove only explicitly retained configuration revisions")
                require(current.get("immutable") is True and current.get("data") == saved["data"], "Retained configuration revision changed")
                self.retained[key] = saved
            elif not key[2]:
                # Do not replace admission/RBAC approval history through Helm.
                require(incoming[key] == saved["manifest"], "Cluster-scoped Helm upgrade needs separate explicit review")
        new = [value for key, value in incoming.items() if key not in self.managed]
        for value in new:
            require(identity(value) not in self.retained, "Helm may not re-adopt a retained revision")
        cluster_manifests = [value for value in new if not identity(value)[2]]
        if cluster_manifests:
            self.cluster.review_cluster_manifests(cluster_manifests)
        receipt = {"format": "sekvyr-stage7-helm-preflight-v1", "action": action,
            "namespace": self.namespace, "namespaceUID": self.owned.namespace_uid, "release": self.release,
            "renderHash": hashlib.sha256(canonical(rendered)).hexdigest(), "external": self.external,
            "absent": [{"apiVersion": value["apiVersion"], "kind": value["kind"], "namespace": value["metadata"].get("namespace", ""),
                "name": value["metadata"]["name"], "manifestHash": hashlib.sha256(canonical(value)).hexdigest()} for value in new]}
        return self.cluster.persist_helm_preflight(receipt), new

    def _capture(self, rendered, new, receipt):
        new_ids = {identity(value) for value in new}
        found = {}
        for manifest in rendered:
            current = self._get(manifest, absent=True)
            if current is None:
                continue
            self._matches(current, manifest)
            key = identity(manifest)
            if key in new_ids:
                self.cluster.capture_helm_created(current, manifest, self.release, receipt)
            else:
                self._owned(current, self.managed[key]["uid"])
            found[key] = {"manifest": copy.deepcopy(manifest), "uid": current["metadata"]["uid"], "data": current.get("data")}
        private_exact(self.directory / ("captured-" + hashlib.sha256(canonical(receipt)).hexdigest() + ".json"), canonical(list(found.values())))
        self.managed = found
        self._external_guard()
        self._retained_guard()
        return len(found) == len(rendered)

    def install(self, values):
        return self._change("install", values)

    def upgrade(self, values):
        return self._change("upgrade", values)

    def _change(self, action, values):
        rendered, path = self.render(values)
        receipt, new = self._preflight(rendered, action)
        args = [action, self.release, str(self.chart), "--values", str(path), "--wait", "--timeout", "180s", "--skip-crds"]
        result = self._run(*args, check=False)
        complete = self._capture(rendered, new, receipt)
        require(result.returncode == 0 and complete, "Helm lifecycle failed; captured partial resources require coordinator review")
        return {"managedResources": len(self.managed), "retainedRevisions": len(self.retained), "helmSucceeded": True}

    def uninstall(self):
        require(self.managed, "Helm uninstall requires captured installation")
        self._external_guard()
        self._retained_guard()
        for saved in self.managed.values():
            current = self._get(saved["manifest"])
            self._owned(current, saved["uid"])
            self._matches(current, saved["manifest"])
        self._run("uninstall", self.release, "--wait", "--timeout", "180s")
        for key, saved in self.managed.items():
            current = self._get(saved["manifest"], absent=True)
            if saved["manifest"]["kind"] == "ConfigMap" and saved["manifest"]["metadata"].get("annotations", {}).get("helm.sh/resource-policy") == "keep":
                require(current is not None and current["metadata"]["uid"] == saved["uid"] and current.get("data") == saved["data"], "Retained configuration missing or replaced")
                self.retained[key] = saved
            else:
                require(current is None, "Helm managed resource remains after uninstall")
        self._external_guard()
        self._retained_guard()
        self.managed = {}
        return {"helmUninstalled": True, "externalUIDsPreserved": True, "retainedRevisions": len(self.retained)}
