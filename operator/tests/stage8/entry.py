"""Prepare and review the exact Stage 8 trial inputs before calling the actor."""

import io
import json
import re
import subprocess
import tarfile

import yaml

from coordinator import BudgetCluster
from fixture import canonical, write_private
from helm_lifecycle import HelmLifecycle, identity
import network_paths

from .assets import owned_file
from .cli_actor import run as run_actor
from .cli_coordinator import owned_capability
from .provision_adapter import digest, require, safe_public, strict

MAX_ARCHIVE = 1 << 20
CHART = "sekvyr-operator"
ENTRY = "stage8-entry"


def _checked(path, expected, maximum):
    raw = owned_file(path, maximum)
    require(digest(raw) == expected, "Stage8EntryArtifactSHA256Mismatch")
    return raw


def _chart_files(raw):
    files, seen = {}, set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            name = member.name
            require(len(seen) < 80 and name not in seen
                and re.fullmatch(r"sekvyr-operator(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*){0,3}", name),
                "Stage8EntryInvalidChartPath")
            seen.add(name)
            if member.isdir():
                continue
            require(member.isfile() and name.startswith(CHART + "/") and 0 < member.size <= 512 << 10,
                "Stage8EntryInvalidChartMember")
            total += member.size
            require(total <= 2 << 20, "Stage8EntryChartTooLarge")
            files[name] = archive.extractfile(member).read()
            require(len(files[name]) == member.size, "Stage8EntryTruncatedChart")
    metadata = yaml.safe_load(files[CHART + "/Chart.yaml"])
    require(metadata["name"] == CHART and metadata["version"] == metadata["appVersion"] == "0.1.0-rc.1"
        and not metadata.get("dependencies"), "Stage8EntryChartVersionMismatch")
    return files


def _object(cluster, *args):
    return strict(cluster.kube("get", *args, "-o", "json").stdout.encode(), 1 << 20)


def _endpoints(owner, cluster):
    owner.guard()
    node_name = owner.preflight["clusterName"] + "-control-plane"
    nodes = _object(cluster, "nodes")["items"]
    require(len(nodes) == 1, "Stage8EntryExpectedSingleKindNode")
    node = nodes[0]
    require(node["metadata"]["name"] == node_name and not node["metadata"].get("deletionTimestamp")
        and any(c.get("type") == "Ready" and c.get("status") == "True"
            for c in node["status"]["conditions"]), "Stage8EntryKindNodeNotReady")
    node_ips = {item["address"] for item in node["status"]["addresses"] if item["type"] == "InternalIP"}
    pod = _object(cluster, "pod", "kube-apiserver-" + node_name, "-n", "kube-system")
    pod_ip = pod["status"]["podIP"]
    require(node_ips == {pod_ip} and pod["status"]["hostIP"] == pod_ip and pod["spec"]["hostNetwork"] is True
        and pod["spec"]["nodeName"] == node_name and not pod["metadata"].get("deletionTimestamp")
        and pod["metadata"]["annotations"].get("kubernetes.io/config.source") == "file"
        and any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod["status"]["conditions"]),
        "Stage8EntryKindAPIServerIdentityMismatch")
    svc = _object(cluster, "service", "kubernetes", "-n", "default")
    spec = svc["spec"]
    ports = [(p["protocol"], p["port"], p["targetPort"]) for p in spec["ports"]]
    require(spec["type"] == "ClusterIP" and spec["clusterIPs"] == [spec["clusterIP"]]
        and ports == [("TCP", 443, 6443)] and not svc["metadata"].get("deletionTimestamp"),
        "Stage8EntryAPIServerServiceMismatch")
    slices = _object(cluster, "endpointslices", "-n", "default",
        "-l", "kubernetes.io/service-name=kubernetes")["items"]
    require(len(slices) == 1 and [(p["protocol"], p["port"]) for p in slices[0]["ports"]] == [("TCP", 6443)]
        and not slices[0]["metadata"].get("deletionTimestamp"), "Stage8EntryAPIServerEndpointPortMismatch")
    endpoints = slices[0]["endpoints"]
    require(len(endpoints) == 1 and endpoints[0]["addresses"] == [pod_ip]
        and endpoints[0]["conditions"].get("ready") is True
        and not endpoints[0]["conditions"].get("terminating"), "Stage8EntryAPIServerEndpointIPMismatch")
    owner.guard()
    return {
        "apiEndpoints": [list(pair) for pair in network_paths._endpoints([(spec["clusterIP"], 443), (pod_ip, 6443)], {443, 6443})],
        "admissionSources": [list(pair) for pair in network_paths._endpoints([(pod_ip, 9443)], {9443})],
    }


def _helm(owner):
    helm = owner.task / "tools" / "helm"
    _checked(helm, owner.preflight["toolSHA256"]["helm"], 100 << 20)
    return helm


def _render(helm, archive, base, ha, namespace, version, repository, image_digest):
    try:
        result = subprocess.run([str(helm), "template", "stage6", str(archive), "--namespace", namespace,
            "--kube-version", version.removeprefix("v"), "-f", str(base), "-f", str(ha),
            "--set-string", "image.repository=" + repository, "--set-string", "image.digest=" + image_digest],
            capture_output=True, timeout=45, check=True)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("Stage8EntryFullHelmRenderFailed") from None
    require(0 < len(result.stdout) <= 512 << 10, "Stage8EntryFullRenderBounds")
    manifests = [item for item in yaml.safe_load_all(result.stdout) if item is not None]
    require(0 < len(manifests) <= 40 and len({identity(item) for item in manifests}) == len(manifests),
        "Stage8EntryInvalidRenderedIdentities")
    for item in manifests:
        _, kind, ns, _ = identity(item)
        require((kind in HelmLifecycle.NAMESPACED and ns == namespace)
            or (kind in HelmLifecycle.CLUSTER and ns == ""), "Stage8EntryUnexpectedRenderedResource")
    network_paths._render_selectors(manifests, namespace, "stage6", True)
    return manifests


@safe_public
def prepare_inputs(task, *, profile, chart_archive, chart_sha256, public_base_values,
        base_values_sha256, public_ha_values, ha_values_sha256, resource_schema, resource_schema_sha256):
    """Save full manifests for independent review. The only live calls are GETs."""
    owner = owned_capability(task, profile)
    task = owner.task
    cluster = BudgetCluster(task)
    ns, _ = network_paths._namespaces(cluster)
    archive = _checked(chart_archive, chart_sha256, MAX_ARCHIVE)
    files = _chart_files(archive)
    schema = _checked(resource_schema, resource_schema_sha256, 512 << 10)
    require(isinstance(json.loads(schema), dict), "Stage8EntryInvalidResourceSchema")
    base = yaml.safe_load(_checked(public_base_values, base_values_sha256, 32 << 10))
    require(base["installation"]["namespace"] == "apps", "Stage8EntryUnexpectedDummyNamespace")
    base["installation"]["namespace"] = ns["apps"]
    ha = yaml.safe_load(_checked(public_ha_values, ha_values_sha256, 32 << 10))
    require(ha["ha"]["enabled"] is True and ha["ha"]["trial"] is True, "Stage8EntryPublicHATrialRequired")
    for item in ha["ha"]["managedObjects"]:
        require(item["namespace"] == "apps", "Stage8EntryUnexpectedDummyNamespace")
        item["namespace"] = ns["apps"]
    helm = _helm(owner)
    endpoints = _endpoints(owner, cluster)
    root = task / "private" / ENTRY
    root.mkdir(mode=0o700)
    archive_path = root / "chart.tgz"
    write_private(archive_path, archive)
    for name, content in sorted(files.items()):
        path = root / "charts" / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private(path, content)
    (root / "design").mkdir(mode=0o700)
    write_private(root / "design" / "resource.schema.json", schema)
    base_path, ha_path = root / "public-base.json", root / "public-ha.json"
    write_private(base_path, canonical(base))
    write_private(ha_path, canonical(ha))
    repository, image_digest = owner.artifacts["operator_image"].split("@")
    manifests = _render(helm, archive_path, base_path, ha_path, ns["apps"],
        owner.profile.version, repository, image_digest)
    raw = canonical(manifests)
    write_private(root / "ha-render.json", raw)
    write_private(root / "endpoints.json", canonical(endpoints))
    return {"sourceStage": 8, "production": False, "chartSHA256": chart_sha256,
        "resourceSchemaSHA256": resource_schema_sha256,
        "haRenderSHA256": digest(raw), "renderedResources": len(manifests)}


@safe_public
def run(task, *, profile, chart_sha256, resource_schema_sha256, reviewed_ha_sha256, acceptance="full"):
    """Require independent archive and complete render digests before mutation."""
    owner = owned_capability(task, profile)
    task = owner.task
    root = task / "private" / ENTRY
    archive = _checked(root / "chart.tgz", chart_sha256, MAX_ARCHIVE)
    files = _chart_files(archive)
    charts = root / "charts"
    chart = charts / CHART
    require(chart.is_dir() and not chart.is_symlink(), "Stage8EntryChartTreeChanged")
    tree = list(chart.rglob("*"))
    require(not any(path.is_symlink() for path in tree)
        and {path.relative_to(charts).as_posix() for path in tree if not path.is_dir()} == set(files),
        "Stage8EntryChartTreeChanged")
    for name, content in files.items():
        require(owned_file(charts / name, 512 << 10) == content, "Stage8EntryChartBytesChanged")
    _checked(chart.parents[1] / "design" / "resource.schema.json", resource_schema_sha256, 512 << 10)
    raw = _checked(root / "ha-render.json", reviewed_ha_sha256, 512 << 10)
    manifests = strict(raw, 512 << 10)
    require(raw == canonical(manifests), "Stage8EntryRenderNotCanonical")
    endpoints = _endpoints(owner, BudgetCluster(task))
    require(owned_file(root / "endpoints.json", 8192) == canonical(endpoints),
        "Stage8EntryEndpointPlanChanged")
    return run_actor(task, profile=profile, helm=_helm(owner), chart=chart, ha_rendered=manifests,
        reviewed_ha_sha256=reviewed_ha_sha256, api_endpoints=endpoints["apiEndpoints"],
        admission_sources=endpoints["admissionSources"], acceptance=acceptance)
