"""Run the PostgreSQL-only backend tests against the fresh owned trial database."""

import hashlib
import json
import re

from app_modes import require
from fixture import canonical, write_private
from manifests import LABEL, object_resource
from . import archive_graph, assets
from .capability import Capability


NAME = "stage8-postgres-verify"
DATABASE = "database"
SECRET = "database-access"
MAX_LOG = 2 << 20
DEADLINE = 270
WORKDIR = "/srv"
UID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
DNS = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
SUMMARY = re.compile(r"15 passed(?:, [1-9][0-9]* warnings?)? in [0-9]+(?:\.[0-9]+)?s\Z")


def object_json(output):
    try:
        result = json.loads(output)
    except (ValueError, RecursionError):
        raise RuntimeError("Invalid trial Kubernetes response") from None
    require(type(result) is dict, "Invalid trial Kubernetes response")
    return result


def get(cluster, kind, name, namespace=None):
    args = ["get", kind, name, "-o", "json"]
    if namespace is not None:
        args.extend(("-n", namespace))
    return object_json(cluster.kube(*args).stdout)


def identity(value, kind, name, namespace, uid):
    meta = value.get("metadata", {})
    require(value.get("kind") == kind and meta.get("name") == name and meta.get("namespace", "") == namespace
        and meta.get("uid") == uid and not meta.get("deletionTimestamp"), "Trial Kubernetes object identity differs")


def creation_uid(cluster, kind, name, namespace):
    records = [object_json(path.read_bytes()) for path in cluster.pins.glob("*.json")]
    matches = [r for r in records if (r.get("kind"), r.get("name"), r.get("namespace")) == (kind, name, namespace)]
    require(len(matches) == 1 and UID.fullmatch(matches[0].get("uid", "")), "Exact trial CREATE UID required")
    return matches[0]["uid"]


def database_preflight(cluster, namespace):
    ns_uid = cluster.namespace_pins().get(namespace, "")
    require(UID.fullmatch(ns_uid), "Trial panel namespace pin required")
    identity(get(cluster, "namespace", namespace), "Namespace", namespace, "", ns_uid)
    require(not cluster.kube("get", "deployment", "panel", "-n", namespace,
        "--ignore-not-found", "-o", "name").stdout.strip(), "PostgreSQL verification must precede panel creation")
    db = get(cluster, "deployment", DATABASE, namespace)
    identity(db, "Deployment", DATABASE, namespace, creation_uid(cluster, "Deployment", DATABASE, namespace))
    spec, status = db.get("spec", {}), db.get("status", {})
    containers = spec.get("template", {}).get("spec", {}).get("containers", [])
    db_pod = spec.get("template", {}).get("spec", {})
    require(spec.get("replicas") == status.get("readyReplicas") == status.get("availableReplicas") == 1
        and status.get("observedGeneration") == db["metadata"].get("generation")
        and spec.get("selector", {}).get("matchLabels") == {LABEL: DATABASE}
        and len(containers) == 1 and containers[0].get("name") == DATABASE
        and {"name": "POSTGRES_USER", "value": "trial_admin"} in containers[0].get("env", [])
        and {"name": "POSTGRES_PASSWORD_FILE", "value": "/access/password"} in containers[0].get("env", [])
        and any(volume.get("name") == "access" and volume.get("secret", {}).get("secretName") == SECRET
            for volume in db_pod.get("volumes", [])), "Fresh owned PostgreSQL deployment is not ready")
    service = get(cluster, "service", DATABASE, namespace)
    identity(service, "Service", DATABASE, namespace, creation_uid(cluster, "Service", DATABASE, namespace))
    spec = service.get("spec", {})
    ports = spec.get("ports", [])
    require(spec.get("type") == "ClusterIP" and spec.get("clusterIP") not in (None, "", "None")
        and spec.get("selector") == {LABEL: DATABASE} and len(ports) == 1
        and ports[0].get("protocol") == "TCP" and ports[0].get("port") == ports[0].get("targetPort") == 5432,
        "Trial PostgreSQL service routing differs")
    # Request only identity metadata. The Secret payload never reaches this helper.
    fields = ('jsonpath={.kind}{"|"}{.metadata.namespace}{"|"}{.metadata.name}{"|"}'
        '{.metadata.uid}{"|"}{.metadata.deletionTimestamp}')
    secret = cluster.kube("get", "secret", SECRET, "-n", namespace, "-o", fields).stdout
    secret_uid = creation_uid(cluster, "Secret", SECRET, namespace)
    require(secret == f"Secret|{namespace}|{SECRET}|{secret_uid}|", "Trial database Secret identity differs")


def policies(namespace):
    for direction, subject, peer in (("Ingress", DATABASE, NAME), ("Egress", NAME, DATABASE)):
        field = direction.lower()
        yield object_resource("NetworkPolicy", NAME + "-" + field, namespace, {
            "podSelector": {"matchLabels": {LABEL: subject}}, "policyTypes": [direction],
            field: [{"from" if direction == "Ingress" else "to": [{"podSelector": {"matchLabels": {LABEL: peer}}}],
                "ports": [{"protocol": "TCP", "port": 5432}]}],
        }, "networking.k8s.io/v1")


def job_manifest(namespace, image):
    security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
        "seccompProfile": {"type": "RuntimeDefault"}}
    test = {"name": "pytest", "image": image, "imagePullPolicy": "Never", "workingDir": WORKDIR,
        "command": ["python", "-m", "pytest"],
        "args": ["-q", "--color=no", "-p", "pytest_asyncio.plugin", "-p", "no:cacheprovider", "-o", "addopts=",
            "tests/test_pg_migrations.py", "tests/test_pg_races.py"],
        "env": [{"name": "TRIAL_PG_PASSWORD", "valueFrom": {"secretKeyRef": {"name": SECRET, "key": "password"}}},
            {"name": "SEKVYR_TEST_PG", "value": "postgresql+asyncpg://trial_admin:$(TRIAL_PG_PASSWORD)@database:5432"},
            {"name": "SEKVYR_TEST_PG_SCHEMA", "value": "alembic"}, {"name": "HOME", "value": "/tmp"},
            {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}},
        "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}
    return object_resource("Job", NAME, namespace, {"backoffLimit": 0, "activeDeadlineSeconds": DEADLINE,
        "parallelism": 1, "completions": 1, "template": {"metadata": {"labels": {LABEL: NAME}}, "spec": {
            "restartPolicy": "Never", "dnsPolicy": "ClusterFirst", "automountServiceAccountToken": False, "enableServiceLinks": False,
            "securityContext": security, "containers": [test], "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}}],
        }}}, "batch/v1")


def selected_manifest(owner, image):
    raw = assets.owned_file(owner.root / "receipts" / "public-assets.json", 128 << 10)
    value = object_json(raw)
    require(raw == canonical(value) and value.get("format") == "sekvyr-stage8-public-assets-v1"
        and value.get("rootTask") == str(owner.root), "Stage 8 imported image receipt differs")
    entry = value.get("archives", {}).get("tests", {})
    require(entry.get("rootDigest") == image.split("@", 1)[1]
        and archive_graph.is_digest(entry.get("linuxAMD64ManifestDigest")), "Backend test image receipt differs")
    _, discovery = assets.verify_archive(owner, "tests", image, entry)
    return entry["linuxAMD64ManifestDigest"], discovery


def owned_pod(value, namespace, job_uid, expected_spec):
    meta = value.get("metadata", {})
    name, uid = meta.get("name", ""), meta.get("uid", "")
    require(DNS.fullmatch(name) and UID.fullmatch(uid), "Verification Pod identity missing")
    identity(value, "Pod", name, namespace, uid)
    controllers = [ref for ref in meta.get("ownerReferences", []) if ref.get("controller") is True]
    require(len(controllers) == 1 and all(controllers[0].get(key) == val for key, val in {
        "apiVersion": "batch/v1", "kind": "Job", "name": NAME, "uid": job_uid}.items())
        and meta.get("labels", {}).get(LABEL) == NAME, "Verification Pod is not controlled by exact Job")
    spec = value.get("spec", {})
    containers = spec.get("containers", [])
    require(len(containers) == 1 and not spec.get("initContainers") and not spec.get("ephemeralContainers")
        and not any(spec.get(key) for key in ("hostNetwork", "hostPID", "hostIPC"))
        and all(spec.get(key) == expected_spec[key] for key in (
            "automountServiceAccountToken", "dnsPolicy", "securityContext", "volumes", "restartPolicy"))
        and all(containers[0].get(key) == val for key, val in expected_spec["containers"][0].items()),
        "Verification Pod execution spec differs")
    return name, uid


def runtime_image_identity(image_id, image, amd, *, owner=None, discovery=None):
    reference, root = image.split("@", 1)
    if image_id in {image, reference + "@" + amd}:
        return "reviewedManifest"
    generated = re.fullmatch(r"docker\.io/library/import-[0-9]{4}-[0-9]{2}-[0-9]{2}@(sha256:[0-9a-f]{64})", image_id)
    if owner is not None and generated is not None and generated[1] == discovery:
        # CRI can report the containerd import wrapper rather than its child.
        # Bind the wrapper to the exact verified archive and reread its content
        # only inside the creation-pinned node before accepting the Job result.
        raw = owner.exec("ctr", "-n", "k8s.io", "content", "get", discovery)
        assets.verify_import_wrapper(raw, discovery, {root})
        return "verifiedArchiveDiscoveryWrapper"
    return None


def completed(job, pod, image, amd, *, owner=None, discovery=None):
    status = job.get("status", {})
    conditions = {c.get("type") for c in status.get("conditions", []) if c.get("status") == "True"}
    require("Complete" in conditions and "Failed" not in conditions and status.get("succeeded") == 1
        and status.get("failed", 0) == 0 and status.get("active", 0) == 0, "PostgreSQL verification Job did not complete")
    pod_status = pod.get("status", {})
    statuses = pod_status.get("containerStatuses", [])
    require(pod_status.get("phase") == "Succeeded" and len(statuses) == 1, "PostgreSQL verification Pod did not succeed")
    runtime = statuses[0]
    image_id = runtime.get("imageID", "").removeprefix("docker-pullable://")
    image_identity = runtime_image_identity(image_id, image, amd, owner=owner, discovery=discovery)
    require(runtime.get("name") == "pytest" and image_identity is not None and runtime.get("restartCount") == 0
        and type(runtime.get("state", {}).get("terminated", {}).get("exitCode")) is int
        and runtime["state"]["terminated"]["exitCode"] == 0, "Verification container digest or exit state differs")
    return image_identity


def verify_summary(raw):
    require(0 < len(raw) < MAX_LOG, "Verification log is empty or reached its bound")
    lines = raw.decode("utf-8", errors="replace").strip().splitlines()
    require(bool(lines) and SUMMARY.fullmatch(lines[-1]) is not None,
        "Expected exactly 15 PostgreSQL tests passed with zero skips")


def run(cluster, *, profile):
    image = assets.references(profile)["tests"]
    owner = Capability(cluster, profile=profile)
    namespace = cluster.fixture["namespaces"]["panel"]
    require(DNS.fullmatch(namespace) and namespace in cluster.namespaces, "Owned panel namespace required")
    ready_path = owner.task / "public-images-ready.json"
    require(ready_path.is_file() and not ready_path.is_symlink(), "Public assets must be imported before verification")
    ready = object_json(ready_path.read_bytes())
    require(ready.get("sourceStage") == 8 and ready.get("publicImagesImportedInsideCreationPinnedKind") == 7
        and ready.get("hostDockerImageImports") == 0 and ready.get("newRCBinaryHashesVerified") is True
        and ready.get("production") is False, "Stage 8 asset import did not complete")
    amd, discovery = selected_manifest(owner, image)
    database_preflight(cluster, namespace)
    directory = owner.task / "private" / NAME
    directory.mkdir(mode=0o700)
    owner.guard()
    for policy in policies(namespace):
        cluster.create(policy)
    manifest = job_manifest(namespace, image)
    created = cluster.create(manifest)
    job_uid = creation_uid(cluster, "Job", NAME, namespace)
    identity(created, "Job", NAME, namespace, job_uid)
    cluster.kube("wait", "--for=condition=Complete", "job/" + NAME, "-n", namespace,
        "--timeout=285s", check=False)
    owner.guard()
    job = get(cluster, "job", NAME, namespace)
    identity(job, "Job", NAME, namespace, job_uid)
    result = object_json(cluster.kube("get", "pods", "-n", namespace, "-l",
        "batch.kubernetes.io/controller-uid=" + job_uid, "-o", "json").stdout)
    pods = result.get("items", [])
    require(len(pods) == 1, "Expected one PostgreSQL verification Pod")
    spec = manifest["spec"]["template"]["spec"]
    pod_name, pod_uid = owned_pod(pods[0], namespace, job_uid, spec)
    pod = get(cluster, "pod", pod_name, namespace)
    require(owned_pod(pod, namespace, job_uid, spec) == (pod_name, pod_uid), "Verification Pod was replaced")
    logs = cluster.kube("logs", pod_name, "-n", namespace, "-c", "pytest", "--limit-bytes=" + str(MAX_LOG)).stdout.encode("utf-8")
    require(len(logs) <= MAX_LOG, "Verification log exceeds its bound")
    pod = get(cluster, "pod", pod_name, namespace)
    require(owned_pod(pod, namespace, job_uid, spec) == (pod_name, pod_uid), "Verification Pod was replaced during log read")
    job = get(cluster, "job", NAME, namespace)
    identity(job, "Job", NAME, namespace, job_uid)
    write_private(directory / "pytest.log", logs)
    image_identity = completed(job, pod, image, amd, owner=owner, discovery=discovery)
    verify_summary(logs)
    receipt = {"passed": 15, "skipped": 0, "schema": "alembic", "jobCompleted": True,
        "ownedPodImageVerified": True, "runtimeImageIdentity": image_identity,
        "logSHA256": hashlib.sha256(logs).hexdigest(), "production": False}
    write_private(directory / "passed.json", canonical(receipt))
    return receipt
