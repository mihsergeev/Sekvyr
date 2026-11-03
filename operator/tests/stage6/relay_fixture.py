"""Pinned test-only admission relay installation, with no network control API."""

from pathlib import Path
import json
import hashlib
import copy

from fixture import canonical
from manifests import LABEL, object_resource
from run import secret


def install(cluster, image, expected_request, node_name=""):
    """Install before switching the OWN webhook service by UID/RV CAS.

    The coordinator must obtain a real upstream allow, hold the old request,
    establish a newer fenced owner, then release the held response. Admission
    timeout is still bounded by the API server; this relay never signs a grant.
    """
    namespace, private = cluster.fixture["namespaces"]["apps"], cluster.task / "private"
    if expected_request["namespace"] != namespace:
        raise ValueError("Relay target is outside this trial")
    cfg = object_resource("ConfigMap", "admission-relay", namespace)
    cfg.update(immutable=True, data={"config.json": canonical(expected_request).decode(),
        "admission_relay.py": Path(__file__).with_name("admission_relay.py").read_text(encoding="utf-8")})
    cluster.create(cfg)
    overrides_file = private / "fixture-overrides.json"
    overrides = json.loads(overrides_file.read_text(encoding="utf-8")) if overrides_file.exists() else {}
    tls_label = overrides.get("relayTLSLabel", "admission-relay")
    if tls_label not in ("admission-relay", "admission-relay-admission"):
        raise ValueError("Unreviewed relay TLS material label")
    cluster.create(secret(namespace, "admission-relay-tls", {
        "tls.crt": (private / (tls_label + ".crt")).read_bytes(),
        "tls.key": (private / (tls_label + ".key")).read_bytes(),
        "ca.crt": (private / "journal-ca.crt").read_bytes()}))
    account = object_resource("ServiceAccount", "admission-relay", namespace)
    account["automountServiceAccountToken"] = False
    cluster.create(account)
    labels = {LABEL: "admission-relay"}
    pod = {"serviceAccountName": "admission-relay", "automountServiceAccountToken": False,
        "enableServiceLinks": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
            "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "relay", "image": image, "imagePullPolicy": "Never",
            "command": ["python3", "-B", "/relay/admission_relay.py"],
            "args": ["--config=/relay/config.json", "--state-dir=/state", "--upstream-ca=/tls/ca.crt",
                "--tls-cert=/tls/tls.crt", "--tls-key=/tls/tls.key"],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}},
            "ports": [{"containerPort": 9443}], "readinessProbe": {"tcpSocket": {"port": 9443}},
            "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                "limits": {"cpu": "500m", "memory": "128Mi"}},
            "volumeMounts": [{"name": "source", "mountPath": "/relay", "readOnly": True},
                {"name": "tls", "mountPath": "/tls", "readOnly": True},
                {"name": "state", "mountPath": "/state"}]}],
        "volumes": [{"name": "source", "configMap": {"name": "admission-relay"}},
            {"name": "tls", "secret": {"secretName": "admission-relay-tls", "defaultMode": 288}},
            {"name": "state", "emptyDir": {"sizeLimit": "1Mi"}}]}
    if node_name:
        pod["nodeName"] = node_name
    cluster.create(object_resource("Deployment", "admission-relay", namespace, {"replicas": 1,
        "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": pod}}, "apps/v1"))
    cluster.create(object_resource("Service", "admission-relay", namespace,
        {"selector": labels, "ports": [{"port": 9443, "targetPort": 9443}]}))


def retry_owned(cluster, expected_request):
    """Explicit new attempt after a failed trial, with a new immutable input.

    Service/TLS/SA/Deployment keep their original UIDs. Only the source
    ConfigMap reference changes; an unknown same-named object is never adopted.
    """
    namespace = cluster.fixture["namespaces"]["apps"]
    pins = [json.loads(p.read_text()) for p in cluster.pins.glob("*.json")]
    matches = [p for p in pins if (p["kind"], p["name"], p["namespace"]) == ("Deployment", "admission-relay", namespace)]
    if len(matches) != 1:
        raise RuntimeError("Explicit relay retry requires its creation UID")
    current = json.loads(cluster.kube("get", "deployment", "admission-relay", "-n", namespace, "-o", "json").stdout)
    if current["metadata"]["uid"] != matches[0]["uid"]:
        raise RuntimeError("Relay Deployment replaced")
    containers = current["spec"]["template"]["spec"]["containers"]
    if len(containers) != 1 or containers[0]["name"] != "relay" or containers[0].get("command") != ["python3", "-B", "/relay/admission_relay.py"]:
        raise RuntimeError("Relay retry process differs from its reviewed fixture")
    data = {"config.json": canonical(expected_request).decode(),
        "admission_relay.py": Path(__file__).with_name("admission_relay.py").read_text(encoding="utf-8")}
    name = "relay-attempt-" + hashlib.sha256(canonical(data)).hexdigest()[:12]
    cfg = object_resource("ConfigMap", name, namespace)
    cfg.update(immutable=True, data=data)
    cluster.create(cfg)
    volumes = copy.deepcopy(current["spec"]["template"]["spec"]["volumes"])
    sources = [v for v in volumes if v["name"] == "source"]
    if len(sources) != 1 or set(sources[0]) != {"name", "configMap"}:
        raise RuntimeError("Relay source mount ambiguous")
    sources[0]["configMap"]["name"] = name
    patch = [{"op": "test", "path": "/metadata/uid", "value": matches[0]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/spec", "value": current["spec"]},
        {"op": "replace", "path": "/spec/template/spec/volumes", "value": volumes}]
    cluster.kube("patch", "deployment", "admission-relay", "-n", namespace, "--type=json", "-p", json.dumps(patch))
