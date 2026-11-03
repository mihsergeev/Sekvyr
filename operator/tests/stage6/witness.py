"""Two real canonical-witness processes for the explicitly disposable trial."""

import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ed25519

from fixture import canonical, issue_leaf, token, write_private
from manifests import LABEL, object_resource, peer
from protocol import ProtocolAuthority, key_descriptor
from run import secret


def prepare_files(task, namespaces):
    private = task / "private"
    if not (private / "fetch-token").exists():
        write_private(private / "fetch-token", token(48).encode())
    if not (private / "witness-server.crt").exists():
        hosts = [name + "." + namespaces["witness"] + ".svc.cluster.local"
                 for name in ("witness", "witness-a", "witness-b")]
        issue_leaf(task, "journal", "witness-server", "server", hosts + ["localhost"])
    for label, service in (("fencer-server", "stage6-fencer"), ("admission-relay", "admission-relay")):
        if not (private / (label + ".crt")).exists():
            host = service + "." + namespaces["apps"] + ".svc"
            issue_leaf(task, "journal", label, "server", [host, host + ".cluster.local", "localhost"])


def config(protocol, namespaces, replica):
    registrations = [protocol.registration, protocol.fault_logs["replica-cas"]["registration"]]
    logs = [item["log_id"] for item in registrations]
    return {"format": "sekvyr-witness-canonical-config-v1",
        "gateway": {"origin": "https://journal." + namespaces["gateway"] + ".svc.cluster.local:8443",
            "ca_file": "/files/journal-ca.crt", "client_cert_file": "/files/client.crt",
            "client_key_file": "/files/client.key"},
        "registrations": [{"journal": entry, "staging_token_file": "/files/fetch-token",
            "panel_ca_file": "/files/journal-ca.crt"} for entry in registrations],
        "signing_key_files": ["/files/witness.key"],
        "clients": [{"common_name": "isolated-trial-admin", "logs": logs,
            "write_kinds": ["snapshot", "transition"]},
            {"common_name": "isolated-trial-panel", "logs": [logs[0]], "write_kinds": []},
            {"common_name": "isolated-trial-operator", "logs": [logs[0]], "write_kinds": []},
            {"common_name": "isolated-trial-fencer", "logs": [logs[0]],
             "write_kinds": ["fence-grant", "fence-activation"]}]}


def install(cluster, image, node_name=""):
    task, namespaces = cluster.task, cluster.fixture["namespaces"]
    prepare_files(task, namespaces)
    protocol = ProtocolAuthority.load(task)
    private, namespace = task / "private", namespaces["witness"]
    for replica in ("witness-a", "witness-b"):
        values = {"journal-ca.crt": (private / "journal-ca.crt").read_bytes(),
            "tls.crt": (private / "witness-server.crt").read_bytes(),
            "tls.key": (private / "witness-server.key").read_bytes(),
            "client.crt": (private / (replica + ".crt")).read_bytes(),
            "client.key": (private / (replica + ".key")).read_bytes(),
            "fetch-token": (private / "fetch-token").read_bytes(),
            "witness.key": (protocol.root / "witness.key").read_bytes()}
        cluster.create(secret(namespace, replica + "-files", values))
        cfg = object_resource("ConfigMap", replica + "-config", namespace)
        cfg.update(immutable=True, data={"config.json": canonical(config(protocol, namespaces, replica)).decode()})
        cluster.create(cfg)
        account = object_resource("ServiceAccount", replica, namespace)
        account["automountServiceAccountToken"] = False
        cluster.create(account)
        labels = {LABEL: "witness", "app.kubernetes.io/instance": replica}
        pod = {"serviceAccountName": replica, "automountServiceAccountToken": False, "enableServiceLinks": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "witness", "image": image, "imagePullPolicy": "Never",
                "command": ["/sekvyr-witness"], "args": ["canonical-serve", "--config=/config/config.json",
                    "--tls-cert=/files/tls.crt", "--tls-key=/files/tls.key", "--client-ca=/files/journal-ca.crt",
                    "--listen=:8443", "--allow-trial-canonical-ledger"],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]}}, "ports": [{"containerPort": 8443}],
                "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 2},
                "resources": {"requests": {"cpu": "50m", "memory": "32Mi"},
                    "limits": {"cpu": "1000m", "memory": "256Mi"}},
                "volumeMounts": [{"name": "files", "mountPath": "/files", "readOnly": True},
                    {"name": "config", "mountPath": "/config", "readOnly": True}]}],
            "volumes": [{"name": "files", "secret": {"secretName": replica + "-files", "defaultMode": 288}},
                {"name": "config", "configMap": {"name": replica + "-config"}}]}
        if node_name:
            pod["nodeName"] = node_name
        cluster.create(object_resource("Deployment", replica, namespace, {"replicas": 1,
            "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": pod}}, "apps/v1"))
        cluster.create(object_resource("Service", replica, namespace,
            {"selector": labels, "ports": [{"port": 8443, "targetPort": 8443}]}))
    cluster.create(object_resource("Service", "witness", namespace,
        {"selector": {LABEL: "witness"}, "ports": [{"port": 8443, "targetPort": 8443}]}))
    cluster.create(object_resource("NetworkPolicy", "witness-canonical", namespace, {
        "podSelector": {"matchLabels": {LABEL: "witness"}}, "policyTypes": ["Ingress", "Egress"],
        "ingress": [{"from": [peer(namespaces["apps"], role) for role in ("operator", "fencer")] +
            [peer(namespaces["panel"], "panel")], "ports": [{"protocol": "TCP", "port": 8443}]}],
        "egress": [{"to": [peer(namespaces["panel"], "panel")], "ports": [{"protocol": "TCP", "port": 8443}]}]},
        "networking.k8s.io/v1"))


def concurrent_cas(task, clients):
    """Race independently processed signed transitions, preserving the app log."""
    protocol = ProtocolAuthority.load(task)
    diagnostic = protocol.fault_logs["replica-cas"]
    log = diagnostic["registration"]["log_id"]
    path = "/v2/logs/" + log
    current = json.loads(clients[0].request("GET", path + "/authority")[1])
    if current["cursor"]["journal_sequence"] != "0":
        raise RuntimeError("CAS proof requires its new dedicated genesis-only log")
    signed = []
    for _ in clients:
        authority = copy.deepcopy(current["authority"])
        authority["revision"] = str(int(authority["revision"]) + 1)
        authority["fencer_epoch"] = str(int(authority["fencer_epoch"]) + 1)
        authority["fencer_keys"] = [key_descriptor(ed25519.Ed25519PrivateKey.generate())]
        signer = copy.copy(protocol)
        signer.scope, signer.genesis_hash = current["scope"], current["genesis_hash"]
        signed.append(signer.transition("rotate-fencer", current, authority=authority))
    def send(pair):
        client, transition = pair
        return client.request("POST", path + "/transitions", canonical(transition),
            {"Content-Type": "application/json"}, expected=(200, 409))[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(send, zip(clients, signed)))
    if outcomes != [200, 409]:
        raise RuntimeError("Two witnesses did not produce exactly one CAS winner")
    states = [json.loads(client.request("GET", path + "/authority")[1]) for client in clients]
    if states[0] != states[1] or states[0]["cursor"]["journal_sequence"] != "1":
        raise RuntimeError("Witness replicas disagree after CAS")
    return {"twoRealWitnessProcesses": True, "conditionalCommitWinners": 1,
        "canonicalJournalAdvancedExactlyOnce": True, "replicaReplayAgreement": True, "production": False}


def repair_admission_tls(app):
    """One explicit fixture repair; never overwrite old TLS or trust pins.

    The Kubernetes webhook client verifies service.namespace.svc, while the
    operator uses the fully qualified cluster.local service name. Both SANs
    must be present under the already pinned CA.
    """
    task, namespace, private = app.task, app.namespace, app.task / "private"
    if (private / "fixture-overrides.json").exists():
        raise RuntimeError("Fixture TLS repair may not reset an earlier repair")
    for label, service in (("fencer-server-admission", "stage6-fencer"),
                           ("admission-relay-admission", "admission-relay")):
        host = service + "." + namespace + ".svc"
        issue_leaf(task, "journal", label, "server", [host, host + ".cluster.local", "localhost"])
    new_name = "fencer-tls-admission"
    tls = app.secret(new_name, {"tls.crt": (private / "fencer-server-admission.crt").read_bytes(),
        "tls.key": (private / "fencer-server-admission.key").read_bytes()})
    deployment = app.get("Deployment", "stage6-fencer")
    volumes = copy.deepcopy(deployment["spec"]["template"]["spec"]["volumes"])
    old_config_name = next(v["configMap"]["name"] for v in volumes if v["name"] == "configuration")
    old_config = app.get("ConfigMap", old_config_name)
    data = copy.deepcopy(old_config["data"])
    config_body = json.loads(data["config.json"])
    matching = [p for p in config_body["material_pins"] if p["name"] == "fencer-tls" and p["key"] == "tls.crt"]
    if len(matching) != 1:
        raise RuntimeError("Original TLS material pin ambiguous")
    matching[0].update(name=new_name, uid=tls["metadata"]["uid"])
    data["config.json"] = canonical(config_body).decode()
    new_config_name = "stage6-fencer-config-" + hashlib.sha256(
        canonical(config_body) + canonical(json.loads(data["client.json"]))).hexdigest()[:12]
    app.config_map(new_config_name, data)
    role = app.get("Role", "stage6-fencer")
    rules = copy.deepcopy(role["rules"])
    changes = 0
    for rule in rules:
        names = rule.get("resourceNames", [])
        if "fencer-tls" in names:
            if rule.get("resources") != ["secrets"] or rule.get("verbs") != ["get"]:
                raise RuntimeError("Unexpected TLS material RBAC rule")
            rule["resourceNames"] = [new_name if n == "fencer-tls" else n for n in names]
            changes += 1
    if changes != 1:
        raise RuntimeError("Exact TLS read permission ambiguous")
    app.patch("Role", "stage6-fencer", [{"op": "replace", "path": "/rules", "value": rules}])
    for volume in volumes:
        if volume["name"] in ("configuration", "journal-config"):
            volume["configMap"]["name"] = new_config_name
        if volume["name"] == "tls":
            volume["secret"]["secretName"] = new_name
    app.patch("Deployment", "stage6-fencer", [{"op": "replace", "path": "/spec/template/spec/volumes", "value": volumes}])
    app.cluster.kube("-n", namespace, "rollout", "status", "deployment/stage6-fencer", "--timeout=180s")
    overrides = {"fencerTLS": {"name": new_name, "uid": tls["metadata"]["uid"], "label": "fencer-server-admission"},
        "relayTLSLabel": "admission-relay-admission"}
    write_private(private / "fixture-overrides.json", canonical(overrides))
    app.fencer_tls_secret_name = new_name
    app.materials["fencer_tls_cert"] = (private / "fencer-server-admission.crt").read_bytes()
    app.materials["fencer_tls_key"] = (private / "fencer-server-admission.key").read_bytes()
    if hasattr(app, "remember_context"):
        app.remember_context()
    return {"admissionBothServiceSANs": True, "samePinnedCA": True, "newImmutableTLSUID": True,
        "exactMaterialRBACReplaced": True, "noAuthorityOrEnrollmentChanged": True, "production": False}


def normalize_repaired_config_name(app):
    """Preserve exact content while matching the chart's deterministic name."""
    deployment = app.get("Deployment", "stage6-fencer")
    volumes = copy.deepcopy(deployment["spec"]["template"]["spec"]["volumes"])
    name = next(v["configMap"]["name"] for v in volumes if v["name"] == "configuration")
    config_map = app.get("ConfigMap", name)
    data = copy.deepcopy(config_map["data"])
    expected = "stage6-fencer-config-" + hashlib.sha256(
        canonical(json.loads(data["config.json"])) + canonical(json.loads(data["client.json"]))).hexdigest()[:12]
    if name != expected:
        app.config_map(expected, data)
        for volume in volumes:
            if volume["name"] in ("configuration", "journal-config"):
                volume["configMap"]["name"] = expected
        app.patch("Deployment", "stage6-fencer", [{"op": "replace", "path": "/spec/template/spec/volumes", "value": volumes}])
        app.cluster.kube("-n", app.namespace, "rollout", "status", "deployment/stage6-fencer", "--timeout=180s")
    return {"exactChartConfigName": True, "materialAndAuthorityUnchanged": True}
