"""Public trial manifests. Secret contents are supplied separately, never rendered."""

import re

SEAWEED_VERSION = "4.51"
SEAWEED_IMAGE = "ghcr.io/chrislusf/seaweedfs@sha256:f7a49e3f3972ebed5be2ed4befa4a0c68eb7bdddba6e692d42729ceb545134b8"
SEAWEED_AMD64 = "sha256:3a522c379599e163433a636e75022630848b63a74f08ea37bf06f8d776e9a707"
SOURCE_COMMIT = "153ab668c99731a6d29492bf6c61d0b4fa701101"
LABEL = "secrets.sekvyr.ru/trial-role"


def object_resource(kind, name, namespace=None, spec=None, api="v1"):
    result = {"apiVersion": api, "kind": kind, "metadata": {"name": name}}
    if namespace:
        result["metadata"]["namespace"] = namespace
    if spec is not None:
        result["spec"] = spec
    return result


def peer(namespace, role):
    # Both selectors in ONE peer are an AND, not a namespace-wide OR.
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
            "podSelector": {"matchLabels": {LABEL: role}}}


def network_policies(namespaces):
    output = []
    for role, namespace in namespaces.items():
        output.append(object_resource("NetworkPolicy", "default-deny", namespace,
            {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}, "networking.k8s.io/v1"))
        output.append(object_resource("NetworkPolicy", "dns-only", namespace, {
            "podSelector": {}, "policyTypes": ["Egress"], "egress": [{"to": [{"namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [
                    {"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}]}, "networking.k8s.io/v1"))
    storage, gateway = namespaces["storage"], namespaces["gateway"]
    output.append(object_resource("NetworkPolicy", "storage-internal", storage, {
        "podSelector": {"matchLabels": {LABEL: "storage"}}, "policyTypes": ["Ingress", "Egress"],
        "ingress": [{"from": [peer(storage, "storage"), peer(storage, "storage-admin")]}],
        "egress": [{"to": [peer(storage, "storage")]}]}, "networking.k8s.io/v1"))
    # Only JournalGateway pods may contact the upstream S3 listener. Witness,
    # fencer, panel and operator namespaces have neither key nor network access.
    output.append(object_resource("NetworkPolicy", "upstream-s3", storage, {
        "podSelector": {"matchLabels": {LABEL: "storage"}}, "policyTypes": ["Ingress"],
        "ingress": [{"from": [peer(gateway, "journal-gateway")], "ports": [{"protocol": "TCP", "port": 8333}]}]}, "networking.k8s.io/v1"))
    output.append(object_resource("NetworkPolicy", "gateway-upstream", gateway, {
        "podSelector": {"matchLabels": {LABEL: "journal-gateway"}}, "policyTypes": ["Egress"],
        "egress": [{"to": [peer(storage, "storage")], "ports": [{"protocol": "TCP", "port": 8333}]}]}, "networking.k8s.io/v1"))
    callers = [peer(namespaces[role], role) for role in ("witness", "fencer")]
    callers.append(peer(gateway, "journal-admin"))
    output.append(object_resource("NetworkPolicy", "journal-mtls", gateway, {
        "podSelector": {"matchLabels": {LABEL: "journal-gateway"}}, "policyTypes": ["Ingress"],
        "ingress": [{"from": callers, "ports": [{"protocol": "TCP", "port": 8443}]}]}, "networking.k8s.io/v1"))
    for role in ("witness", "fencer"):
        output.append(object_resource("NetworkPolicy", "journal-client", namespaces[role], {
            "podSelector": {"matchLabels": {LABEL: role}}, "policyTypes": ["Egress"],
            "egress": [{"to": [peer(gateway, "journal-gateway")], "ports": [{"protocol": "TCP", "port": 8443}]}]}, "networking.k8s.io/v1"))
    return output


def product_network_policies(namespaces, api_addresses, admission_addresses):
    """Additional exact trial paths; addresses come from private live baseline.

    Default deny stays installed. No upstream S3 route is granted to a product
    identity, even when fencer and operator share the installation namespace.
    """
    import ipaddress
    def blocks(addresses):
        result = []
        for address in addresses:
            parsed = ipaddress.ip_address(address)
            result.append({"ipBlock": {"cidr": str(parsed) + ("/32" if parsed.version == 4 else "/128")}})
        if not result:
            raise ValueError("Exact trial API/admission addresses required")
        return result
    api_peers, admission_peers = blocks(api_addresses), blocks(admission_addresses)
    apps, gateway, witness, panel = [namespaces[k] for k in ("apps", "gateway", "witness", "panel")]
    output = []
    def policy(namespace, name, role, ingress=None, egress=None):
        spec = {"podSelector": {"matchLabels": {LABEL: role}}, "policyTypes": []}
        if ingress is not None:
            spec.update(ingress=ingress)
            spec["policyTypes"].append("Ingress")
        if egress is not None:
            spec.update(egress=egress)
            spec["policyTypes"].append("Egress")
        output.append(object_resource("NetworkPolicy", name, namespace, spec, "networking.k8s.io/v1"))
    def path(namespace, role, port):
        return {"to": [peer(namespace, role)], "ports": [{"protocol": "TCP", "port": port}]}
    api_path = {"to": api_peers, "ports": [{"protocol": "TCP", "port": p} for p in (443, 6443)]}
    policy(gateway, "installation-journal-clients", "journal-gateway", ingress=[{
        "from": [peer(apps, role) for role in ("operator", "fencer")],
        "ports": [{"protocol": "TCP", "port": 8443}]}])
    policy(apps, "operator-exact-paths", "operator", egress=[api_path,
        path(gateway, "journal-gateway", 8443), path(panel, "panel", 8443),
        path(witness, "witness", 8443), path(apps, "fencer", 9443)])
    policy(apps, "fencer-exact-paths", "fencer", ingress=[{
        "from": admission_peers + [peer(apps, "operator"), peer(apps, "admission-relay")],
        "ports": [{"protocol": "TCP", "port": 9443}]}],
        egress=[api_path, path(gateway, "journal-gateway", 8443)])
    policy(apps, "relay-exact-paths", "admission-relay", ingress=[{
        "from": admission_peers, "ports": [{"protocol": "TCP", "port": 9443}]}],
        egress=[path(apps, "fencer", 9443)])
    policy(panel, "panel-product-paths", "panel", ingress=[{
        "from": [peer(apps, "operator"), peer(witness, "witness")],
        "ports": [{"protocol": "TCP", "port": 8443}]}], egress=[path(witness, "witness", 8443)])
    return output


def cilium_trial_policies(namespaces):
    """Explicit Cilium-only additions, confined to the new installation NS.

    Cilium's default CIDR semantics exclude managed nodes. Do not change the
    cluster-wide CIDR match mode, remove default deny or permit world/cluster.
    """
    def selector(roles):
        return {"matchExpressions": [{"key": "k8s:" + LABEL, "operator": "In", "values": roles}]}
    return [object_resource("CiliumNetworkPolicy", "trial-kube-api", namespaces["apps"], {
        "endpointSelector": selector(["operator", "fencer"]), "egress": [{"toEntities": ["kube-apiserver"],
            "toPorts": [{"ports": [{"port": str(port), "protocol": "TCP"} for port in (443, 6443)]}]}]}, "cilium.io/v2"),
        object_resource("CiliumNetworkPolicy", "trial-admission", namespaces["apps"], {
            "endpointSelector": selector(["fencer", "admission-relay"]), "ingress": [{
                "fromEntities": ["kube-apiserver", "host"],
                "toPorts": [{"ports": [{"port": "9443", "protocol": "TCP"}]}]}]}, "cilium.io/v2")]


def storage_manifests(namespaces, storage_class, node_name=""):
    namespace = namespaces["storage"]
    pod_security = {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"}}
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    pvc = object_resource("PersistentVolumeClaim", "trial-storage", namespace, {
        "accessModes": ["ReadWriteOnce"], "storageClassName": storage_class, "resources": {"requests": {"storage": "3Gi"}}})
    filer_config = object_resource("ConfigMap", "filer-config", namespace)
    filer_config.update(immutable=True, data={"filer.toml": '[leveldb2]\nenabled = true\ndir = "/data/filer"\n'})
    account = object_resource("ServiceAccount", "trial-storage", namespace)
    account["automountServiceAccountToken"] = False
    ports = [9333, 19333, 8080, 18080, 8888, 18888, 8333]
    backend_name = "storage." + namespace + ".svc.cluster.local"
    containers = [{"name": "storage", "image": SEAWEED_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["/usr/bin/weed"], "args": ["-logtostderr=true", "server", "-filer=true", "-s3=false", "-ip=" + backend_name,
            "-ip.bind=0.0.0.0", "-dir=/data", "-master.dir=/data/master", "-master.volumeSizeLimitMB=256",
            "-master.telemetry=false", "-volume.max=8", "-filer.disableHttp=true", "-filer.port=8888"],
        "workingDir": "/config", "securityContext": security,
        "ports": [{"containerPort": port} for port in ports if port != 8333],
        "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "tmp", "mountPath": "/tmp"},
            {"name": "config", "mountPath": "/config", "readOnly": True}],
        "readinessProbe": {"tcpSocket": {"port": 18888}, "periodSeconds": 2}}]
    # Two independent gateways exercise same-key CAS outside a gateway-local lock.
    for index in (1, 2):
        containers.append({"name": "s3-" + str(index), "image": SEAWEED_IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["/usr/bin/weed"], "args": ["-logtostderr=true", "s3", "-filer=" + backend_name + ":8888", "-port=" + str(8332 + index),
                "-cert.file=/tls/storage.crt", "-key.file=/tls/storage.key", "-config=/identity/s3-identities.json",
                "-autoCreateBucket=false", "-iam=false", "-port.iceberg=0", "-port.lance=0"],
            "securityContext": security, "ports": [{"containerPort": 8332 + index}],
            "volumeMounts": [{"name": "tls", "mountPath": "/tls", "readOnly": True},
                {"name": "identity", "mountPath": "/identity", "readOnly": True},
                {"name": "tmp-" + str(index), "mountPath": "/tmp"}],
            "readinessProbe": {"tcpSocket": {"port": 8332 + index}, "periodSeconds": 2}})
    pod_spec = {"serviceAccountName": "trial-storage", "automountServiceAccountToken": False, "enableServiceLinks": False,
        "securityContext": pod_security, "containers": containers,
        "initContainers": [{"name": "prepare-storage-directories", "image": SEAWEED_IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["/bin/sh", "-c", "mkdir -p /data/master /data/filer"], "securityContext": security,
            "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "trial-storage"}},
            {"name": "config", "configMap": {"name": "filer-config"}},
            {"name": "tls", "secret": {"secretName": "storage-tls", "defaultMode": 0o440}},
            {"name": "identity", "secret": {"secretName": "storage-identities", "defaultMode": 0o440}},
            *[{"name": name, "emptyDir": {}} for name in ("tmp", "tmp-1", "tmp-2")]]}
    if node_name:
        pod_spec["nodeSelector"] = {"kubernetes.io/hostname": node_name}
    deployment = object_resource("Deployment", "storage", namespace, {"replicas": 1,
        "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {LABEL: "storage"}},
        "template": {"metadata": {"labels": {LABEL: "storage"}}, "spec": pod_spec}}, "apps/v1")
    service = object_resource("Service", "storage", namespace, {"selector": {LABEL: "storage"}, "publishNotReadyAddresses": True,
        "ports": [{"name": "p" + str(port), "port": port, "targetPort": port} for port in ports + [8334]]})
    s3 = object_resource("Service", "s3", namespace, {"selector": {LABEL: "storage"},
        "ports": [{"name": "primary", "port": 8333, "targetPort": 8333}, {"name": "secondary", "port": 8334, "targetPort": 8334}]})
    return [account, pvc, filer_config, service, s3, deployment]


def fsync_command(bucket):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket):
        raise ValueError("Invalid dedicated bucket")
    return "fs.configure -locationPrefix=/buckets/" + bucket + "/ -fsync=true -volumeGrowthCount=1 -apply\n"


def gateway_manifests(namespaces, image, node_name="", config_name="journal-gateway"):
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", image):
        raise ValueError("Exact built gateway image digest required")
    namespace = namespaces["gateway"]
    account = object_resource("ServiceAccount", "journal-gateway", namespace)
    account["automountServiceAccountToken"] = False
    container = {"name": "gateway", "image": image, "imagePullPolicy": "IfNotPresent",
        "command": ["/sekvyr-journal-gateway"],
        "args": ["--config=/config/config.json", "--tls-cert=/trust/journal.crt", "--tls-key=/trust/journal.key",
            "--client-ca=/trust/journal-ca.crt", "--listen=:8443", "--allow-trial-canonical-ledger"],
        "env": [{"name": name, "valueFrom": {"secretKeyRef": {"name": "gateway-upstream-access", "key": key}}}
            for name, key in (("AWS_ACCESS_KEY_ID", "access-key"), ("AWS_SECRET_ACCESS_KEY", "secret-key"))],
        "ports": [{"containerPort": 8443}], "securityContext": {"readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "config", "mountPath": "/config", "readOnly": True},
            {"name": "trust", "mountPath": "/trust", "readOnly": True}],
        "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 2}}
    pod = {"serviceAccountName": "journal-gateway", "automountServiceAccountToken": False, "enableServiceLinks": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
            "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [container],
        "volumes": [{"name": "config", "configMap": {"name": config_name}},
                    {"name": "trust", "secret": {"secretName": "journal-gateway-files", "defaultMode": 0o440}}]}
    if node_name:
        pod["nodeSelector"] = {"kubernetes.io/hostname": node_name}
    deployment = object_resource("Deployment", "journal", namespace, {"replicas": 1,
        "selector": {"matchLabels": {LABEL: "journal-gateway"}},
        "template": {"metadata": {"labels": {LABEL: "journal-gateway"}}, "spec": pod}}, "apps/v1")
    service = object_resource("Service", "journal", namespace, {"selector": {LABEL: "journal-gateway"},
        "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]})
    return [account, service, deployment]
