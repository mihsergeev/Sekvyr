"""Manifests for the disposable real-service stage-4 integration cluster."""

import json
from pathlib import Path

from authority import b64, canonical, public
from common import create, object_resource
import common

PANEL_NS = "stage4-panel"
WITNESS_NS = "stage4-witness"
APP_NS = "stage4-apps"
SA = "sekvyr-operator"
FOREIGN_NS = "stage4-foreign"
RELEASE = "stage4"


def configure(prefix, release="stage4"):
    global PANEL_NS, WITNESS_NS, APP_NS, FOREIGN_NS, RELEASE
    RELEASE = release
    PANEL_NS, WITNESS_NS, APP_NS, FOREIGN_NS = [prefix + "-" + suffix for suffix in ("panel", "witness", "apps", "foreign")]


def secret(namespace, name, values, immutable=True):
    value = object_resource("Secret", name, namespace)
    value.update(type="Opaque", immutable=immutable, stringData={
        key: item.decode() if isinstance(item, bytes) else item for key, item in values.items()
    })
    return create(value)


def config_map(namespace, name, values, immutable=True):
    value = object_resource("ConfigMap", name, namespace)
    value.update(immutable=immutable, data=values)
    return create(value)


def pvc(namespace, name, size="1Gi"):
    if common.HOSTPATH_MODE:
        directory = common.TASK_DIR / "storage" / namespace / name
        if directory.resolve() != directory:
            raise RuntimeError("Isolated storage must not follow symlinks")
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or directory.resolve().parent != (common.TASK_DIR / "storage" / namespace).resolve():
            raise RuntimeError("Unexpected isolated storage directory")
        common.run(["sudo", "-n", "install", "-d", "-o", "65532", "-g", "65532", "-m", "0700", str(directory)])
        return
    specification = {
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": size}},
    }
    if common.STORAGE_CLASS:
        specification["storageClassName"] = common.STORAGE_CLASS
    return create(object_resource("PersistentVolumeClaim", name, namespace, {
        **specification,
    }))


def storage_volume(namespace, name):
    if common.HOSTPATH_MODE:
        return {"hostPath": {"path": str(common.TASK_DIR / "storage" / namespace / name), "type": "Directory"}}
    return {"persistentVolumeClaim": {"claimName": name}}


def deployment(namespace, name, containers, volumes, security_context=None, init_containers=None, annotations=None):
    pod_spec = {"containers": containers, "volumes": volumes, "automountServiceAccountToken": False}
    if security_context:
        pod_spec["securityContext"] = security_context
    if init_containers:
        pod_spec["initContainers"] = init_containers
    if common.NODE_NAME:
        pod_spec["nodeSelector"] = {"kubernetes.io/hostname": common.NODE_NAME}
    resource = object_resource("Deployment", name, namespace, {
        "replicas": 1, "selector": {"matchLabels": {"app": name}},
        "template": {"metadata": {"labels": {"app": name}}, "spec": pod_spec},
    }, api="apps/v1")
    if annotations:
        resource["metadata"]["annotations"] = annotations
    return create(resource)


def service(namespace, name, port):
    return create(object_resource("Service", name, namespace, {
        "selector": {"app": name}, "ports": [{"name": "api", "port": port, "targetPort": port}],
    }))


def prepare_namespaces():
    identities = {}
    for namespace in (PANEL_NS, WITNESS_NS, APP_NS, FOREIGN_NS):
        if common.DRIVER == "k0s" and common.kube("get", "namespace", namespace, "--ignore-not-found", "-o", "name").stdout.strip():
            raise RuntimeError("An isolated test namespace already exists")
        created = create(object_resource("Namespace", namespace))
        identities[namespace] = created["metadata"]["uid"]
    # Explicitly precreate the intended Helm-owned SA to obtain a bootstrap
    # audience token. Runtime authentication later uses the real projected token.
    account = object_resource("ServiceAccount", SA, APP_NS)
    account["metadata"].update(labels={"app.kubernetes.io/managed-by": "Helm"},
                               annotations={"meta.helm.sh/release-name": RELEASE, "meta.helm.sh/release-namespace": APP_NS})
    account["automountServiceAccountToken"] = False
    create(account)
    return identities


def prepare_panel(authority, panel_image, database_image):
    pvc(PANEL_NS, "database")
    pvc(PANEL_NS, "panel-data")
    secret(PANEL_NS, "database-access", {"password": authority.db_password})
    deployment(PANEL_NS, "database", [{
        "name": "database", "image": database_image, "imagePullPolicy": "Never",
        "env": [{"name": "POSTGRES_DB", "value": "sekvyr"}, {"name": "POSTGRES_USER", "value": "sekvyr"},
                {"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "database-access", "key": "password"}}}],
        "ports": [{"containerPort": 5432}],
        "volumeMounts": [{"name": "data", "mountPath": "/var/lib/postgresql"}],
        "readinessProbe": {"exec": {"command": ["pg_isready", "-U", "sekvyr", "-d", "sekvyr"]}, "periodSeconds": 2},
    }], [{"name": "data", **storage_volume(PANEL_NS, "database")}])
    service(PANEL_NS, "database", 5432)
    values = {
        "SEKVYR_DB_URL": "postgresql+asyncpg://sekvyr:" + authority.db_password + "@database:5432/sekvyr",
        "SEKVYR_JWT_SECRET": authority.jwt_secret, "SEKVYR_ADMIN_PASSWORD": authority.owner_password,
    }
    secret(PANEL_NS, "panel-access", values)
    secret(PANEL_NS, "panel-files", {
        "tls.crt": (authority.root / "panel-tls.crt").read_bytes(),
        "tls.key": (authority.root / "panel-tls.key").read_bytes(),
        "witness-ca.crt": authority.witness_ca, "fetch-token": authority.fetch_token,
    })
    env = [{"name": key, "valueFrom": {"secretKeyRef": {"name": "panel-access", "key": key}}} for key in values]
    env.extend({"name": key, "value": value} for key, value in {
        "SEKVYR_DATA_DIR": "/data", "SEKVYR_ADMIN_USER": "admin",
        "SEKVYR_PANEL_URL": authority.panel_origin, "SEKVYR_ALERT_ON_ENVS": "",
        "SEKVYR_E2E2_WITNESS_ORIGIN": authority.witness_origin,
        "SEKVYR_E2E2_WITNESS_CA_FILE": "/fixture/witness-ca.crt",
        "SEKVYR_E2E2_WITNESS_PUBLIC_KEY": b64(public(authority.witness)),
        "SEKVYR_E2E2_WITNESS_EPOCH": "1",
        "SEKVYR_E2E2_WITNESS_FETCH_TOKEN_FILE": "/fixture/fetch-token",
        "SEKVYR_E2E2_WITNESS_FETCH_VIEWS": authority.scope["view_id"],
    }.items())
    deployment(PANEL_NS, "panel", [{
        "name": "panel", "image": panel_image, "imagePullPolicy": "Never", "env": env,
        "command": ["/usr/local/bin/docker-entrypoint.sh"],
        "args": ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-certfile /fixture/tls.crt --ssl-keyfile /fixture/tls.key --no-access-log"],
        "ports": [{"containerPort": 8443}],
        "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "secret", "mountPath": "/secret"},
                         {"name": "tmp", "mountPath": "/tmp"}, {"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
        "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"], "add": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]}},
    }], [{"name": "data", **storage_volume(PANEL_NS, "panel-data")},
         {"name": "secret", "emptyDir": {}}, {"name": "tmp", "emptyDir": {}},
         {"name": "fixture", "secret": {"secretName": "panel-files", "defaultMode": 0o440}}],
       security_context={"fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}})
    service(PANEL_NS, "panel", 8443)


def prepare_witness(authority, witness_image):
    genesis, genesis_hash = authority.genesis()
    config = {"format": "sekvyr-witness-config-v1", "registrations": [{
        "log_id": authority.scope["log_id"], "genesis_hash": genesis_hash,
        "admin_public_key": b64(public(authority.admin)),
        "minimum_checkpoint": {"sequence": "0", "envelope_hash": "0" * 64},
        "staging_token_file": "/fixture/fetch-token", "panel_ca_file": "/fixture/panel-ca.crt",
    }]}
    secret(WITNESS_NS, "witness-files", {
        "genesis.json": canonical(genesis), "config.json": canonical(config),
        "admin.pub.b64": b64(public(authority.admin)), "witness.pkcs8.pem": (authority.root / "witness.pkcs8.pem").read_bytes(),
        "tls.crt": (authority.root / "witness-tls.crt").read_bytes(), "tls.key": (authority.root / "witness-tls.key").read_bytes(),
        "panel-ca.crt": authority.panel_ca, "fetch-token": authority.fetch_token,
    })
    pvc(WITNESS_NS, "independent-development-ledger")
    mounts = [{"name": "ledger", "mountPath": "/ledger"}, {"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
    init = [{"name": "register", "image": witness_image, "imagePullPolicy": "Never",
             "args": ["init", "--ledger-root=/ledger", "--registration=/fixture/genesis.json",
                      "--admin-public-key=/fixture/admin.pub.b64", "--allow-development-filesystem-ledger"],
             "volumeMounts": mounts, "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]
    # Registration is an explicit offline Job, not a repeated Deployment init
    # container: a service restart must replay the existing journal, not re-init.
    job = object_resource("Job", "witness-genesis", WITNESS_NS, {
        "backoffLimit": 0, "template": {"metadata": {"labels": {"app": "witness-genesis"}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532},
            "containers": init, "volumes": [{"name": "ledger", **storage_volume(WITNESS_NS, "independent-development-ledger")},
                                                {"name": "fixture", "secret": {"secretName": "witness-files", "defaultMode": 0o440}}],
        }},
    }, api="batch/v1")
    if common.NODE_NAME:
        job["spec"]["template"]["spec"]["nodeSelector"] = {"kubernetes.io/hostname": common.NODE_NAME}
    create(job)
    return mounts, genesis_hash


def start_witness(witness_image, mounts):
    deployment(WITNESS_NS, "witness", [{
        "name": "witness", "image": witness_image, "imagePullPolicy": "Never",
        "args": ["serve", "--ledger-root=/ledger", "--config=/fixture/config.json",
                 "--signing-key=/fixture/witness.pkcs8.pem", "--tls-cert=/fixture/tls.crt", "--tls-key=/fixture/tls.key",
                 "--listen=:8443", "--allow-development-filesystem-ledger"],
        "ports": [{"containerPort": 8443}], "volumeMounts": mounts,
        "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
    }], [{"name": "ledger", **storage_volume(WITNESS_NS, "independent-development-ledger")},
         {"name": "fixture", "secret": {"secretName": "witness-files", "defaultMode": 0o440}}],
       security_context={"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}})
    service(WITNESS_NS, "witness", 8443)


def start_canary(python_image, target):
    config_map(APP_NS, "canary-source", {"canary.py": Path(__file__).with_name("canary.py").read_text(encoding="utf-8")})
    pod = object_resource("Pod", "canary", APP_NS, {
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "canary", "image": python_image, "imagePullPolicy": "Never",
                        "command": ["python", "-u", "/app/canary.py"], "ports": [{"containerPort": 8080}],
                        "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True}, {"name": "secrets", "mountPath": "/secrets", "readOnly": True}]}],
        "volumes": [{"name": "source", "configMap": {"name": "canary-source"}},
                    {"name": "secrets", "secret": {"secretName": target, "optional": True}}],
    })
    if common.NODE_NAME:
        pod["spec"]["nodeSelector"] = {"kubernetes.io/hostname": common.NODE_NAME}
    return create(pod)
