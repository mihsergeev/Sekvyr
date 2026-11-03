"""Disposable PostgreSQL for approved migration tests and the future trial panel."""

import json

from fixture import canonical, token, write_private
from manifests import LABEL, object_resource
from run import secret


POSTGRES_IMAGE = "docker.io/library/postgres@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5"


def prepare(cluster, storage_class, node_name=""):
    namespace = cluster.fixture["namespaces"]["panel"]
    password = token(36)
    write_private(cluster.task / "private" / "database-password", password)
    cluster.create(secret(namespace, "database-access", {"password": password.encode()}))
    cluster.create(object_resource("PersistentVolumeClaim", "trial-database", namespace, {
        "accessModes": ["ReadWriteOnce"], "storageClassName": storage_class,
        "resources": {"requests": {"storage": "1Gi"}}}))
    pod = {"automountServiceAccountToken": False, "enableServiceLinks": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 999, "runAsGroup": 999, "fsGroup": 999,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "database", "image": POSTGRES_IMAGE, "imagePullPolicy": "IfNotPresent",
            "env": [{"name": "POSTGRES_USER", "value": "trial_admin"}, {"name": "POSTGRES_DB", "value": "trial_panel"},
                    {"name": "PGDATA", "value": "/data/pgdata"}, {"name": "POSTGRES_PASSWORD_FILE", "value": "/access/password"}],
            "ports": [{"containerPort": 5432}],
            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1000m", "memory": "512Mi"}},
            "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "access", "mountPath": "/access", "readOnly": True},
                {"name": "run", "mountPath": "/var/run/postgresql"}, {"name": "tmp", "mountPath": "/tmp"}],
            "readinessProbe": {"exec": {"command": ["pg_isready", "-U", "trial_admin", "-d", "trial_panel"]}, "periodSeconds": 2}}],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "trial-database"}},
            {"name": "access", "secret": {"secretName": "database-access", "defaultMode": 0o440}},
            {"name": "run", "emptyDir": {}}, {"name": "tmp", "emptyDir": {}}]}
    if node_name:
        pod["nodeSelector"] = {"kubernetes.io/hostname": node_name}
    cluster.create(object_resource("Deployment", "database", namespace, {"replicas": 1, "strategy": {"type": "Recreate"},
        "selector": {"matchLabels": {LABEL: "database"}}, "template": {"metadata": {"labels": {LABEL: "database"}}, "spec": pod}}, "apps/v1"))
    cluster.create(object_resource("Service", "database", namespace, {"selector": {LABEL: "database"},
        "ports": [{"name": "postgres", "port": 5432, "targetPort": 5432}]}))
    cluster.create(object_resource("NetworkPolicy", "panel-database", namespace, {
        "podSelector": {"matchLabels": {LABEL: "database"}}, "policyTypes": ["Ingress"], "ingress": [{
            "from": [{"podSelector": {"matchLabels": {LABEL: "panel"}}}], "ports": [{"protocol": "TCP", "port": 5432}]}]}, "networking.k8s.io/v1"))
    cluster.create(object_resource("NetworkPolicy", "panel-database-client", namespace, {
        "podSelector": {"matchLabels": {LABEL: "panel"}}, "policyTypes": ["Egress"], "egress": [{
            "to": [{"podSelector": {"matchLabels": {LABEL: "database"}}}], "ports": [{"protocol": "TCP", "port": 5432}]}]}, "networking.k8s.io/v1"))
    metadata = {"namespace": namespace, "service": "database", "secret_name": "database-access", "password_key": "password",
                "superuser": "trial_admin", "panel_database_reserved": "trial_panel", "production": False}
    write_private(cluster.task / "private" / "database-metadata.json", canonical(metadata))
    return {"databaseCreated": True, "credentialsExported": False, "production": False}
