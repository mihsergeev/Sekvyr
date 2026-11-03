"""Actual isolated TLS panel and owner API provider for stage6 acceptance.

All credentials and private exports remain in the coordinator's private task.
This module neither creates a witness nor adopts an existing panel database.
"""

import base64
import copy
import json
from pathlib import Path
import re
import subprocess
import uuid
from urllib.parse import quote

from fixture import canonical, issue_leaf, token, write_private
from forward import Forward
from journal_client import JournalClient
from manifests import object_resource
from protocol import key_descriptor
from panel_database import ensure_trial_database

PINNED_IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}")
PANEL_DB, PANEL_USER = "trial_panel", "trial_admin"


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


class Panel:
    def __init__(self, cluster, protocol, witness_client, recovery_executable=None):
        self.cluster, self.protocol, self.task = cluster, protocol, cluster.task
        self.namespace = cluster.fixture["namespaces"]["panel"]
        self.namespace_uid = cluster.namespace_pins()[self.namespace]
        self.witness_client = witness_client
        self.recovery_executable = Path(recovery_executable) if recovery_executable else None
        self.forward, self.client, self.owner = None, None, None
        self.private = self.task / "private"
        self.origin = protocol.panel_origin
        self.files_name = "panel-files"
        self.revision = 0
        self.created = {}
        for path in cluster.pins.glob("*.json"):
            pin = json.loads(path.read_text(encoding="utf-8"))
            if pin["namespace"] == self.namespace:
                self.created[(pin["kind"], pin["name"])] = pin

    def __repr__(self):
        return "<isolated stage6 TLS panel provider [redacted]>"

    def get(self, kind, name):
        pin = self.created.get((kind, name))
        require(pin is not None, "Panel object has no creation UID")
        namespace = json.loads(self.cluster.kube("get", "namespace", self.namespace, "-o", "json").stdout)
        require(namespace["metadata"]["uid"] == self.namespace_uid, "Panel namespace replaced")
        value = json.loads(self.cluster.kube("get", kind, name, "-n", self.namespace, "-o", "json").stdout)
        require(value["metadata"]["uid"] == pin["uid"] and not value["metadata"].get("deletionTimestamp"), "Panel object replaced")
        return value

    def create(self, resource):
        require(resource["metadata"].get("namespace") == self.namespace, "Panel create outside owned namespace")
        namespace = json.loads(self.cluster.kube("get", "namespace", self.namespace, "-o", "json").stdout)
        require(namespace["metadata"]["uid"] == self.namespace_uid, "Panel namespace replaced")
        value = self.cluster.create(resource)
        self.created[(value["kind"], value["metadata"]["name"])] = {"uid": value["metadata"]["uid"]}
        return value

    def patch(self, kind, name, operations):
        value = self.get(kind, name)
        for operation in operations:
            require(operation.get("op") in ("add", "replace", "remove", "test") and operation.get("path") not in
                ("", "/", "/metadata", "/metadata/uid", "/metadata/resourceVersion", "/metadata/name", "/metadata/namespace"), "Unsafe panel patch")
        patch = [{"op": "test", "path": "/metadata/uid", "value": value["metadata"]["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": value["metadata"]["resourceVersion"]}] + copy.deepcopy(operations)
        return json.loads(self.cluster.kube("patch", kind, name, "-n", self.namespace, "--type=json", "-p", json.dumps(patch), "-o", "json").stdout)

    def secret(self, name, data):
        value = object_resource("Secret", name, self.namespace)
        value.update(type="Opaque", immutable=True, data={key: base64.b64encode(raw if isinstance(raw, bytes) else raw.encode()).decode() for key, raw in data.items()})
        return self.create(value)

    def authority_config(self, witness_origin):
        p = self.protocol
        return {"format": "sekvyr-panel-authority-config-v1", "registrations": [{"scope": p.scope,
            "genesis_hash": p.genesis_hash, "minimum_cursor": p.registration["minimum_cursor"],
            "witness_public_key": key_descriptor(p.witness)["public_key"], "witness_epoch": p.authority["witness_epoch"],
            "witness_origin": witness_origin, "ca_file": "/fixture/journal-ca.crt",
            "client_cert_file": "/fixture/panel-client.crt", "client_key_file": "/fixture/panel-client.key"}]}

    def file_materials(self, witness_origin):
        return {"tls.crt": (self.private / "panel-server.crt").read_bytes(), "tls.key": (self.private / "panel-server.key").read_bytes(),
            "journal-ca.crt": (self.private / "journal-ca.crt").read_bytes(), "panel-client.crt": (self.private / "panel.crt").read_bytes(),
            "panel-client.key": (self.private / "panel.key").read_bytes(), "fetch-token": (self.private / "fetch-token").read_bytes(),
            "authority.json": canonical(self.authority_config(witness_origin))}

    def prepare(self, image, storage_class, witness_origin, node_name=""):
        require(PINNED_IMAGE.fullmatch(image) is not None and storage_class, "Exact panel image and storage class required")
        require(not (self.private / "panel-access.json").exists(), "Panel preparation may not reset a prior fixture")
        ensure_trial_database(self)
        db_secret = self.get("Secret", "database-access")
        password = base64.b64decode(db_secret["data"]["password"], validate=True).decode()
        issue_leaf(self.task, "journal", "panel-server", "server", ["panel." + self.namespace + ".svc.cluster.local", "localhost"])
        access = {"SEKVYR_DB_URL": "postgresql+asyncpg://" + PANEL_USER + ":" + quote(password, safe="") + "@database:5432/" + PANEL_DB,
            "SEKVYR_JWT_SECRET": token(48), "SEKVYR_ADMIN_PASSWORD": token(24)}
        write_private(self.private / "panel-access.json", canonical(access))
        self.secret("panel-access", access)
        self.secret(self.files_name, self.file_materials(witness_origin))
        pvc = object_resource("PersistentVolumeClaim", "panel-data", self.namespace)
        pvc["spec"] = {"accessModes": ["ReadWriteOnce"], "storageClassName": storage_class, "resources": {"requests": {"storage": "1Gi"}}}
        self.create(pvc)
        values = {"SEKVYR_DATA_DIR": "/data", "SEKVYR_ADMIN_USER": "admin", "SEKVYR_PANEL_URL": self.origin,
            "SEKVYR_ALERT_ON_ENVS": "", "SEKVYR_E2E2_WITNESS_ORIGIN": witness_origin,
            "SEKVYR_E2E2_WITNESS_CA_FILE": "/fixture/journal-ca.crt", "SEKVYR_E2E2_WITNESS_PUBLIC_KEY": key_descriptor(self.protocol.witness)["public_key"],
            "SEKVYR_E2E2_WITNESS_EPOCH": self.protocol.authority["witness_epoch"], "SEKVYR_E2E2_WITNESS_FETCH_TOKEN_FILE": "/fixture/fetch-token",
            "SEKVYR_E2E2_WITNESS_FETCH_VIEWS": self.protocol.scope["view_id"], "SEKVYR_E2E2_AUTHORITY_CONFIG_FILE": "/fixture/authority.json"}
        environment = [{"name": key, "value": value} for key, value in values.items()] + [{"name": key, "valueFrom": {"secretKeyRef": {"name": "panel-access", "key": key}}} for key in access]
        labels = {"app": "panel", "secrets.sekvyr.ru/trial-role": "panel"}
        container = {"name": "panel", "image": image, "imagePullPolicy": "IfNotPresent", "env": environment,
            "command": ["/usr/local/bin/docker-entrypoint.sh"], "args": ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-certfile /fixture/tls.crt --ssl-keyfile /fixture/tls.key --no-access-log"],
            "ports": [{"name": "https", "containerPort": 8443}], "resources": {"requests": {"cpu": "100m", "memory": "192Mi"}, "limits": {"cpu": "2", "memory": "768Mi"}},
            "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"], "add": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]}},
            "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/api/health", "port": "https"}, "periodSeconds": 2},
            "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "secret", "mountPath": "/secret"}, {"name": "tmp", "mountPath": "/tmp"}, {"name": "fixture", "mountPath": "/fixture", "readOnly": True}]}
        pod = {"automountServiceAccountToken": False, "enableServiceLinks": False,
            "securityContext": {"fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [container],
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "panel-data"}}, {"name": "secret", "emptyDir": {}},
                {"name": "tmp", "emptyDir": {}}, {"name": "fixture", "secret": {"secretName": self.files_name, "defaultMode": 0o440}}]}
        if node_name:
            pod["nodeSelector"] = {"kubernetes.io/hostname": node_name}
        deployment = object_resource("Deployment", "panel", self.namespace, api="apps/v1")
        deployment["spec"] = {"replicas": 1, "selector": {"matchLabels": {"app": "panel"}}, "template": {"metadata": {"labels": labels}, "spec": pod}}
        self.create(deployment)
        service = object_resource("Service", "panel", self.namespace)
        service["spec"] = {"selector": {"app": "panel"}, "ports": [{"name": "https", "port": 8443, "targetPort": "https"}]}
        self.create(service)
        return {"panelCreated": True, "independentAuthorityConfig": True, "production": False}

    def connect(self):
        self.get("Service", "panel")
        if self.forward:
            self.forward.close()
        self.forward = Forward(self.cluster, self.namespace, "service/panel", 8443)
        self.client = JournalClient(self.forward.origin, self.private / "journal-ca.crt")
        return self

    def request(self, method, path, body=None, access_token=None, expected=(200,)):
        require(self.client is not None, "Panel connection is not established")
        headers = {"Content-Type": "application/json"}
        if access_token:
            headers["Authorization"] = "Bearer " + access_token
        code, raw, _ = self.client.request(method, path, canonical(body) if body is not None else None, headers, expected, maximum=8 << 20)
        try:
            return code, json.loads(raw) if raw else None
        except ValueError:
            raise RuntimeError("Panel returned invalid JSON") from None

    def owner_request(self, method, path, body=None, expected=(200,)):
        require(self.owner is not None, "Panel owner has not authenticated")
        return self.request(method, path, body, self.owner, expected)

    def login(self):
        access = json.loads((self.private / "panel-access.json").read_text(encoding="utf-8"))
        _, body = self.request("POST", "/api/auth/login", {"username": "admin", "password": access["SEKVYR_ADMIN_PASSWORD"]})
        self.owner = body["access_token"]

    def unseal(self):
        _, status = self.owner_request("GET", "/api/vault/status")
        root_path = self.private / "panel-vault-key.json"
        if not status["initialized"]:
            require(not root_path.exists(), "Vault initialization cannot reset saved recovery material")
            _, body = self.owner_request("POST", "/api/vault/init", {"mode": "env"})
            write_private(root_path, canonical({"root_key": body["root_key"]}))
        _, status = self.owner_request("GET", "/api/vault/status")
        if status["sealed"]:
            root = json.loads(root_path.read_text(encoding="utf-8"))["root_key"]
            _, status = self.owner_request("POST", "/api/vault/unseal", {"root_key": root})
            require(not status["sealed"], "Explicit trial vault unseal failed")

    def bootstrap(self, operator_service_account="sekvyr-operator"):
        require(not (self.private / "panel-bootstrap.json").exists(), "Panel bootstrap must not reset an earlier identity")
        self.login()
        self.unseal()
        _, project = self.owner_request("POST", "/api/projects", {"slug": "trial", "title": "Isolated trial", "environments": ["trial"]}, (201,))
        _, environments = self.owner_request("GET", "/api/projects/" + str(project["id"]) + "/environments")
        environment = next(item for item in environments if item["name"] == "trial")
        jwks = json.loads(self.cluster.kube("get", "--raw", "/openid/v1/jwks").stdout)
        discovery = json.loads(self.cluster.kube("get", "--raw", "/.well-known/openid-configuration").stdout)
        _, identity = self.owner_request("POST", "/api/machines/clusters", {"name": "isolated-trial-cluster", "issuer": discovery["issuer"], "audience": "sekvyr", "jwks": json.dumps(jwks)}, (201,))
        apps = self.cluster.fixture["namespaces"]["apps"]
        sa = json.loads(self.cluster.kube("get", "serviceaccount", operator_service_account, "-n", apps, "-o", "json").stdout)
        pins = [json.loads(path.read_text()) for path in self.cluster.pins.glob("*.json")]
        require(any(pin["kind"] == "ServiceAccount" and pin["namespace"] == apps and pin["name"] == operator_service_account and pin["uid"] == sa["metadata"]["uid"] for pin in pins), "Machine bootstrap needs an own pinned ServiceAccount")
        _, machine = self.owner_request("POST", "/api/machines", {"name": "isolated-operator-reader", "cluster_id": identity["id"], "k8s_namespace": apps, "k8s_service_account": operator_service_account}, (201,))
        self.owner_request("POST", "/api/policies", {"subject_type": "machine", "subject_id": machine["id"], "project_id": project["id"], "environment_id": environment["id"], "path_prefix": "/", "actions": ["list", "read"], "effect": "allow"}, (201,))
        projected = self.cluster.kube("create", "token", operator_service_account, "-n", apps, "--audience=sekvyr", "--duration=10m").stdout.strip()
        _, machine_session = self.request("POST", "/api/v1/machine/token", {"kubernetes_token": projected})
        self.request("POST", "/api/v1/machine/report", {"public_key": base64.b64encode(self.protocol.node_public).decode()}, machine_session["access_token"])
        self.owner_request("POST", "/api/e2e2/views", {"project_id": project["id"], "environment_id": environment["id"], "context": self.protocol.scope,
            "publisher_keys": {key_descriptor(self.protocol.publisher)["key_id"]: key_descriptor(self.protocol.publisher)["public_key"]}, "read_key_epoch": "1", "publisher_policy_epoch": "1"}, (201,))
        metadata = {"project_id": project["id"], "environment_id": environment["id"], "machine_id": machine["id"], "cluster_id": identity["id"]}
        write_private(self.private / "panel-bootstrap.json", canonical(metadata))
        return metadata

    def current(self):
        code, raw, _ = self.witness_client.request("GET", "/v2/logs/" + self.protocol.scope["log_id"] + "/authority")
        return json.loads(raw)

    def enroll(self, enrollment):
        current = self.current()
        transition = self.protocol.transition("enroll-installation", current, enrollment=enrollment)
        self.witness_client.request("POST", "/v2/logs/" + self.protocol.scope["log_id"] + "/transitions", canonical(transition), {"Content-Type": "application/json"})
        return self.current()

    def publish_sealed(self, envelope, digest):
        view = self.protocol.scope["view_id"]
        _, staged = self.owner_request("POST", "/api/e2e2/views/" + view + "/envelopes", envelope, (201,))
        require(staged["envelope_hash"] == digest, "Panel staged a different hash")
        current = self.current()
        self.witness_client.request("POST", "/v2/logs/" + self.protocol.scope["log_id"] + "/commits", canonical({"expected": current["cursor"], "envelope_hash": digest}), {"Content-Type": "application/json"})
        _, indexed = self.owner_request("POST", "/api/e2e2/views/" + view + "/rotation-project", {})
        require(indexed["envelope_hash"] == digest, "Panel projection does not match canonical committed data")
        return self.current()["snapshot"]

    def grant_reader(self):
        meta = json.loads((self.private / "panel-bootstrap.json").read_text(encoding="utf-8"))
        _, body = self.owner_request("POST", "/api/e2e2/views/" + self.protocol.scope["view_id"] + "/readers", {"machine_id": meta["machine_id"], "wrapper": self.protocol.reader_wrap()})
        require(body["has_wrap"], "Panel did not authorize the signed reader wrap")

    def publish(self, generation, demo_value):
        current = self.current()
        envelope, digest = self.protocol.snapshot(int(current["snapshot"]["sequence"]) + 1, current["snapshot"]["envelope_hash"], generation, demo_value)
        return self.publish_sealed(envelope, digest)

    def project_rotation(self, transition, envelope, wrappers=True):
        meta = json.loads((self.private / "panel-bootstrap.json").read_text(encoding="utf-8"))
        view = self.protocol.scope["view_id"]
        readers = [{"machine_id": meta["machine_id"], "wrapper": self.protocol.reader_wrap()}] if wrappers else []
        self.owner_request("POST", "/api/e2e2/views/" + view + "/rotation-stage", {"envelope": envelope, "readers": readers}, (201,))
        self.witness_client.request("POST", "/v2/logs/" + self.protocol.scope["log_id"] + "/transitions", canonical(transition), {"Content-Type": "application/json"})
        self.owner_request("POST", "/api/e2e2/views/" + view + "/rotation-project", {})
        return self.current()

    def offline_export(self):
        current = self.current()
        view = self.protocol.scope["view_id"]
        # Owner APIs return ciphertext. Exact hash is independently known from
        # the replay-verified witness/provider state and the Go reader rechecks it.
        _, envelope = self.owner_request("GET", "/api/e2e2/views/" + view + "/envelopes/" + current["snapshot"]["envelope_hash"])
        return canonical(envelope), canonical(self.protocol.reader_wrap())

    def recover(self, plan, envelope, wrapper, installation):
        executable = self.recovery_executable
        require(executable is not None and executable.is_absolute() and executable.is_file() and not executable.is_symlink()
            and executable.resolve() == executable and executable.name == "sekvyr-checkpoint-recovery"
            and executable.parent.name == "bin" and executable.parent.parent.name == "out"
            and executable.parent.parent.parent.parent == Path("/opt/sekvyr-trial")
            and re.fullmatch(r"sekvyr-stage6-[0-9]{8}-[0-9a-f]{8}", executable.parent.parent.parent.name), "Exact private recovery binary required")
        # Pure-Go static binary runs in a private filesystem with Kubernetes DNS
        # from our own database Pod. The host resolver and all cluster workloads
        # remain untouched, and no cluster-admin credential enters a Pod.
        sandbox = self.private / ("recovery-sandbox-" + uuid.uuid4().hex)
        sandbox.mkdir(mode=0o700)
        for name in ("bin", "inputs", "etc", "tmp"):
            (sandbox / name).mkdir(mode=0o700)
        self.get("Deployment", "database")
        resolv = self.cluster.kube("exec", "deployment/database", "-n", self.namespace, "-c", "database", "--", "cat", "/etc/resolv.conf").stdout
        require(len(resolv) < 16384 and re.search(r"(?m)^nameserver\s+[0-9a-fA-F:.]+\s*$", resolv), "Private Kubernetes DNS configuration unavailable")
        write_private(sandbox / "etc" / "resolv.conf", resolv)
        write_private(sandbox / "etc" / "hosts", "127.0.0.1 localhost\n::1 localhost\n")
        import yaml
        kube_raw = self.cluster.config.read_bytes()
        kube = yaml.safe_load(kube_raw)
        require(type(kube) is dict and kube.get("clusters") and kube.get("users"), "Explicit private kubeconfig required")
        for cluster in kube["clusters"]:
            value = cluster["cluster"]
            require(value.get("certificate-authority-data") and not value.get("insecure-skip-tls-verify") and "certificate-authority" not in value,
                "Recovery kubeconfig must contain embedded verified CA material")
        for user in kube["users"]:
            value = user["user"]
            require(not {"exec", "auth-provider", "tokenFile", "client-certificate", "client-key"}.intersection(value)
                and (value.get("token") or value.get("client-certificate-data") and value.get("client-key-data")),
                "Recovery kubeconfig must contain embedded credentials without helper execution")
        write_private(sandbox / "inputs" / "kubeconfig", kube_raw)
        binary = sandbox / "bin" / executable.name
        write_private(binary, executable.read_bytes())
        binary.chmod(0o500)
        paths = {name: sandbox / "inputs" / (name + ".json") for name in ("plan", "envelope", "reader-wrap", "installation")}
        for name, body in (("plan", plan), ("envelope", envelope), ("reader-wrap", wrapper), ("installation", installation)):
            write_private(paths[name], body if isinstance(body, bytes) else canonical(body))
        command = ["sudo", "-n", "/usr/bin/env", "-i", "KUBECONFIG=/inputs/kubeconfig", "/usr/sbin/chroot", str(sandbox),
            "/bin/" + executable.name, "--kubeconfig=/inputs/kubeconfig", "--allow-trial-canonical-ledger", "--installation-file", "/inputs/installation.json",
            "--plan", "/inputs/plan.json", "--envelope", "/inputs/envelope.json", "--reader-wrap", "/inputs/reader-wrap.json"]
        if plan["body"].get("allow_rollout"):
            command.append("--enable-rollout")
        result = subprocess.run(command, capture_output=True, text=True, timeout=320)
        if result.returncode:
            reason = result.stderr.strip()
            reason = reason if re.fullmatch(r"[A-Za-z]{1,80}", reason) else "RecoveryRejected"
            raise RuntimeError("Trial checkpoint recovery failed: " + reason)
        require(result.stdout.strip() == "CheckpointRecoveryComplete", "Recovery tool returned unexpected completion")
        return {"checkpointRecoveryComplete": True}

    def scale(self, replicas):
        require(replicas in (0, 1), "Panel fault injection allows only zero or one replica")
        return self.patch("Deployment", "panel", [{"op": "replace", "path": "/spec/replicas", "value": replicas}])

    def replace_witness_pin(self, witness_origin):
        self.revision += 1
        name = "panel-files-rotation-" + str(self.revision)
        self.secret(name, self.file_materials(witness_origin))
        deployment = self.get("Deployment", "panel")
        volumes = deployment["spec"]["template"]["spec"]["volumes"]
        index = next(i for i, item in enumerate(volumes) if item["name"] == "fixture")
        self.patch("Deployment", "panel", [{"op": "replace", "path": "/spec/template/spec/volumes/" + str(index) + "/secret/secretName", "value": name}])
        self.files_name = name

    def close(self):
        if self.forward:
            self.forward.close()
            self.forward = None
        self.client, self.owner = None, None
