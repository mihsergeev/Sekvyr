"""Actual app modes for the coordinator's explicit isolated Stage7Cluster.

No topology, provider API, credentials, image tag resolution or live action is
chosen on import. Legacy agent stays an unchanged caller-supplied pinned image.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")
ROLE = "secrets.sekvyr.ru/trial-role"
LABEL = "secrets.sekvyr.ru/stage7-app"
OPTOUT = {name: "false" for name in ("reloader.stakater.com/auto", "secret.reloader.stakater.com/auto", "configmap.reloader.stakater.com/auto")}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def wait(check, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.4)
    raise RuntimeError("Stage7 application wait expired")


def resource(kind, name, namespace, spec=None, api="v1"):
    require(NAME.fullmatch(name) is not None and NAME.fullmatch(namespace) is not None, "Invalid exact fixture resource name")
    value = {"apiVersion": api, "kind": kind, "metadata": {"name": name, "namespace": namespace}}
    if spec is not None:
        value["spec"] = spec
    return value


class OwnedNamespace:
    def __init__(self, cluster, namespace):
        require(namespace in cluster.namespaces, "Namespace outside this trial")
        self.cluster, self.namespace = cluster, namespace
        self.namespace_uid = cluster.namespace_pins()[namespace]
        self.reload_pins()

    def __repr__(self):
        return "<stage7 owned namespace [redacted]>"

    def reload_pins(self):
        self.pins = {}
        for path in self.cluster.pins.glob("*.json"):
            require(not path.is_symlink(), "Unsafe fixture UID registry")
            pin = json.loads(path.read_bytes())
            if pin.get("namespace") == self.namespace:
                key = pin["kind"], pin["name"]
                require(key not in self.pins, "Ambiguous fixture creation pins")
                self.pins[key] = pin

    def guard(self):
        current = json.loads(self.cluster.kube("get", "namespace", self.namespace, "-o", "json").stdout)
        require(current["metadata"]["uid"] == self.namespace_uid and not current["metadata"].get("deletionTimestamp"), "Fixture namespace replaced or deleting")

    def create(self, value):
        self.guard()
        meta = value["metadata"]
        require(meta.get("namespace") == self.namespace and NAME.fullmatch(meta["name"]) is not None
            and not {"uid", "resourceVersion"}.intersection(meta), "Fixture CREATE identity invalid")
        require((value["kind"], meta["name"]) not in self.pins, "Fixture resource name already owned")
        answer = self.cluster.create(value)
        require(answer["metadata"]["namespace"] == self.namespace and answer["metadata"]["name"] == meta["name"]
            and answer["kind"] == value["kind"] and answer["metadata"]["uid"], "Fixture CREATE response mismatch")
        self.reload_pins()
        require(self.pins[(value["kind"], meta["name"])]["uid"] == answer["metadata"]["uid"], "Fixture CREATE UID was not durably captured")
        return answer

    def create_service_account(self, name):
        value = resource("ServiceAccount", name, self.namespace)
        value["automountServiceAccountToken"] = False
        return self.create(value)

    def get(self, kind, name):
        self.guard()
        require((kind, name) in self.pins, "Fixture object lacks an explicit UID pin")
        value = json.loads(self.cluster.kube("get", kind, name, "-n", self.namespace, "-o", "json").stdout)
        meta = value["metadata"]
        require(value["kind"] == kind and meta["name"] == name and meta["namespace"] == self.namespace
            and meta["uid"] == self.pins[(kind, name)]["uid"] and not meta.get("deletionTimestamp"), "Fixture object replaced or deleting")
        return value

    def patch(self, kind, name, operations):
        current = self.get(kind, name)
        for operation in operations:
            require(operation.get("op") in ("add", "replace", "remove", "test")
                and operation.get("path") not in (None, "", "/", "/metadata", "/metadata/name", "/metadata/namespace", "/metadata/uid", "/metadata/resourceVersion"),
                "Unsafe fixture mutation")
        patch = [{"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}] + copy.deepcopy(operations)
        result = json.loads(self.cluster.kube("patch", kind, name, "-n", self.namespace, "--type=json", "-p", json.dumps(patch), "-o", "json").stdout)
        require(result["metadata"]["uid"] == current["metadata"]["uid"], "Fixture mutation UID changed")
        return result


def _security(uid=65532):
    return {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid, "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}


class Stage7Applications:
    def __init__(self, cluster, namespace, python_image, agent_image=None):
        require(IMAGE.fullmatch(python_image) is not None and (agent_image is None or IMAGE.fullmatch(agent_image) is not None), "All app images must be digest pinned")
        self.owned, self.cluster = OwnedNamespace(cluster, namespace), cluster
        self.namespace, self.python_image, self.agent_image = namespace, python_image, agent_image
        self.modes = {}

    def __repr__(self):
        return "<stage7 application modes [redacted]>"

    def target(self, reference):
        """Read only; an operator-created target requires the provider's UID.

        The provider obtains that UID from protected state + fresh DataCurrent.
        A GET here never creates a cleanup pin or adopts a managed Secret.
        """
        if isinstance(reference, str):
            return self.owned.get("Secret", reference)
        require(isinstance(reference, dict) and set(reference) == {"name", "uid"}
            and NAME.fullmatch(reference["name"]) is not None
            and isinstance(reference["uid"], str) and 0 < len(reference["uid"]) <= 128,
            "Explicit runtime target name and UID required")
        self.owned.guard()
        value = json.loads(self.cluster.kube("get", "Secret", reference["name"], "-n", self.namespace, "-o", "json").stdout)
        meta = value["metadata"]
        require(value["kind"] == "Secret" and meta["namespace"] == self.namespace and meta["name"] == reference["name"]
            and meta["uid"] == reference["uid"] and not meta.get("deletionTimestamp"), "Runtime target replaced or deleting")
        return value

    def _target_name(self, reference, replicas):
        # replicas=0 supports the unavailable-before-first-target case. The
        # future reference is explicit; no existing object is adopted.
        name = reference if isinstance(reference, str) else reference.get("name", "")
        require(isinstance(name, str) and NAME.fullmatch(name) is not None, "Exact target name required")
        if replicas != 0:
            self.target(reference)
        return name

    def _source(self, name, code):
        require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,49}", name), "Bounded fixture application name required")
        value = resource("ConfigMap", name + "-source", self.namespace)
        value.update(immutable=True, data={"app.py": code})
        self.owned.create(value)
        return name + "-source"

    def _deploy(self, name, containers, volumes, replicas, uid=65532, service_account=None, init=None):
        require(type(replicas) is int and replicas in (0, 1), "Fixture replicas must be zero or one")
        labels = {LABEL: name, ROLE: "agent" if init else "application"}
        pod = {"automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True,
            "runAsUser": uid, "runAsGroup": uid, "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": containers, "volumes": volumes}
        if service_account:
            self.owned.get("ServiceAccount", service_account)
            pod["serviceAccountName"] = service_account
        if init:
            pod["initContainers"] = init
        value = resource("Deployment", name, self.namespace, {"replicas": replicas,
            "selector": {"matchLabels": {LABEL: name}}, "template": {"metadata": {"labels": labels}, "spec": pod}}, "apps/v1")
        value["metadata"]["annotations"] = dict(OPTOUT)
        return self.owned.create(value)

    def _app(self, source, mode="env", uid=65532):
        command = ["python", "-B", "/app/app.py"] + ([] if mode == "env" else ["--mode", mode])
        return {"name": "app", "image": self.python_image, "imagePullPolicy": "IfNotPresent", "command": command,
            "ports": [{"containerPort": 8080}], "securityContext": _security(uid),
            "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 1},
            "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True}]}

    def create_env(self, name, target, replicas=1):
        target = self._target_name(target, replicas)
        source = self._source(name, (HERE.parent / "stage5" / "app.py").read_text(encoding="utf-8"))
        app = self._app(source)
        app["envFrom"] = [{"secretRef": {"name": target}}]
        value = self._deploy(name, [app], [{"name": "source", "configMap": {"name": source}}], replicas)
        self.modes[name] = "env"
        return value

    def create_volume(self, name, target, replicas=1):
        target = self._target_name(target, replicas)
        source = self._source(name, (HERE / "file_app.py").read_text(encoding="utf-8"))
        app = self._app(source, "volume")
        app["volumeMounts"].append({"name": "secrets", "mountPath": "/secrets", "readOnly": True})
        value = self._deploy(name, [app], [{"name": "source", "configMap": {"name": source}},
            {"name": "secrets", "secret": {"secretName": target, "defaultMode": 288}}], replicas)
        self.modes[name] = "volume"
        return value

    def create_agent(self, name, source_config, service_account, ca_ref, source_protocol="plain", token_expiration=600):
        require(self.agent_image is not None and source_protocol == "plain", "Legacy regression requires unchanged agent image and Plain source")
        require(type(token_expiration) is int and 600 <= token_expiration <= 3600, "Bounded projected JWT expiry required")
        require(set(source_config).issubset({"SEKVYR_URL", "SEKVYR_GROUP", "SEKVYR_PROJECT", "SEKVYR_ENV"})
            and all(isinstance(value, str) for value in source_config.values()) and source_config.get("SEKVYR_PROJECT") and source_config.get("SEKVYR_ENV"),
            "Agent routing must not contain credentials or arbitrary environment")
        url = urllib.parse.urlsplit(source_config.get("SEKVYR_URL", ""))
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and url.path in ("", "/") and not url.query and not url.fragment, "Agent needs fixed verified HTTPS origin")
        ca = self.owned.get("ConfigMap", ca_ref["name"])
        require(ca.get("immutable") is True and ca["data"].get(ca_ref["key"]), "Agent CA reference must be immutable and UID pinned")
        source = self._source(name, (HERE / "file_app.py").read_text(encoding="utf-8"))
        app = self._app(source, "file", 65534)
        app["volumeMounts"].append({"name": "secrets", "mountPath": "/secrets", "readOnly": True})
        env = dict(source_config, SEKVYR_TOKEN_FILE="/var/run/secrets/sekvyr/token", SSL_CERT_FILE="/trust/ca.crt")
        agent = {"name": "sekvyr-agent", "image": self.agent_image, "imagePullPolicy": "IfNotPresent",
            "args": ["agent", "-o", "/secrets/.env", "--mode", "0440", "--interval", "5s", "--no-update", "--no-cache"],
            "env": [{"name": key, "value": value} for key, value in sorted(env.items())], "securityContext": _security(65534),
            "volumeMounts": [{"name": "secrets", "mountPath": "/secrets"},
                {"name": "panel-token", "mountPath": "/var/run/secrets/sekvyr", "readOnly": True},
                {"name": "ca", "mountPath": "/trust", "readOnly": True}]}
        initial = copy.deepcopy(agent)
        initial["name"], initial["args"] = "sekvyr-init", ["render", "-o", "/secrets/.env", "--mode", "0440", "--no-cache"]
        volumes = [{"name": "source", "configMap": {"name": source}}, {"name": "secrets", "emptyDir": {"medium": "Memory", "sizeLimit": "4Mi"}},
            {"name": "panel-token", "projected": {"defaultMode": 288, "sources": [{"serviceAccountToken": {
                "path": "token", "audience": "sekvyr", "expirationSeconds": token_expiration}}]}},
            {"name": "ca", "configMap": {"name": ca_ref["name"], "defaultMode": 288, "items": [{"key": ca_ref["key"], "path": "ca.crt"}]}}]
        value = self._deploy(name, [app, agent], volumes, 1, 65534, service_account, [initial])
        self.modes[name] = "file"
        return value

    def footprint(self, name):
        deployment = self.owned.get("Deployment", name)
        sets = json.loads(self.cluster.kube("get", "replicasets", "-n", self.namespace, "-l", LABEL + "=" + name, "-o", "json").stdout)["items"]
        uid = deployment["metadata"]["uid"]
        require(all(any(ref.get("uid") == uid and ref.get("kind") == "Deployment" and ref.get("controller") is True
            for ref in value["metadata"].get("ownerReferences", [])) for value in sets), "Application ReplicaSet owner mismatch")
        return {"deployment_uid": uid, "template": deployment["spec"]["template"], "replica_sets": sorted(value["metadata"]["uid"] for value in sets)}

    def status(self, name):
        before = self.footprint(name)
        pods = json.loads(self.cluster.kube("get", "pods", "-n", self.namespace, "-l", LABEL + "=" + name, "-o", "json").stdout)["items"]
        require(all(pod["metadata"].get("namespace") == self.namespace and any(ref.get("kind") == "ReplicaSet" and ref.get("controller") is True and ref.get("uid") in before["replica_sets"]
            for ref in pod["metadata"].get("ownerReferences", [])) for pod in pods), "Application Pod owner mismatch")
        ready = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp") and any(condition["type"] == "Ready"
            and condition["status"] == "True" for condition in pod.get("status", {}).get("conditions", []))]
        if len(ready) != 1:
            return False
        spec = importlib.util.spec_from_file_location("sekvyr_stage7_forward", HERE.parent / "stage6" / "forward.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pod = ready[0]
        with module.Forward(self.cluster, self.namespace, "pod/" + pod["metadata"]["name"], 8080) as forward:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open("http://127.0.0.1:" + str(forward.port) + "/status", timeout=5) as response:
                raw = response.read(4097)
        raw_current = self.cluster.kube("get", "pod", pod["metadata"]["name"], "-n", self.namespace, "--ignore-not-found", "-o", "json").stdout
        if not raw_current.strip():
            return False  # A rollout removed the selected, already verified Pod.
        current = json.loads(raw_current)
        meta = current["metadata"]
        require(meta.get("namespace") == self.namespace and meta.get("name") == pod["metadata"]["name"], "Application Pod identity is outside its namespace")
        if meta["uid"] != pod["metadata"]["uid"]:
            # Never attach the old process response to the replacement UID.
            latest = self.footprint(name)
            require(any(ref.get("kind") == "ReplicaSet" and ref.get("controller") is True and ref.get("uid") in latest["replica_sets"]
                for ref in meta.get("ownerReferences", [])), "Replacement application Pod has foreign owner")
            return False
        require(meta.get("ownerReferences") == pod["metadata"].get("ownerReferences"), "Application Pod owner changed during status read")
        if meta.get("deletionTimestamp"):
            return False
        require(len(raw) <= 4096, "Application status exceeds bounds")
        value = json.loads(raw)
        allowed = {"generation", "value_digest", "boot_id", "pid", "reload_count", "errors", "initial_loaded"}
        require(set(value).issubset(allowed) and {"generation", "value_digest", "boot_id", "pid"}.issubset(value)
            and re.fullmatch(r"[0-9a-f-]{36}", value["boot_id"]) is not None, "Unexpected application status shape")
        return dict(value, pod_uid=pod["metadata"]["uid"])

    def capture(self, name):
        return {"footprint": self.footprint(name), "status": wait(lambda: self.status(name))}

    def frozen(self, name, before, seconds=7):
        deadline = time.monotonic() + seconds
        while True:
            require(self.footprint(name) == before["footprint"], "Unexpected Pod template or ReplicaSet change")
            status = self.status(name)
            require(status and status["pod_uid"] == before["status"]["pod_uid"] and status["boot_id"] == before["status"]["boot_id"], "Application restarted unexpectedly")
            if time.monotonic() >= deadline:
                return
            time.sleep(0.5)

    def assert_env_changed(self, name, before, generation, demo_value, target):
        require(self.modes[name] == "env", "Env rollout proof requires envFrom mode")
        status = wait(lambda: value if (value := self.status(name)) and value["generation"] == generation else False)
        require(status["value_digest"] == hashlib.sha256(demo_value.encode()).hexdigest()
            and status["boot_id"] != before["status"]["boot_id"] and status["pod_uid"] != before["status"]["pod_uid"], "Changed env did not reach a new app process")
        after, secret = self.footprint(name), self.target(target)
        require(len(set(after["replica_sets"]) - set(before["footprint"]["replica_sets"])) == 1, "Expected exactly one new ReplicaSet")
        expected = copy.deepcopy(before["footprint"]["template"])
        expected["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/restart-" + secret["metadata"]["uid"]] = secret["metadata"]["annotations"]["secrets.sekvyr.ru/revision"]
        require(after["template"] == expected, "Rollout changed another Pod template field")
        return {"newReplicaSets": 1, "newPodAndBoot": True, "onlyOwnRestartAnnotation": True}

    def assert_reloaded_without_restart(self, name, before, generation, demo_value):
        require(self.modes[name] in ("volume", "file"), "Reload proof requires volume or legacy file mode")
        status = wait(lambda: value if (value := self.status(name)) and value["generation"] == generation else False)
        require(status["value_digest"] == hashlib.sha256(demo_value.encode()).hexdigest()
            and status["reload_count"] > before["status"]["reload_count"], "Changed values were not reloaded by the same app")
        self.frozen(name, before, seconds=1)
        return {"samePodAndBoot": True, "samePodTemplateAndReplicaSets": True, "applicationReloaded": True}
