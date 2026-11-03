"""Isolated local Kubernetes helpers. Never print credentials or response bodies."""

import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

NODE = "sekvyr-stage4-control-plane"
DOCKER = ["sudo", "-n", "docker", "--host=unix:///var/run/docker.sock"]
DRIVER = "kind"
KUBECTL = DOCKER + ["exec", "-i", NODE, "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf"]
TASK_DIR = None
NODE_NAME = ""
STORAGE_CLASS = ""
HOSTPATH_MODE = False


def configure(driver, task_dir, node_name=""):
    global DRIVER, KUBECTL, TASK_DIR, NODE_NAME
    if driver not in ("kind", "k0s"):
        raise RuntimeError("Unsupported isolated test driver")
    DRIVER, TASK_DIR, NODE_NAME = driver, Path(task_dir).resolve(), node_name
    KUBECTL = (["sudo", "-n", "k0s", "kubectl"] if driver == "k0s" else
               DOCKER + ["exec", "-i", NODE, "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf"])


def run(args, value=None, check=True):
    result = subprocess.run(args, input=value, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError("Local command failed: " + " ".join(str(arg) for arg in args[:4]))
    return result


def kube(*args, value=None, check=True):
    return run(KUBECTL + list(args), value, check)


def object_resource(kind, name, namespace=None, spec=None, api="v1"):
    value = {"apiVersion": api, "kind": kind, "metadata": {"name": name}}
    if namespace:
        value["metadata"]["namespace"] = namespace
    if spec is not None:
        value["spec"] = spec
    return value


def create(value):
    return json.loads(kube("create", "-f", "-", "-o", "json", value=json.dumps(value)).stdout)


def apply(value):
    # Keep credentials out of kubectl's last-applied-configuration annotation.
    return json.loads(kube("apply", "--server-side", "--field-manager=stage4-harness", "-f", "-", "-o", "json", value=json.dumps(value)).stdout)


def get(kind, name, namespace):
    return json.loads(kube("get", kind, name, "-n", namespace, "-o", "json").stdout)


def wait(name, check, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (RuntimeError, ValueError, OSError, KeyError):
            pass
        time.sleep(1)
    raise RuntimeError("Timed out: " + name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        return None


class TLSClient:
    def __init__(self, origin, ca_file):
        self.origin = origin.rstrip("/")
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def request(self, method, path, body=None, token=None, expected=(200,)):
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as response:
            if response.code not in expected:
                raise RuntimeError("HTTP " + str(response.code) + " for " + method + " " + path) from None
            raw = response.read(32 * 1024 * 1024 + 1)
            return response.code, json.loads(raw) if raw else None
        with response:
            if response.status not in expected:
                raise RuntimeError("Unexpected HTTP status")
            raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise RuntimeError("HTTP response too large")
            return response.status, json.loads(raw) if raw else None


class Forward:
    def __init__(self, task_dir, namespace, target, remote_port):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        task_dir = Path(task_dir)
        self.process = subprocess.Popen([str(task_dir / "kubectl"), "--kubeconfig", str(task_dir / "kubeconfig"),
                                         "-n", namespace, "port-forward", "--address=127.0.0.1", target,
                                         str(self.port) + ":" + str(remote_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
        try:
            wait("local service forward", self.listening, timeout=30)
        except BaseException:
            self.close()
            raise

    def listening(self):
        if self.process.poll() is not None:
            raise RuntimeError("Service forward stopped")
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                return True
        except OSError:
            return False

    def close(self):
        if self.process.poll() is not None:
            return
        try:
            isolated_group = os.name == "posix" and os.getpgid(self.process.pid) == self.process.pid
        except ProcessLookupError:
            return
        if isolated_group:
            # sudo/k0s may have a privileged child. Signal only this newly
            # created process group, rather than leaving its forward orphaned.
            result = subprocess.run(["sudo", "-n", "kill", "-TERM", "--", "-" + str(self.process.pid)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode and self.process.poll() is None:
                self.process.terminate()
        else:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if isolated_group:
                subprocess.run(["sudo", "-n", "kill", "-KILL", "--", "-" + str(self.process.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
