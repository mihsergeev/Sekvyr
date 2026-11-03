#!/usr/bin/env python3
"""Trial-only relay: hold ONE genuine upstream allow verdict, never invent one.

The selected request remains in memory. Only opaque request/identity pins are
written to the private state directory. No control API or request logging exists.
"""

import argparse
import json
import os
import re
from pathlib import Path
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_REVIEW = 4 << 20
MAX_RESPONSE = 256 << 10


def admission_path(path):
    # Kubernetes admission REST requests include this canonical deadline hint.
    # It is not an authorization input and cannot choose another upstream.
    return re.fullmatch(r"/admit(?:\?timeout=(?:[1-9]|[12][0-9]|30)s)?", path) is not None


def encoded(value):
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class Relay:
    def __init__(self, config, state_dir, ca_file):
        required = {"upstream_origin", "namespace", "name", "target_uid", "operator_username", "operator_sa_uid", "old_pod_uid", "kind", "api_version", "maximum_hold_seconds", "request_marker", "expected_resource_version"}
        if set(config) != required or any(not config[key] for key in required):
            raise ValueError("Exact relay pins required")
        parsed = urllib.parse.urlsplit(config["upstream_origin"])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("Fixed upstream HTTPS origin required")
        if not isinstance(config["maximum_hold_seconds"], (int, float)) or not 0 < config["maximum_hold_seconds"] <= 25:
            raise ValueError("Relay hold must fit the admission deadline")
        if (config["api_version"], config["kind"]) not in (("v1", "Secret"), ("apps/v1", "Deployment")):
            raise ValueError("Only pinned trial write kinds are supported")
        if re.fullmatch(r"[0-9a-f]{32}", config["request_marker"]) is None or not isinstance(config["expected_resource_version"], str) or not 1 <= len(config["expected_resource_version"]) <= 128:
            raise ValueError("Exact external request marker and resourceVersion required")
        self.config = dict(config)
        self.state = Path(state_dir)
        if not self.state.is_dir() or self.state.is_symlink():
            raise ValueError("Private relay state directory required")
        self.lock = threading.Lock()
        self.claimed = False
        context = ssl.create_default_context(cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def __repr__(self):
        return "<trial admission relay [redacted]>"

    def matches(self, request):
        config = self.config
        identity = request.get("userInfo", {})
        obj, old = request.get("object", {}), request.get("oldObject", {})
        meta, old_meta = obj.get("metadata", {}), old.get("metadata", {})
        version = obj.get("apiVersion")
        return (request.get("operation") == "UPDATE" and request.get("dryRun") is not True and request.get("namespace") == config["namespace"]
            and request.get("name") == config["name"] and obj.get("kind") == config["kind"]
            and old.get("kind") == config["kind"] and version == config["api_version"] and old.get("apiVersion") == version
            and meta.get("name") == config["name"] and meta.get("namespace") == config["namespace"]
            and old_meta.get("name") == config["name"] and old_meta.get("namespace") == config["namespace"]
            and meta.get("uid") == config["target_uid"] == old_meta.get("uid")
            and identity.get("username") == config["operator_username"] and identity.get("uid") == config["operator_sa_uid"]
            and identity.get("extra", {}).get("authentication.kubernetes.io/pod-uid") == [config["old_pod_uid"]]
            and meta.get("annotations", {}).get("stage6-trial-late-write") == config["request_marker"]
            and "stage6-trial-late-write" not in old_meta.get("annotations", {})
            and meta.get("resourceVersion") == old_meta.get("resourceVersion") == config["expected_resource_version"])

    def forward(self, raw):
        request = urllib.request.Request(self.config["upstream_origin"] + "/admit", data=raw, method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                result = response.read(MAX_RESPONSE + 1)
                if response.status != 200 or len(result) > MAX_RESPONSE:
                    raise RuntimeError("Upstream admission response rejected")
                return result
        except (urllib.error.URLError, OSError):
            raise RuntimeError("Upstream admission unavailable") from None

    @staticmethod
    def denied(uid):
        return encoded({"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": {
            "uid": uid, "allowed": False, "status": {"code": 403, "message": "Trial admission relay failed closed"}}})

    def handle(self, raw):
        uid = ""
        try:
            if not raw or len(raw) > MAX_REVIEW:
                return self.denied(uid)
            review = json.loads(raw)
            request = review["request"]
            uid = request["uid"]
            if review.get("apiVersion") != "admission.k8s.io/v1" or review.get("kind") != "AdmissionReview" or not isinstance(uid, str) or not uid:
                return self.denied("")
            # Always get the real admission decision FIRST. A mismatched or deny
            # decision can never be transformed into allow by this harness.
            verdict_raw = self.forward(raw)
            verdict = json.loads(verdict_raw)
            response = verdict.get("response", {})
            if response.get("uid") != uid or not isinstance(response.get("allowed"), bool):
                return self.denied(uid)
            if not response["allowed"] or not self.matches(request):
                return verdict_raw
            with self.lock:
                if self.claimed:
                    return self.denied(uid)
                self.claimed = True
            pin = {"request_uid": uid, "target_uid": self.config["target_uid"], "old_pod_uid": self.config["old_pod_uid"],
                   "upstream_allowed": True, "resource_version": request["object"]["metadata"]["resourceVersion"],
                   "request_marker": self.config["request_marker"]}
            fd = os.open(self.state / "held.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded(pin))
                stream.flush()
                os.fsync(stream.fileno())
            deadline = time.monotonic() + self.config["maximum_hold_seconds"]
            while time.monotonic() < deadline:
                release = self.state / "release"
                if release.is_file() and not release.is_symlink():
                    return verdict_raw
                time.sleep(0.02)
            return self.denied(uid)
        except Exception:
            return self.denied(uid)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if not admission_path(self.path):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAX_REVIEW:
                raise ValueError("bounds")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("truncated")
            response = self.server.relay.handle(raw)
        except Exception:
            response = Relay.denied("")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(response)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--upstream-ca", type=Path, required=True)
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--tls-key", required=True)
    parser.add_argument("--port", type=int, default=9443)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    relay = Relay(config, args.state_dir, args.upstream_ca)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.daemon_threads = True
    server.relay = relay
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.tls_cert, args.tls_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("FAIL trial admission relay startup")
        raise SystemExit(1)
