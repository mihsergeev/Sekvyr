"""Synthetic app: reload two canaries from Secret volume or legacy agent file.

No values are logged. This fixture is not a general shell interpreter or SDK.
"""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import threading
import uuid

ROOT = Path("/secrets")
LOCK = threading.Lock()
STATE = {"generation": None, "value_digest": None, "reload_count": 0, "errors": 0,
    "boot_id": str(uuid.uuid4()), "pid": os.getpid(), "initial_loaded": False}


def assignments(raw):
    values = {}
    for token in shlex.split(raw.decode("utf-8"), comments=True, posix=True):
        key, separator, value = token.partition("=")
        if not separator or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None or key in values:
            raise ValueError("Invalid synthetic environment")
        values[key] = value
    return values


def read_values(mode):
    if mode == "volume":
        # Resolve the AtomicWriter directory ONCE: two independent symlink
        # resolutions could mix old/new keys during a Kubelet projection swap.
        projected = (ROOT / "..data").resolve(strict=True)
        if projected.parent != ROOT:
            raise ValueError("Invalid projection")
        return {name: (projected / name).read_bytes().decode("utf-8") for name in ("GENERATION", "DEMO_VALUE")}
    if mode != "file":
        raise ValueError("Invalid synthetic reader mode")
    with (ROOT / ".env").open("rb") as stream:
        raw = stream.read((1 << 20) + 1)
    if len(raw) > 1 << 20:
        raise ValueError("Synthetic environment too large")
    return assignments(raw)


def poll(mode):
    try:
        values = read_values(mode)
        generation, value = values["GENERATION"], values["DEMO_VALUE"]
        if re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", generation) is None:
            raise ValueError("Invalid synthetic generation")
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    except (OSError, ValueError, KeyError, UnicodeError):
        with LOCK:
            STATE["errors"] += 1
        return
    with LOCK:
        if STATE["initial_loaded"] and (STATE["generation"], STATE["value_digest"]) == (generation, digest):
            return
        if STATE["initial_loaded"]:
            STATE["reload_count"] += 1
        STATE.update(generation=generation, value_digest=digest, initial_loaded=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        with LOCK:
            value = dict(STATE)
        if self.path == "/status":
            code, body = 200, value
        elif self.path == "/health":
            code, body = (200 if value["initial_loaded"] else 503), {"initial_loaded": value["initial_loaded"]}
        else:
            code, body = 404, {}
        raw = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("volume", "file"), required=True)
    args = parser.parse_args()
    def watch():
        while True:
            poll(args.mode)
            threading.Event().wait(0.2)
    threading.Thread(target=watch, daemon=True).start()
    print(json.dumps({"event": "fixture_started", "boot_id": STATE["boot_id"], "pid": STATE["pid"]}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
