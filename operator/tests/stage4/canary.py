"""Disposable test pod: observe projected Secret changes without leaking values."""

import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path("/secrets")
LOCK = threading.Lock()
STATE = {
    "generation": None, "digest": None, "reload_count": 0,
    "boot_id": str(uuid.uuid4()), "pid": os.getpid(), "errors": 0,
    "initial_loaded": False, "loaded_at": None,
}


def poll():
    try:
        # Resolve AtomicWriter's directory once, otherwise two independent
        # symlink resolutions could combine old and new projected revisions.
        projected = (ROOT / "..data").resolve(strict=True)
        if projected.parent != ROOT:
            raise ValueError("invalid projection")
        generation_raw = (projected / "GENERATION").read_bytes()
        value = (projected / "DEMO_VALUE").read_bytes()
        generation = generation_raw.decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", generation):
            raise ValueError("invalid generation")
        digest = hashlib.sha256(len(generation_raw).to_bytes(8, "big") + generation_raw + value).hexdigest()
    except (OSError, ValueError):
        with LOCK:
            STATE["errors"] += 1
        return
    with LOCK:
        if STATE["digest"] == digest:
            return
        if STATE["initial_loaded"]:
            STATE["reload_count"] += 1
        STATE.update(generation=generation, digest=digest, initial_loaded=True,
                     loaded_at=datetime.now(timezone.utc).isoformat())


def watch():
    while True:
        poll()
        threading.Event().wait(0.2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        with LOCK:
            status = dict(STATE)
        if self.path == "/status":
            code, body = 200, status
        elif self.path == "/health":
            code = 200 if status["initial_loaded"] else 503
            body = {"initial_loaded": status["initial_loaded"]}
        else:
            code, body = 404, {"error": "not_found"}
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass


if __name__ == "__main__":
    threading.Thread(target=watch, daemon=True).start()
    print(json.dumps({"event": "canary_started", "boot_id": STATE["boot_id"]}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
