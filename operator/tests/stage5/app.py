"""Test app reads its environment once; an update requires a new pod process."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import uuid

GENERATION = os.environ["GENERATION"]
if not re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", GENERATION):
    raise ValueError("Invalid test generation")
STATUS = {"generation": GENERATION, "boot_id": str(uuid.uuid4()), "pid": os.getpid(),
          "value_digest": hashlib.sha256(os.environ["DEMO_VALUE"].encode()).hexdigest()}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        code, body = (200, STATUS) if self.path == "/status" else ((200, {"ready": True}) if self.path == "/health" else (404, {}))
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
    print(json.dumps({"event": "app_started", "boot_id": STATUS["boot_id"], "pid": STATUS["pid"]}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
