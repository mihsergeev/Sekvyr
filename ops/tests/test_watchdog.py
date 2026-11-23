"""Run the host watchdog against an isolated heartbeat and HTTP receiver."""

import http.server
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs


WATCHDOG = Path(__file__).resolve().parents[1] / "panel-watchdog.sh"


@unittest.skipUnless(os.name == "posix" and shutil.which("curl"), "Linux and curl required")
class WatchdogTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.heartbeat = self.data / "heartbeat"
        self.state = self.data / "watchdog.state"

    def receiver(self, statuses):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                requests.append((self.path, body))
                self.send_response(statuses[min(len(requests), len(statuses)) - 1])
                self.end_headers()
                self.wfile.write(b"synthetic receipt")

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}", requests

    def run_watchdog(self, **values):
        fields = {"ts": int(time.time()), "sealed": 1, **values}
        self.heartbeat.write_text("".join(f"{key}={value}\n" for key, value in fields.items()))
        return subprocess.run(
            ["sh", str(WATCHDOG)], capture_output=True, text=True, timeout=7,
            env={**os.environ, "SEKVYR_APP": str(self.root), "SEKVYR_WATCHDOG_STATE": str(self.state),
                 "SEKVYR_HEARTBEAT": str(self.heartbeat), "SEKVYR_LANG": "en", "SEKVYR_WD_STRIKES": "1"},
        )

    def test_state_write_does_not_follow_symlink(self):
        canary = self.root / "host-canary"
        canary.write_text("keep\n")
        self.state.symlink_to(canary)
        result = self.run_watchdog()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(canary.read_text(), "keep\n")
        self.assertFalse(self.state.is_symlink())

    def test_heartbeat_cannot_supply_curl_options(self):
        receiver, requests = self.receiver([200])
        canary = self.root / "host-canary"
        canary.write_text("keep\n")
        config = self.data / "curl-config"
        config.write_text(f'url = "{receiver}/injected"\noutput = "{canary}"\n')
        result = self.run_watchdog(webhook=f"-K{config}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(canary.read_text(), "keep\n")
        self.assertEqual(requests, [])

    def test_retries_failed_delivery_then_deduplicates(self):
        receiver, requests = self.receiver([503, 200, 200])
        for _ in range(3):
            result = self.run_watchdog(webhook=f"{receiver}/hook")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([path for path, _ in requests], ["/hook", "/hook"])
        self.assertIn(b"SEALED", requests[-1][1])

    def test_telegram_retries_recovery_until_receiver_accepts_it(self):
        receiver, requests = self.receiver([200, 302, 200])
        telegram = {"tg_api": receiver, "tg_token": "synthetic:fixture", "tg_chat": "test room"}
        self.assertEqual(self.run_watchdog(**telegram).returncode, 0)
        for _ in range(3):
            self.assertEqual(self.run_watchdog(sealed=0, **telegram).returncode, 0)
        self.assertEqual([path for path, _ in requests], ["/botsynthetic:fixture/sendMessage"] * 3)
        forms = [parse_qs(body.decode()) for _, body in requests]
        self.assertTrue(all(form["chat_id"] == ["test room"] for form in forms))
        self.assertIn("SEALED", forms[0]["text"][0])
        self.assertIn("back to normal", forms[-1]["text"][0])


if __name__ == "__main__":
    unittest.main()
