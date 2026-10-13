"""Пересобрать кадры README одной командой.

Поднимает панель на временной SQLite-базе с демо-данными (docs/demo-seed.py),
раздает собранный фронтенд, снимает кадры и все за собой убирает. Настоящая
панель и настоящий фронтенд, меняется только содержимое базы.

    cd frontend && npm run build && npm i --no-save playwright-core && cd ..
    python docs/make-shots.py

Английские кадры ложатся в docs/img, русские в docs/img/ru.
"""

from __future__ import annotations

import http.server
import os
import secrets
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "frontend" / "dist"
API_PORT, WEB_PORT = 8111, 5111
# Панель живет на 127.0.0.1 ровно на время съемки, но пароль в исходниках
# выглядит как пароль: генерируем его на каждый запуск и никуда не пишем.
PASSWORD = secrets.token_urlsafe(18)
TMP = Path(tempfile.gettempdir()) / "sekvyr-shots"

PY = ROOT / "backend" / ".venv" / "Scripts" / "python.exe"
if not PY.exists():
    PY = ROOT / "backend" / ".venv" / "bin" / "python"
if not PY.exists():
    PY = Path(sys.executable)


class Handler(http.server.SimpleHTTPRequestHandler):
    """Статика и прокси /api: vite dev для съемки не нужен, слежение за файлами
    тоже."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIST), **kwargs)

    def log_message(self, *args):
        pass

    def _proxy(self, method):
        body = None
        if length := int(self.headers.get("Content-Length") or 0):
            body = self.rfile.read(length)
        req = urllib.request.Request(
            f"http://127.0.0.1:{API_PORT}{self.path}", data=body, method=method
        )
        for header in ("Authorization", "Content-Type", "Accept", "Accept-Language"):
            if header in self.headers:
                req.add_header(header, self.headers[header])
        try:
            with urllib.request.urlopen(req) as res:
                data, code, ctype = res.read(), res.status, res.headers.get("Content-Type")
        except urllib.error.HTTPError as exc:
            data, code, ctype = exc.read(), exc.code, exc.headers.get("Content-Type")
        self.send_response(code)
        self.send_header("Content-Type", ctype or "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api"):
            return self._proxy("GET")
        if "." not in self.path.split("?")[0].rsplit("/", 1)[-1]:
            self.path = "/index.html"  # маршруты SPA
        return super().do_GET()

    def do_POST(self):
        return self._proxy("POST")

    def do_PUT(self):
        return self._proxy("PUT")

    def do_PATCH(self):
        return self._proxy("PATCH")

    def do_DELETE(self):
        return self._proxy("DELETE")


def env_for(db: Path, data: Path) -> dict:
    return {
        **os.environ,
        "SEKVYR_DB_URL": f"sqlite+aiosqlite:///{db.as_posix()}",
        "SEKVYR_DATA_DIR": str(data),
        "SEKVYR_ADMIN_USER": "admin",
        "SEKVYR_ADMIN_PASSWORD": PASSWORD,
        "SEKVYR_JWT_SECRET": secrets.token_hex(32),
        "SEKVYR_TIMEZONE": "Europe/Berlin",
    }


def wait_api(timeout: int = 40) -> None:
    for _ in range(timeout * 4):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{API_PORT}/api/health", timeout=2):
                return
        except OSError:
            time.sleep(0.25)
    raise SystemExit("бэкенд не поднялся")


def main() -> None:
    if not DIST.exists():
        raise SystemExit("нет frontend/dist: соберите фронтенд, npm run build")
    shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True)

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    web = socketserver.ThreadingTCPServer(("127.0.0.1", WEB_PORT), Handler)
    threading.Thread(target=web.serve_forever, daemon=True).start()

    langs = sys.argv[1:] or ["en", "ru"]
    for lang in langs:
        db, data = TMP / f"demo-{lang}.db", TMP / f"data-{lang}"
        data.mkdir()
        env = env_for(db, data)
        print(f"[{lang}] база")
        subprocess.run(
            [str(PY), "-m", "alembic", "upgrade", "head"],
            cwd=ROOT / "backend", env=env, check=True, capture_output=True,
        )
        print(f"[{lang}] панель")
        api = subprocess.Popen(
            [str(PY), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
             "--port", str(API_PORT), "--log-level", "warning"],
            cwd=ROOT / "backend", env=env,
        )
        try:
            wait_api()
            print(f"[{lang}] демо-данные")
            subprocess.run(
                [str(PY), str(ROOT / "docs" / "demo-seed.py"),
                 "--url", f"http://127.0.0.1:{API_PORT}", "--db", str(db),
                 "--lang", lang, "--password", PASSWORD],
                env=env, check=True, cwd=ROOT,
            )
            print(f"[{lang}] кадры")
            subprocess.run(
                [shutil.which("node") or "node", str(ROOT / "frontend" / "scripts" / "shots.mjs")],
                cwd=ROOT / "frontend",
                env={**os.environ, "SHOTS_LANG": lang, "SHOTS_PASS": PASSWORD,
                     "SHOTS_BASE": f"http://127.0.0.1:{WEB_PORT}",
                     "SHOTS_OUT": str(ROOT / "docs" / "img")},
                check=True,
            )
        finally:
            api.terminate()
            api.wait(timeout=15)
    web.shutdown()
    shutil.rmtree(TMP, ignore_errors=True)
    print("готово:", ROOT / "docs" / "img")


if __name__ == "__main__":
    main()
