#!/usr/bin/env python3
"""Готовит ЧИСТУЮ панель к живой проверке прав: заводит сейф и отпирает её.

Только для проверок на пустой базе - в CI и при локальной отладке. На панели,
где уже есть секреты, скрипт ничего не делает: заведение сейфа необратимо, и
случайно запускать его на рабочей установке нельзя.

    python ops/ci_bootstrap.py --url http://127.0.0.1:8000 --password '...'
"""

from __future__ import annotations

import argparse
import sys

import httpx


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--owner", default="admin")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    c = httpx.Client(base_url=args.url.rstrip("/"), timeout=30)
    token = c.post(
        "/api/auth/login", json={"username": args.owner, "password": args.password}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    status = c.get("/api/vault/status", headers=headers).json()
    if status["initialized"]:
        print("сейф уже заведён — ничего не делаю")
        return 0

    res = c.post("/api/vault/init", headers=headers, json={"mode": "env"})
    if res.status_code != 200:
        print("не удалось завести сейф:", res.text)
        return 1
    print("сейф заведён, панель отперта")
    return 0


if __name__ == "__main__":
    sys.exit(main())
