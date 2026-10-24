#!/usr/bin/env python3
"""Дописывает к версиям в backend/constraints.txt хеши файлов с PyPI.

Версия говорит, что ставить, а хеш - что именно скачалось. Без хеша образ
панели доверяет индексу и всему, что стоит между сборкой и индексом: тот же
номер версии мог приехать другим файлом. С хешами pip в образе работает в
режиме --require-hashes и отказывается ставить файл, которого здесь нет.

Хеши берутся для всех файлов версии (колеса под все платформы и исходники),
поэтому сборка на arm64 проверяется так же, как образ из GHCR.

Обычно хеши обновляет Dependabot вместе с версией. Руками - после правки
версий в constraints.txt (нужен интернет):
    python ops/pin_hashes.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "..", "backend", "constraints.txt")
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)")


def russian() -> bool:
    choice = os.environ.get("SEKVYR_LANG", "").strip().lower()
    if choice in ("ru", "en"):
        return choice == "ru"
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(name, "")
        if value:
            return value.lower().startswith("ru")
    return False


RU = russian()


def t(ru: str, en: str) -> str:
    return ru if RU else en


def logical_lines(text: str) -> list[str]:
    """Строки с продолжением через обратный слеш склеиваются в одну."""
    out: list[str] = []
    buf = ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return out


def hashes(name: str, version: str) -> list[str]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as resp:
        files = json.load(resp)["urls"]
    found = sorted({f["digests"]["sha256"] for f in files if f.get("digests", {}).get("sha256")})
    if not found:
        raise SystemExit(t(f"на PyPI нет файлов {name}=={version}", f"PyPI has no files for {name}=={version}"))
    return found


def main() -> int:
    with open(PATH, encoding="utf-8") as fh:
        text = fh.read()
    out: list[str] = []
    for line in logical_lines(text):
        match = PIN.match(line.strip())
        if not match:
            out.append(line.rstrip())
            continue
        name, version = match.groups()
        found = hashes(name, version)
        out.append(f"{name}=={version} \\")
        out += [f"    --hash=sha256:{digest} \\" for digest in found[:-1]]
        out.append(f"    --hash=sha256:{found[-1]}")
        print(f"{name}=={version}: {len(found)}")
    with open(PATH, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(out).rstrip("\n") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
