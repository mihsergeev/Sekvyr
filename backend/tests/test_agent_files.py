"""Раздача агента: скрипт установки, подписанное описание и бинарь.

Эти три маршрута - единственная дорога агента на новую ноду. Тестов на них не
было, и скрипт установки почти месяц отвечал 500: при правке соседней функции
пропало имя каталога, а заметила это только установка на чистой машине.
"""

import hashlib
import json

from app import config


def _agent_dir(tmp_path, monkeypatch, binary=b"agent-binary", signed=b"agent-binary"):
    root = tmp_path / "agent"
    root.mkdir()
    (root / "install.sh").write_text('#!/bin/sh\nPANEL="${SEKVYR_URL:-}"\n', encoding="utf-8")
    (root / "sekvyr-linux-amd64").write_bytes(binary)
    manifest = {
        "version": "1.0.0",
        "files": {"amd64": {"sha256": hashlib.sha256(signed).hexdigest(), "size": 0}},
        "signature": "",
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("SEKVYR_AGENT_DIR", root.as_posix())
    config.get_settings.cache_clear()


async def test_install_script_carries_the_panel_address(client, tmp_path, monkeypatch):
    _agent_dir(tmp_path, monkeypatch)
    res = await client.get("/api/v1/machine/install.sh")
    assert res.status_code == 200, res.text
    # Команду из панели копируют целиком: адрес панели уже вписан в скрипт.
    assert 'PANEL="${SEKVYR_URL:-http://test}"' in res.text


async def test_manifest_and_binary_are_served(client, tmp_path, monkeypatch):
    _agent_dir(tmp_path, monkeypatch)
    res = await client.get("/api/v1/machine/agent/manifest")
    assert res.status_code == 200, res.text
    assert res.json()["version"] == "1.0.0"
    res = await client.get("/api/v1/machine/agent", params={"arch": "amd64"})
    assert res.status_code == 200, res.text
    assert res.content == b"agent-binary"


async def test_binary_that_does_not_match_the_signature_is_not_served(
    client, tmp_path, monkeypatch
):
    _agent_dir(tmp_path, monkeypatch, binary=b"something else")
    res = await client.get("/api/v1/machine/agent", params={"arch": "amd64"})
    assert res.status_code == 500
