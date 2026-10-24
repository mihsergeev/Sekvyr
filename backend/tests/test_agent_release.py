"""ops/agent_release.py: описание версии агента, подписанное по чужим хешам.

Сборка и подпись бывают на разных машинах, и тогда в описание попадает только
то, что передали через --digest. Размер не подписывается и никем не читается,
но описание не должно утверждать про бинарь то, чего про него не знают.
"""

import base64
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

A = "a" * 64
B = "b" * 64


def _release():
    """Загружаем ops/agent_release.py как модуль: он живет вне пакета намеренно."""
    path = Path(__file__).resolve().parents[2] / "ops" / "agent_release.py"
    spec = importlib.util.spec_from_file_location("agent_release", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def release(tmp_path, monkeypatch):
    """Модуль с каталогом агента во временной папке и свежим ключом: подпись
    в тесте не должна задеть настоящие manifest.json и pubkey.txt."""
    module = _release()
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "VERSION").write_text("9.9.9\n", encoding="utf-8")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "AGENT", agent)
    monkeypatch.setattr(module, "MANIFEST", agent / "manifest.json")
    monkeypatch.setattr(module, "PUBKEY", agent / "pubkey.txt")
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    monkeypatch.setenv("SEKVYR_AGENT_KEY", base64.b64encode(key).decode())
    return module


def _files(release) -> dict:
    return json.loads(release.MANIFEST.read_text(encoding="utf-8"))["files"]


def test_digest_without_size_has_no_size(release):
    # Раньше здесь стоял "size": 0, то есть описание говорило, что бинарь пустой.
    release.sign(release.digests_from([f"amd64={A}", f"arm64={B}"]))
    assert _files(release) == {"amd64": {"sha256": A}, "arm64": {"sha256": B}}
    assert release.verify() == 0


def test_digest_with_size_keeps_it(release):
    release.sign(release.digests_from([f"amd64={A.upper()}:7340032", f"arm64={B}"]))
    assert _files(release) == {"amd64": {"sha256": A, "size": 7340032}, "arm64": {"sha256": B}}
    assert release.verify() == 0


@pytest.mark.parametrize(
    "item",
    [f"amd64={A}:7k", f"amd64={A}:-1", f"mips={A}", f"amd64={A[:-1]}", "amd64=" + "g" * 64],
)
def test_bad_digest_is_rejected(release, item):
    with pytest.raises(SystemExit):
        release.digests_from([item])
