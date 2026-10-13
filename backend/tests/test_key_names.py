"""Имена ключей, которые сломают файл окружения на сервере.

Пробел docker compose не принимает вовсе ("key cannot contain a space"), и
приложение на ноде перестает подниматься. Такие имена приходили руками,
импортом .env и переносом из Vault. Остальное (точки, дефисы, кириллица)
compose принимает, и такие имена остаются разрешенными.
"""

import pytest

from app import secrets_store


@pytest.mark.parametrize("name", ["DB_URL", "spring.datasource.url", "dash-key", "ключ", "1START"])
def test_names_compose_reads_are_allowed(name):
    secrets_store.check_name(name)


@pytest.mark.parametrize("name", ["", "KEY WITH SPACE", "TAB\tKEY", "A=B", "LINE\nBREAK", "#COMMENT"])
def test_names_that_break_the_file_are_refused(name):
    with pytest.raises(secrets_store.BadName):
        secrets_store.check_name(name)


@pytest.mark.parametrize(
    "name", ["DB_\u202eDROWSSAP", "ZERO\u200bWIDTH", "C1\x9bKEY", "BOM\ufeffINSIDE", "ISO\u2066LATE"]
)
def test_invisible_characters_are_refused(name):
    """В файле такие имена живут, но в интерфейсе и журнале выглядят как другие."""
    with pytest.raises(secrets_store.BadName):
        secrets_store.check_name(name)


def test_import_strips_bom_and_refuses_bad_names():
    rows = secrets_store.parse_env("\ufeffDB_URL=x\nOTHER=y\n")
    assert [name for _path, name, _value in rows] == ["DB_URL", "OTHER"]
    with pytest.raises(ValueError):
        secrets_store.parse_env("GOOD=1\nBAD NAME=2\n")


async def test_api_refuses_a_bad_name_with_400(client, owner_headers, env_id, unsealed):
    res = await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB PASSWORD", "value": "x"},
    )
    assert res.status_code == 400, res.text
    assert "имя" in res.json()["detail"]
