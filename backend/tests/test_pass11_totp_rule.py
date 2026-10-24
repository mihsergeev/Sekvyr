"""Отказ по праву, которое действует только со вторым фактором (1.0.1).

Падает на 1.0.0: отказ говорил "нет права", хотя право было и не хватало
только второго фактора.
"""

from tests.conftest import login
from tests.pass11_helpers import PASS, _policy, _put, _user


# --- 6. право со вторым фактором -------------------------------------------


async def test_refusal_names_missing_second_factor(client, owner_headers, env_id):
    oh = owner_headers
    did = await _user(client, oh, "dev", "developer")
    await _policy(
        client, oh, subject_type="user", subject_id=did, environment_id=env_id,
        actions=["list", "read", "write"], require_2fa=True,
    )
    dev = await login(client, "dev", PASS)
    res = await _put(client, dev, env_id, "A", "1")
    assert res.status_code == 403, res.text
    assert res.json()["detail"] == (
        'Право "менять значения" здесь действует только со вторым фактором: '
        "включите его в меню своей учетной записи"
    )


async def test_refusal_without_any_right_is_unchanged(client, owner_headers, env_id):
    oh = owner_headers
    await _user(client, oh, "dev", "developer")
    dev = await login(client, "dev", PASS)
    res = await _put(client, dev, env_id, "A", "1")
    assert res.status_code == 403
    assert res.json()["detail"].startswith("Нет права «")
