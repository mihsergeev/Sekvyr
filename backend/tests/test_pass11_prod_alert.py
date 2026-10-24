"""Подтвержденная правка прода уходит оповещением (1.0.1).

Падает на 1.0.0: оповещение уходило, когда правку предлагали, а когда значение
в проде действительно менялось, при подтверждении, - нет.
"""

from app import config
from tests.conftest import login
from tests.pass11_helpers import (
    PASS,
    _approve,
    _capture_alerts,
    _policy,
    _project_id,
    _put,
    _threshold,
    _user,
)


# --- 4. подтвержденная правка прода ----------------------------------------


async def test_approved_change_in_prod_is_announced(client, owner_headers, env_id, monkeypatch):
    monkeypatch.setenv("SEKVYR_ALERT_ON_ENVS", "prod")
    config.get_settings.cache_clear()
    sent = _capture_alerts(monkeypatch)
    oh = owner_headers
    pid = await _project_id(client, oh)
    assert (await _put(client, oh, env_id, "API_KEY", "real")).status_code == 200
    await _threshold(client, oh, 30)
    did = await _user(client, oh, "dev", "developer")
    await _policy(
        client, oh, subject_type="user", subject_id=did, project_id=pid,
        actions=["list", "read", "write"],
    )
    dev = await login(client, "dev", PASS)
    proposal = await _put(client, dev, env_id, "API_KEY", "new")
    sent.clear()
    res = await _approve(client, oh, env_id, "API_KEY", proposal.json()["version"])
    assert res.status_code == 200, res.text
    assert len(sent) == 1, sent
    assert "подтвердил правку от dev" in sent[0] and "API_KEY" in sent[0]
