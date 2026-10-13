"""Состояние канала оповещений для пульса и стража.

Вебхук не проверить, не послав сообщения, поэтому о нем судим по последней
настоящей отправке. Раньше при одном вебхуке пульс всегда писал "неизвестно",
и мертвый приемник не замечал никто: ни панель, ни сторож.
"""

import httpx
import pytest

from app import alerts, heartbeat


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(alerts, "last_delivery", None)


def _transport(monkeypatch, status: int):
    original = httpx.AsyncClient

    def fake(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(status))
        return original(*args, **kwargs)

    monkeypatch.setattr(alerts.httpx, "AsyncClient", fake)


async def test_failed_webhook_marks_the_channel_broken(monkeypatch):
    _transport(monkeypatch, 502)
    errors = await alerts.send({"webhook": "https://hooks.example/x"}, "проверка")
    assert errors and errors[0].startswith("Вебхук")
    assert alerts.last_delivery is False
    # Telegram не настроен (getMe проверять нечего), но канал все равно сломан.
    assert heartbeat.channel_state(-1) == 0


async def test_delivered_webhook_marks_the_channel_alive(monkeypatch):
    _transport(monkeypatch, 200)
    assert await alerts.send({"webhook": "https://hooks.example/x"}, "проверка") == []
    assert alerts.last_delivery is True
    assert heartbeat.channel_state(-1) == 1


def test_channel_state_combinations(monkeypatch):
    assert heartbeat.channel_state(-1) == -1  # ничего не известно
    assert heartbeat.channel_state(1) == 1
    assert heartbeat.channel_state(0) == 0
    monkeypatch.setattr(alerts, "last_delivery", False)
    # Telegram отвечает на getMe, но настоящая отправка куда-то не дошла.
    assert heartbeat.channel_state(1) == 0
    monkeypatch.setattr(alerts, "last_delivery", True)
    assert heartbeat.channel_state(0) == 0
