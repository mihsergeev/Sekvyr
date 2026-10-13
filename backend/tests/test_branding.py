"""Свой логотип: что принимается, что отвергается и кому это доступно."""

import base64

import httpx

from tests.conftest import login

PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmM"
    "IQAAAABJRU5ErkJggg=="
)
SVG_OK = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
    b'<rect width="10" height="10" fill="#111111"/></svg>'
)
SVG_SCRIPT = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
SVG_ONLOAD = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>'
SVG_REMOTE = (
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
    b'<image href="https://evil.example/x.png"/></svg>'
)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def _save(client, headers, **body):
    payload = {"plate": "auto", "title": "", **body}
    return await client.post("/api/branding/save", json=payload, headers=headers)


async def test_default_is_standard_logo(client: httpx.AsyncClient):
    # Без входа: экран входа рисуется до авторизации, значит ручка открытая.
    res = await client.get("/api/branding")
    assert res.status_code == 200
    assert res.json()["logo"] is False
    assert (await client.get("/api/branding/logo")).status_code == 404
    assert (await client.get("/api/branding/logo-dark")).status_code == 404


async def test_png_roundtrip(client: httpx.AsyncClient, owner_headers):
    res = await _save(client, owner_headers, data=b64(PNG_1PX), title="Ромашка")
    assert res.status_code == 200, res.text
    assert res.json()["logo"] is True and res.json()["title"] == "Ромашка"

    logo = await client.get("/api/branding/logo")
    assert logo.status_code == 200
    assert logo.headers["content-type"].startswith("image/png")
    # Чужой файл отдаем в песочнице и без угадывания типа.
    assert "sandbox" in logo.headers["content-security-policy"]
    assert logo.headers["x-content-type-options"] == "nosniff"
    assert logo.content == PNG_1PX
    # Своей версии для темного фона нет.
    assert (await client.get("/api/branding/logo-dark")).status_code == 404


async def test_dark_variant_and_settings(client: httpx.AsyncClient, owner_headers):
    res = await _save(client, owner_headers, data=b64(SVG_OK))
    assert res.status_code == 200, res.text
    assert res.json()["dark_logo"] is False

    # Вариант для темной темы - без повторной заливки основного файла.
    res = await _save(client, owner_headers, dark=b64(PNG_1PX))
    assert res.json()["logo"] is True and res.json()["dark_logo"] is True
    dark = await client.get("/api/branding/logo-dark")
    assert dark.status_code == 200 and dark.content == PNG_1PX
    assert "sandbox" in dark.headers["content-security-policy"]
    assert (await client.get("/api/branding/logo")).content == SVG_OK

    # Только настройки: файлы остаются.
    res = await _save(client, owner_headers, plate="never", title="Ромашка")
    assert res.status_code == 200
    assert res.json()["plate"] == "never" and res.json()["dark_logo"] is True

    # Убрать вариант для темной темы.
    res = await _save(client, owner_headers, dark_remove=True)
    assert res.json()["dark_logo"] is False
    assert (await client.get("/api/branding/logo-dark")).status_code == 404


async def test_versions_grow(client: httpx.AsyncClient, owner_headers):
    first = (await _save(client, owner_headers, data=b64(PNG_1PX))).json()["version"]
    second = (await _save(client, owner_headers, title="x")).json()["version"]
    third = (await client.post("/api/branding/reset", headers=owner_headers)).json()["version"]
    assert first < second < third


async def test_reset_removes_both_files(client: httpx.AsyncClient, owner_headers):
    await _save(client, owner_headers, data=b64(PNG_1PX), dark=b64(SVG_OK), title="Ромашка")
    res = await client.post("/api/branding/reset", headers=owner_headers)
    assert res.json()["logo"] is False and res.json()["dark_logo"] is False
    assert res.json()["title"] == ""
    assert (await client.get("/api/branding/logo")).status_code == 404
    assert (await client.get("/api/branding/logo-dark")).status_code == 404


async def test_rejects_active_svg(client: httpx.AsyncClient, owner_headers):
    # Файл отдается с адреса панели, поэтому активное содержимое режем на входе,
    # и в основном файле, и в варианте для темной темы.
    for payload in (SVG_SCRIPT, SVG_ONLOAD, SVG_REMOTE):
        res = await _save(client, owner_headers, data=b64(payload))
        assert res.status_code == 400, payload
    assert (await client.get("/api/branding")).json()["logo"] is False

    await _save(client, owner_headers, data=b64(SVG_OK))
    res = await _save(client, owner_headers, dark=b64(SVG_SCRIPT))
    assert res.status_code == 400
    assert (await client.get("/api/branding")).json()["dark_logo"] is False


async def test_rejects_non_image_and_oversize(client: httpx.AsyncClient, owner_headers):
    # Тип определяется по содержимому: назваться картинкой недостаточно.
    res = await _save(client, owner_headers, data=b64(b"#!/bin/sh\nrm -rf /\n"))
    assert res.status_code == 400
    res = await _save(client, owner_headers, data=b64(PNG_1PX + b"\x00" * (512 * 1024)))
    assert res.status_code == 413


async def test_settings_need_a_logo(client: httpx.AsyncClient, owner_headers):
    res = await _save(client, owner_headers, title="Ромашка")
    assert res.status_code == 400


async def test_only_owner_changes_logo(client: httpx.AsyncClient, owner_headers):
    created = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "lead", "password": "member-pass-2026", "role": "maintainer"},
    )
    assert created.status_code == 201, created.text
    lead = await login(client, "lead", "member-pass-2026")

    assert (await client.get("/api/branding", headers=lead)).status_code == 200
    assert (await _save(client, lead, data=b64(PNG_1PX))).status_code == 403
    assert (await client.post("/api/branding/reset", headers=lead)).status_code == 403


async def test_logo_changes_are_audited(client: httpx.AsyncClient, owner_headers):
    await _save(client, owner_headers, data=b64(PNG_1PX))
    await client.post("/api/branding/reset", headers=owner_headers)
    res = await client.get("/api/audit", headers=owner_headers)
    assert res.status_code == 200, res.text
    actions = [row["action"] for row in res.json()["entries"]]
    assert "branding_set" in actions and "branding_reset" in actions


async def test_svg_references_only_inside_the_file(client: httpx.AsyncClient, owner_headers):
    """Ссылки - только на #id внутри файла и на встроенную картинку. Обходы
    прежнего фильтра (другие теги, &#...;, префикс пространства имен, url() в
    стилях, анимация href) - отказ; обычные логотипы проходят."""
    head = b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
    bad = [
        b'<a href="https://evil.example/">x</a>',
        b'<feImage href="https://evil.example/x.png"/>',
        b'<use href="data:image/svg+xml;base64,AAAA"/>',
        b'<image href="&#104;ttps://evil.example/x.png"/>',
        b'<a href="&#106;avascript:alert(1)">x</a>',
        b'<s:script xmlns:s="http://www.w3.org/2000/svg">alert(1)</s:script>',
        b"<style>@import url(https://evil.example/x.css);</style>",
        b'<rect style="fill:url(https://evil.example/x)"/>',
        b'<set attributeName="href" to="x"/>',
    ]
    for part in bad:
        res = await _save(client, owner_headers, data=b64(head + part + b"</svg>"))
        assert res.status_code == 400, part
    good = (
        head
        + b'<defs><linearGradient id="g"/></defs><rect fill="url(#g)"/><use xlink:href="#g"/>'
        + b'<image href="data:image/png;base64,' + b64(PNG_1PX).encode() + b'"/>'
        + b"<style>.a{fill:#fff}</style></svg>"
    )
    res = await _save(client, owner_headers, data=b64(good))
    assert res.status_code == 200, res.text


def test_svg_filter_is_linear():
    """Полмегабайта без единой > прежний фильтр считал около двух минут."""
    import time

    from app.api.branding import _SVG_BAD

    start = time.monotonic()
    _SVG_BAD.search(b"<svg>" + b"<use " * 100_000)
    assert time.monotonic() - start < 2
