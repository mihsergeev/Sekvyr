"""Проверка адресов, по которым панель ходит САМА (вебхуки, зеркало Bot API).

Эти адреса задает человек в интерфейсе, а запрос уходит из контейнера панели -
изнутри периметра, откуда видно и базу, и соседние сервисы. Без проверки это
готовый SSRF: достаточно сохранить вебхук вида `http://127.0.0.1:8000/api/...`
или адрес соседнего контейнера, и панель постучится туда сама, а ответ вернется
в тексте ошибки. Схема `http` вдобавок отправила бы содержимое оповещений
открытым текстом через произвольный хост - а в оповещениях панели про секреты
идет речь о том, кто и к какому окружению обращался.

Проверяем при СОХРАНЕНИИ настройки, а не при каждой отправке: так человек видит
внятную ошибку сразу, а доставка оповещения не начинает зависеть от резолвера
ровно в тот момент, когда оповещение нужнее всего.

Остаточный риск - DNS rebinding: имя резолвится в публичный адрес при
сохранении и во внутренний позже. Для настройки, доступной только владельцу за
белым списком адресов, это приемлемо и записано в модели угроз.
"""

from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlparse


class UrlNotAllowed(ValueError):
    """Адрес не годится для исходящего запроса панели."""


# Общее адресное пространство провайдеров (RFC 6598): для ipaddress оно не
# частное, но и не интернет. В нем же метаданные Alibaba Cloud.
_SHARED = ipaddress.ip_network("100.64.0.0/10")
# Метаданные облаков вне link-local: Alibaba Cloud и IPv6 у AWS.
_METADATA = frozenset(ipaddress.ip_address(a) for a in ("100.100.100.200", "fd00:ec2::254"))


def _address(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Адрес из строки резолвера; IPv4 внутри IPv6 (::ffff:a.b.c.d) - как сам
    IPv4, иначе петля в такой записи проверялась бы как обычный IPv6."""
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _is_global(ip: str) -> bool:
    try:
        addr = _address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or addr in _SHARED
    )


def _port(parsed) -> int | None:
    try:
        return parsed.port
    except ValueError as exc:
        raise UrlNotAllowed("в адресе не разобрать порт") from exc


async def check_outbound_url(raw: str) -> None:
    """Бросает UrlNotAllowed, если по этому адресу панели ходить нельзя.
    Пустая строка - это "канал выключен", её пропускаем."""
    url = (raw or "").strip()
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UrlNotAllowed(
            "адрес должен начинаться с https:// — иначе оповещения уйдут открытым текстом"
        )
    host = parsed.hostname
    if not host:
        raise UrlNotAllowed("в адресе не разобрать имя хоста")
    port = _port(parsed)

    # Литеральный адрес проверяем без резолва.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not _is_global(host):
            raise UrlNotAllowed("адреса внутренних сетей недопустимы")
        return

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port or 443)
    except OSError as exc:
        raise UrlNotAllowed(f"имя «{host}» не резолвится: {exc.strerror or exc}") from exc
    if not infos:
        raise UrlNotAllowed(f"имя «{host}» не резолвится")
    # Все адреса имени должны быть публичными: имя, отдающее и публичный, и
    # внутренний адрес, иначе проезжает проверку по счастливой случайности.
    for info in infos:
        if not _is_global(info[4][0]):
            raise UrlNotAllowed(f"имя «{host}» указывает на внутренний адрес {info[4][0]}")


def _is_panel_side(ip: str) -> bool:
    """Адрес, где источника переноса быть не может, а ответ бывает ценен:
    петля (изнутри контейнера это сама панель), link-local с метаданными облака
    (169.254.169.254), служебные адреса облаков, широковещание."""
    try:
        addr = _address(ip)
    except ValueError:
        return True
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
        or addr in _METADATA
    )


async def check_source_url(raw: str) -> None:
    """Адрес Vault или Infisical, откуда переносят секреты.

    Источник почти всегда стоит внутри периметра, поэтому частные сети здесь
    разрешены, в отличие от вебхуков. Закрыто только то, где Vault быть не
    может. Имя, которое не резолвится, пропускаем: запрос по нему никуда не
    уйдет, а ошибку человеку понятнее увидеть ту, что вернет сам поход.
    Остаточный риск тот же, что у вебхуков, - DNS rebinding между проверкой и
    запросом. Тело чужого ответа панель при этом не пересказывает
    (importers._detail), так что такой обход дает только "есть ли там что-то".
    """
    parsed = urlparse((raw or "").strip())
    if parsed.scheme not in ("http", "https"):
        raise UrlNotAllowed("адрес источника должен начинаться с http:// или https://")
    host = parsed.hostname
    if not host:
        raise UrlNotAllowed("в адресе не разобрать имя хоста")
    port = _port(parsed)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, port or 443)
        except OSError:
            return
        addresses = [info[4][0] for info in infos]
    else:
        addresses = [host]
    if any(_is_panel_side(ip) for ip in addresses):
        raise UrlNotAllowed("адрес источника ведет в саму панель или к служебным адресам облака")
