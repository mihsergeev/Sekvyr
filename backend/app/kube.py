"""Проверка ServiceAccount-токена Kubernetes.

Под предъявляет свой projected-токен, панель проверяет подпись ключами кластера
и по namespace с именем ServiceAccount находит машинную личность. Статического
секрета на ноде при этом нет вовсе, и это главная причина всей затеи с
кластерами.

Почему JWKS, а не TokenReview: панели тогда не нужны учетные данные кластера, а
кластеру - доступность панели изнутри. Ключи кластера вписываются один раз
(`kubectl get --raw /openid/v1/jwks`), и их смена означает обновление записи в
панели - событие редкое и заметное.
"""

from __future__ import annotations

import json

import jwt
from jwt import PyJWK

# Расхождение часов кластера и панели: свежий токен пода с iat на пару секунд
# впереди иначе отклонялся бы.
LEEWAY = 60
# Дольше суток токен пода не живет: kubelet выписывает projected-токены на час и
# обновляет их сам. Подпись проверяется без обращения к кластеру, и удаления
# пода панель не видит, поэтому токен на год (kubectl create token --duration)
# был бы снова статическим секретом - тем, от чего все это избавляет.
MAX_LIFETIME = 24 * 3600


class TokenError(Exception):
    """Токен не принят. Причина внутри - она уходит в журнал, но не наружу:
    подробный отказ подсказывает, какая часть подделки уже удалась."""


def load_keys(jwks_text: str) -> dict[str, PyJWK]:
    try:
        data = json.loads(jwks_text)
    except json.JSONDecodeError as exc:
        raise TokenError(f"ключи кластера не разобрались: {exc}") from exc
    # JSON разбирается и как true, и как список: такой "JWKS" ронял создание
    # кластера с 500 (нашел фаззинг схемы).
    if not isinstance(data, dict) or not isinstance(data.get("keys", []), list):
        raise TokenError("ключи кластера не разобрались: нужен объект JWKS с массивом keys")
    keys: dict[str, PyJWK] = {}
    for raw in data.get("keys", []):
        if not isinstance(raw, dict):
            continue
        try:
            key = PyJWK(raw)
        except Exception:  # noqa: BLE001 - чужой ключ не должен ронять проверку
            continue
        # Только ключи с открытой половиной: общий секрет в JWKS кластера
        # подписал бы токен кем угодно, кто его видел.
        if key.key_id and key.algorithm_name[:2] in ("RS", "PS", "ES", "Ed"):
            keys[key.key_id] = key
    if not keys:
        raise TokenError("в ключах кластера нет ни одного пригодного")
    return keys


def verify(token: str, *, jwks_text: str, issuer: str, audience: str) -> tuple[str, str]:
    """Проверяет токен и возвращает (namespace, serviceaccount).

    Проверяется все сразу: подпись ключом кластера, издатель, audience и срок.
    Audience обязателен: токен, выписанный "для kubernetes", к панели подходить
    не должен - под просит отдельный, и такой токен бесполезен где-то еще.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenError(f"заголовок токена не разобрался: {exc}") from exc

    keys = load_keys(jwks_text)
    key = keys.get(header.get("kid", ""))
    if key is None:
        raise TokenError("ключ с таким kid кластеру не принадлежит")

    try:
        # Алгоритм берется у ключа кластера, а не из заголовка токена: заголовок
        # пишет тот, кто токен предъявляет.
        claims = jwt.decode(
            token,
            key.key,
            algorithms=[key.algorithm_name],
            issuer=issuer,
            audience=audience,
            leeway=LEEWAY,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        lifetime = int(claims["exp"]) - int(claims["iat"])
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        # Не только PyJWTError: на ключе не того типа библиотека бросает
        # TypeError, и отказ без учетки превращался в 500 мимо лимитера.
        raise TokenError(f"токен не прошёл проверку: {exc}") from exc
    if lifetime > MAX_LIFETIME:
        raise TokenError("токен живет дольше суток: это уже статический секрет")

    # Современный kubernetes кладет разбор в отдельный блок, но `sub` есть
    # всегда и выглядит одинаково: system:serviceaccount:<ns>:<имя>.
    kube = claims.get("kubernetes.io") or {}
    namespace = str(kube.get("namespace", ""))
    account = str((kube.get("serviceaccount") or {}).get("name", ""))
    if not namespace or not account:
        sub = str(claims.get("sub", ""))
        parts = sub.split(":")
        if len(parts) != 4 or parts[0] != "system" or parts[1] != "serviceaccount":
            raise TokenError("это не токен ServiceAccount")
        namespace, account = parts[2], parts[3]
    return namespace, account
