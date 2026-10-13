"""Аварийный архив: все значения панели одним запечатанным файлом.

Зачем он нужен. Бэкап базы восстанавливает панель, но только вместе с корневым
ключом: без него дамп - это шифротекст. Аварийный архив отвечает на другой
вопрос - "панели нет, ключа нет, а прод надо поднять сейчас". Внутри лежат
готовые значения по окружениям, снаружи - пароль, который знает владелец.

Честно про риск: это единственный файл в системе, где секреты лежат все сразу и
без корневого ключа. Поэтому:

  * собирает его только владелец и только со вторым фактором;
  * пароль задается при сборке и нигде не сохраняется;
  * каждая сборка пишется в журнал и уходит в оповещения - "кто-то собрал
    архив" должно быть событием, которое видно, а не деталью;
  * панель не хранит архив у себя: файл отдается в ответ и живет дальше там,
    куда его положил человек.

Читает архив `ops/breakglass.py`: одна команда печатает `.env` нужного
окружения. Панель для этого не нужна - в том и смысл.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto, envkeys, sealedfile, secrets_store
from app.models import Environment, Project
from app.sealbox import SealBox

KIND = "emergency"


async def collect(session: AsyncSession, box: SealBox) -> dict:
    """Снимок всех значений: проекты, окружения, итоговые ключи.

    Значения берутся итоговые, с наследованием, - те же, что панель отдала бы
    приложению. В аварии нужен рабочий `.env`, а не карта того, где какой ключ
    был определен; откуда именно приехало значение, видно в поле `from`.
    """
    projects_out: list[dict] = []
    projects = await session.scalars(select(Project).order_by(Project.group_slug, Project.slug))
    for project in projects:
        envs = await session.scalars(
            select(Environment)
            .where(Environment.project_id == project.id)
            .order_by(Environment.name)
        )
        envs = list(envs)
        names = {env.id: env.name for env in envs}
        envs_out: list[dict] = []
        for env in envs:
            values: list[dict] = []
            if project.e2e:
                # Проект с шифрованием в браузере: сервер видит только блобы, и
                # класть их в аварийный архив бессмысленно - открыть их сможет
                # лишь тот, кто помнит пароль проекта. Пишем об этом прямо,
                # чтобы в день аварии не искать "почему тут пусто".
                envs_out.append(
                    {
                        "name": env.name,
                        "parent": names.get(env.parent_id or 0, ""),
                        "values": [],
                        "note": "шифрование в браузере: значения знает только "
                        "владелец пароля проекта",
                    }
                )
                continue
            lost: list[str] = []
            for secret, level in await secrets_store.effective_list(session, env.id):
                try:
                    value = await secrets_store.read_if_alive(session, box, secret)
                except (envkeys.MissingKeyError, crypto.DecryptionError):
                    # В аварийном архиве одно нечитаемое значение не должно
                    # стоить всех остальных: оно называется отдельно.
                    lost.append(f"{secret.path}:{secret.name}")
                    continue
                if value is None:
                    continue
                values.append(
                    {
                        "path": secret.path,
                        "name": secret.name,
                        "value": value,
                        # Пусто - значение свое; иначе имя окружения-источника.
                        "from": "" if level == env.id else names.get(level, ""),
                    }
                )
            out_env = {
                "name": env.name,
                "parent": names.get(env.parent_id or 0, ""),
                "values": values,
            }
            if lost:
                # Отдельным полем, а не note: note у breakglass значит
                # "шифрование в браузере, значений нет".
                out_env["unreadable"] = lost
            envs_out.append(out_env)
        projects_out.append(
            {
                "group": project.group_slug,
                "slug": project.slug,
                "title": project.title,
                "environments": envs_out,
            }
        )
    return {
        "panel": "Sekvyr",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "projects": projects_out,
    }


def counts(snapshot: dict) -> tuple[int, int, int]:
    """Сколько всего проектов, окружений и значений - для журнала и оповещения."""
    envs = sum(len(p["environments"]) for p in snapshot["projects"])
    values = sum(len(e["values"]) for p in snapshot["projects"] for e in p["environments"])
    return len(snapshot["projects"]), envs, values


def pack(snapshot: dict, password: str, *, note: str = "") -> bytes:
    """Запечатывает снимок паролем. Возвращает готовый файл целиком.

    Целиком - потому что архив со всеми значениями панели измеряется мегабайтами,
    а не гигабайтами: сто тысяч ключей по сто байт это десять мегабайт. Дамп
    базы, который может быть куда больше, запечатывается потоком (`app/cli.py`).
    """
    plain = json.dumps(snapshot, ensure_ascii=False, indent=1).encode()
    out = io.BytesIO()
    sealedfile.seal(io.BytesIO(plain), out, password=password, note=note, kind=KIND)
    return out.getvalue()
