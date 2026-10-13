"""Служебные команды панели.

Нужна скрипту бэкапа: `pg_dump` отдает дамп в стандартный вывод, а на диск он
должен лечь уже зашифрованным - чтобы между "сняли" и "зашифровали" не было
момента, когда открытый дамп лежит файлом.

    pg_dump ... | python -m app.cli seal --password-file /run/backup.pass > dump.sealed

Открывает такой файл `ops/breakglass.py` - ему панель не нужна вовсе. Пароль
берем из файла, а не из аргумента: командная строка видна в `ps` любому
процессу на хосте.

Вторая команда проставляет признак многострочного значения тем ключам, которые
были записаны до его появления:

    python -m app.cli multiline

Она расшифровывает действующие версии и смотрит, есть ли в них перевод строки.
Значения при этом никуда не выводятся и не сохраняются - меняется только флаг.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app import sealedfile


def _password(args: argparse.Namespace) -> str:
    if args.password_file:
        password = Path(args.password_file).read_text(encoding="utf-8").strip()
    else:
        password = ""
    if not password:
        sys.exit("Пустой пароль: файл с паролем не задан или пуст")
    return password


async def _mark_multiline() -> int:
    """Проставить признак многострочности действующим значениям.

    Панель тут не участвует: команда сама открывает базу и корневой ключ теми же
    средствами, что и приложение при старте. Запертый сейф - честный отказ: без
    ключа значение не прочитать, а гадать по длине шифротекста нельзя.

    Значения нигде не выводятся и не переписываются: меняется один булев флаг.
    """
    import asyncio  # noqa: F401 - нужен вызывающему

    from sqlalchemy import select

    from app import sealbox, secrets_store
    from app.config import get_settings
    from app.db import create_engine_and_factory
    from app.models import Secret

    settings = get_settings()
    key = sealbox.root_from_env(settings.root_key, settings.root_key_file)
    if key is None:
        sys.exit("нет корневого ключа: задайте SEKVYR_ROOT_KEY или SEKVYR_ROOT_KEY_FILE")

    engine, factory = create_engine_and_factory(settings.db_url)
    box = sealbox.SealBox()
    changed = looked = 0
    async with factory() as session:
        meta = await sealbox.read_meta(session)
        if not meta.initialized or not sealbox.check_root(key, meta):
            await engine.dispose()
            sys.exit("корневой ключ не подходит к этой базе")
        box.set_root(key)

        for secret in await session.scalars(select(Secret).where(Secret.deleted.is_(False))):
            version = await secrets_store.current_version(session, secret)
            if version is None or version.deleted or version.multiline:
                continue
            looked += 1
            try:
                value = await secrets_store.read_value(session, box, secret)
            except Exception:  # noqa: BLE001 - битую версию пропускаем молча
                continue
            if "\n" in value:
                version.multiline = True
                changed += 1
        await session.commit()
    await engine.dispose()
    print(f"просмотрено значений: {looked}, отмечено многострочных: {changed}")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="app.cli", description="Служебные команды Sekvyr")
    sub = parser.add_subparsers(dest="command", required=True)

    seal = sub.add_parser("seal", help="запечатать стандартный ввод паролем")
    seal.add_argument("--password-file", required=True)
    seal.add_argument("--note", default="", help="пометка внутри файла")
    seal.add_argument("--kind", default="backup")

    sub.add_parser("multiline", help="проставить признак многострочных значений")

    args = parser.parse_args(argv)
    if args.command == "multiline":
        import asyncio

        raise SystemExit(asyncio.run(_mark_multiline()))

    head = sealedfile.seal(
        sys.stdin.buffer,
        sys.stdout.buffer,
        password=_password(args),
        note=args.note,
        kind=args.kind,
    )
    print(f"запечатано {head['created']}", file=sys.stderr)


if __name__ == "__main__":
    main()
