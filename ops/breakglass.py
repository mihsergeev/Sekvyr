#!/usr/bin/env python3
"""Аварийный доступ к секретам, когда панели нет.

Один файл, который надо уметь запустить в худший день: панель не поднимается,
база лежит в дампе, а прод нужно поднять сейчас. Зависимость ровно одна -
`cryptography` (та же, что у панели). Ничего из `app/` не импортируется
намеренно: в аварии под рукой может не оказаться репозитория, и этот файл
должен работать сам по себе.

Три способа добраться до значений, от простого к трудному:

  1. **Аварийный архив.** Собран заранее в разделе "Обслуживание", запечатан
     паролем. Тут нужен только пароль:

         python3 breakglass.py env sekvyr-emergency.sealed acme/web/prod

  2. **Бэкап базы и корневой ключ.** Дамп `pg_dump` (можно запечатанный
     `ops/backup.sh`) плюс ключ из файла или доли Шамира:

         python3 breakglass.py dump sekvyr-2026-09-08.sql.sealed \\
             --env acme/web/prod --share SEKVYR-1-... --share SEKVYR-1-...

  3. **Просто распечатать файл** и дальше разбираться руками:

         python3 breakglass.py open sekvyr-2026-09-08.sql.sealed -o dump.sql

Чего утилита не делает: не ходит в сеть, не пишет в базу, не спрашивает панель.
Она только читает и расшифровывает. Значения печатаются в стандартный вывод -
перенаправляйте в файл осознанно, помня, что это открытый текст.

Формат запечатанного файла и разбор долей повторяют `backend/app/sealedfile.py`
и `backend/app/shamir.py`. Совпадение проверяется тестом и `ops/selfcheck.py`:
разъехавшийся формат обнаружится в обычный день, а не в аварийный.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import io
import json
import os
import re
import struct
import sys
from typing import BinaryIO


def _russian() -> bool:
    """Язык вывода: SEKVYR_LANG (ru или en), иначе русская локаль, иначе
    английский. В Windows локали в переменных нет, спрашиваем систему."""
    choice = os.environ.get("SEKVYR_LANG", "").strip().lower()
    if choice in ("ru", "en"):
        return choice == "ru"
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(name, "")
        if value:
            return value.lower().startswith("ru")
    try:
        import locale

        current = (locale.getlocale(locale.LC_CTYPE)[0] or "").lower()
    except (ValueError, TypeError):
        current = ""
    return current.startswith(("ru", "russian"))


RU = _russian()


def t(ru: str, en: str) -> str:
    """Строка на языке вывода."""
    return ru if RU else en


try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:  # pragma: no cover - сообщение важнее трассировки
    sys.exit(
        t(
            "Нужен пакет cryptography: pip install cryptography\n"
            "Либо запустите утилиту внутри контейнера панели, там он уже есть.",
            "The cryptography package is needed: pip install cryptography\n"
            "Or run the tool inside the panel container, where it is already installed.",
        )
    )

# --- формат запечатанного файла (см. backend/app/sealedfile.py) ------------

MAGIC = "SEKVYR-SEALED-1"
CHUNK = 1 << 20
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_SIZE = 32
NONCE_PREFIX = 8
LENGTH = 4


class SealedError(Exception):
    """Файл не открылся: не тот пароль, испорчен, обрезан или не наш формат."""


def _aad(header_hash: bytes, index: int, final: bool) -> bytes:
    return header_hash + struct.pack(">IB", index, 1 if final else 0)


def read_header(src: BinaryIO) -> dict:
    line = src.readline()
    if not line.startswith(MAGIC.encode()):
        raise SealedError(t("это не запечатанный файл Sekvyr", "this is not a Sekvyr sealed file"))
    try:
        head = json.loads(line[len(MAGIC) :].decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise SealedError(t("заголовок не разобрался", "the header could not be parsed")) from exc
    head["_hash"] = hashlib.sha256(line).digest()
    return head


def unseal(src: BinaryIO, dst: BinaryIO, password: str) -> dict:
    """Распечатывает поток паролем. Возвращает заголовок файла."""
    head = read_header(src)
    if head.get("v") != 1:
        raise SealedError(t("файл новее этой утилиты", "the file is newer than this tool"))
    if head.get("kdf") != "scrypt":
        raise SealedError(
            t(
                "файл запечатан не паролем — такие открывает только панель",
                "the file is not sealed with a password: only the panel opens such files",
            )
        )
    secret = Scrypt(
        salt=bytes.fromhex(head["salt"]),
        length=KEY_SIZE,
        n=int(head["n"]),
        r=int(head["r"]),
        p=int(head["p"]),
    ).derive(password.encode())

    aes = AESGCM(secret)
    prefix = bytes.fromhex(head["nonce_prefix"])
    head_hash = head["_hash"]
    index = 0
    while True:
        raw = src.read(LENGTH)
        if len(raw) < LENGTH:
            raise SealedError(
                t(
                    "файл обрывается: последний кусок не помечен как последний",
                    "the file is cut short: the last chunk is not marked as last",
                )
            )
        size = struct.unpack(">I", raw)[0]
        blob = src.read(size)
        if len(blob) != size:
            raise SealedError(
                t("файл обрывается посреди куска", "the file is cut short in the middle of a chunk")
            )
        nonce = prefix + struct.pack(">I", index)
        plain, final = None, False
        for guess in (False, True):
            try:
                plain = aes.decrypt(nonce, blob, _aad(head_hash, index, guess))
            except InvalidTag:
                continue
            final = guess
            break
        if plain is None:
            raise SealedError(
                t(
                    "не открывается: неверный пароль либо файл испорчен",
                    "does not open: wrong password or a damaged file",
                )
                if index == 0
                else t("файл испорчен: кусок не сошёлся", "the file is damaged: a chunk does not match")
            )
        dst.write(plain)
        if final:
            return head
        index += 1


# --- доли Шамира (см. backend/app/shamir.py) -------------------------------

SHARE_PREFIX = "SEKVYR-1-"
_SHARE_VERSION = 1
_FP_LEN = 4
_CRC_LEN = 4


class ShareError(Exception):
    """Доля не разобралась: испорчена, от другого сейфа или чужого формата."""


def _mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        result ^= a & -(b & 1)
        b >>= 1
        high = a & 0x80
        a = (a << 1) & 0xFF
        a ^= 0x1B & -(high >> 7)
    return result


def _inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError(t("в GF(256) нет обратного к нулю", "zero has no inverse in GF(256)"))
    result, power = 1, a
    for bit in range(8):
        if (254 >> bit) & 1:
            result = _mul(result, power)
        power = _mul(power, power)
    return result


def _decode_share(share: str) -> tuple[bytes, int, bytes]:
    text = share.strip()
    if not text.upper().startswith(SHARE_PREFIX):
        raise ShareError(t("это не доля Sekvyr", "this is not a Sekvyr share"))
    payload = text[len(SHARE_PREFIX) :]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ShareError(t("доля испорчена", "the share is damaged")) from exc
    if len(raw) < 1 + _FP_LEN + 1 + 1 + _CRC_LEN:
        raise ShareError(t("доля испорчена", "the share is damaged"))
    body, crc = raw[:-_CRC_LEN], raw[-_CRC_LEN:]
    if hashlib.sha256(body).digest()[:_CRC_LEN] != crc:
        raise ShareError(
            t(
                "доля не сходится с контрольной суммой — проверьте, чем копировали",
                "the share fails its checksum: check how it was copied",
            )
        )
    if body[0] != _SHARE_VERSION:
        raise ShareError(t("доля другого формата", "the share has another format"))
    return body[1 : 1 + _FP_LEN], body[1 + _FP_LEN], body[2 + _FP_LEN :]


def combine(shares: list[str]) -> bytes:
    """Восстанавливает корневой ключ из долей."""
    if not shares:
        raise ShareError(t("нет ни одной доли", "no shares given"))
    parsed = [_decode_share(s) for s in shares]
    if len({fp for fp, _, _ in parsed}) > 1:
        raise ShareError(t("доли от разных ключей", "the shares belong to different keys"))
    indexes = [index for _, index, _ in parsed]
    if len(set(indexes)) != len(indexes):
        raise ShareError(t("одна и та же доля подана дважды", "the same share is given twice"))
    lengths = {len(data) for _, _, data in parsed}
    if len(lengths) > 1:
        raise ShareError(t("доли разной длины", "the shares have different lengths"))

    size = lengths.pop()
    secret = bytearray()
    for position in range(size):
        total = 0
        for _, xi, data_i in parsed:
            numerator, denominator = 1, 1
            for _, xj, _ in parsed:
                if xj == xi:
                    continue
                numerator = _mul(numerator, xj)
                denominator = _mul(denominator, xi ^ xj)
            total ^= _mul(data_i[position], _mul(numerator, _inv(denominator)))
        secret.append(total)
    root = bytes(secret)
    fingerprint = hashlib.sha256(root).digest()[:_FP_LEN]
    if fingerprint != parsed[0][0]:
        # Интерполяция ВСЕГДА что-то возвращает: без этой проверки из неверных
        # долей вышел бы правдоподобный мусор, а не понятная ошибка. Порога
        # доля в себе не несет, поэтому "долей мало" отсюда не отличить от
        # "среди долей чужая", и называются обе причины: в аварии первая
        # встречается чаще, и искать "чужую" долю было бы потерей времени.
        raise ShareError(
            t(
                f"ключ не сошелся: введено долей {len(parsed)}, это меньше порога, или среди них есть чужая",
                f"the key does not match: {len(parsed)} shares given, fewer than the threshold, or one of them is foreign",
            )
        )
    return root


# --- разбор дампа pg_dump --------------------------------------------------

COPY_HEAD = re.compile(r"^COPY (?:public\.)?\"?(\w+)\"? \(([^)]*)\) FROM stdin;$")


def _unescape(field: str) -> str:
    out, i = [], 0
    while i < len(field):
        char = field[i]
        if char == "\\" and i + 1 < len(field):
            nxt = field[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(nxt, nxt))
            i += 2
            continue
        out.append(char)
        i += 1
    return "".join(out)


def read_tables(path: str, wanted: set[str], password: str = "") -> dict[str, list[dict]]:
    """Достает из дампа нужные таблицы. Понимает и запечатанный файл.

    Разбираем текстовый дамп, а не поднимаем Postgres: в аварии "сначала
    поставьте СУБД и восстановите базу" - это лишние полчаса и лишний сервер, на
    котором окажутся все секреты сразу.
    """
    raw = open(path, "rb")
    with raw:
        peek = raw.read(len(MAGIC))
        raw.seek(0)
        if peek == MAGIC.encode():
            if not password:
                password = getpass.getpass(t("Пароль файла: ", "File password: "))
            plain = io.BytesIO()
            unseal(raw, plain, password)
            plain.seek(0)
            stream = io.TextIOWrapper(plain, encoding="utf-8")
        else:
            stream = io.TextIOWrapper(io.BytesIO(raw.read()), encoding="utf-8")

    tables: dict[str, list[dict]] = {name: [] for name in wanted}
    columns: list[str] = []
    current = ""
    for line in stream:
        line = line.rstrip("\n")
        if current:
            if line == "\\.":
                current = ""
                continue
            fields = line.split("\t")
            row = {
                col: (None if value == "\\N" else _unescape(value))
                for col, value in zip(columns, fields)
            }
            tables[current].append(row)
            continue
        match = COPY_HEAD.match(line)
        if match and match.group(1) in wanted:
            current = match.group(1)
            columns = [c.strip().strip('"') for c in match.group(2).split(",")]
    missing = [name for name in wanted if not tables[name]]
    if missing:
        print(
            t("# в дампе нет строк таблиц: ", "# the dump has no rows of tables: ")
            + ", ".join(sorted(missing)),
            file=sys.stderr,
        )
    return tables


# --- расшифровка значений --------------------------------------------------


def _b64(text: str) -> bytes:
    return base64.b64decode(text)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: str) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad.encode())
    except InvalidTag as exc:
        raise SealedError(
            t(
                "шифротекст не сошёлся: не тот ключ или испорченные данные",
                "the ciphertext does not match: wrong key or damaged data",
            )
        ) from exc


def env_values(tables: dict[str, list[dict]], root: bytes, env_id: int) -> list[tuple[str, str, str]]:
    """Итоговые значения окружения: свои и унаследованные, как их отдает панель.

    Возвращает список (папка, имя, значение).
    """
    environments = {int(r["id"]): r for r in tables["environments"]}
    keys: dict[tuple[int, int], bytes] = {}
    for row in tables["env_keys"]:
        holder, generation = int(row["environment_id"]), int(row["generation"])
        keys[(holder, generation)] = decrypt(
            root,
            _b64(row["nonce"]),
            _b64(row["wrapped_key"]),
            "\x1f".join(("envkey1", str(holder), str(generation))),
        )

    versions: dict[int, list[dict]] = {}
    for row in tables["secret_versions"]:
        versions.setdefault(int(row["secret_id"]), []).append(row)

    # Цепочка наследования: от самого окружения к корню.
    chain, node = [], env_id
    seen = set()
    while node and node not in seen:
        seen.add(node)
        chain.append(node)
        parent = environments.get(node, {}).get("parent_id")
        node = int(parent) if parent else 0

    out: dict[tuple[str, str], tuple[str, str, str]] = {}
    hidden: set[tuple[str, str]] = set()
    for level in chain:
        for secret in tables["secrets"]:
            if int(secret["environment_id"]) != level:
                continue
            place = (secret["path"], secret["name"])
            if place in out or place in hidden:
                continue
            current = int(secret["current_version"] or 0)
            version = next(
                (
                    v
                    for v in versions.get(int(secret["id"]), [])
                    if int(v["version"]) == current
                ),
                None,
            )
            if version is None or version["inherits"] == "t":
                continue
            if version["deleted"] == "t":
                hidden.add(place)
                continue
            key = keys.get((level, int(version["env_key_generation"])))
            if key is None:
                generation = version["env_key_generation"]
                print(
                    t(
                        f"# нет ключа окружения {level} поколения {generation} — "
                        f"ключ «{secret['name']}» пропущен",
                        f"# no key of environment {level}, generation {generation}: "
                        f"key \"{secret['name']}\" skipped",
                    ),
                    file=sys.stderr,
                )
                continue
            value = decrypt(
                key,
                _b64(version["nonce"]),
                _b64(version["ciphertext"]),
                "\x1f".join(
                    (
                        "v1",
                        str(level),
                        str(secret["id"]),
                        version["name_at"],
                        str(version["version"]),
                    )
                ),
            ).decode()
            out[place] = (secret["path"], secret["name"], value)
    return [out[place] for place in sorted(out)]


# --- вывод -----------------------------------------------------------------


def quote(value: str) -> str:
    """Значение для файла .env. Правила те же, что у панели и агента
    (backend/app/secrets_store.py, _quote): без кавычек только безопасное,
    остальное в одинарных кавычках, где docker compose ничего не подставляет;
    двойные с экранированием $ - только когда одинарные не годятся. Файл для
    compose и systemd, а не для source в shell: обратный апостроф в двойных
    кавычках остается как есть."""
    if value == "":
        return '""'
    if re.fullmatch(r"[A-Za-z0-9_\-.,:/@%+=]+", value):
        return value
    if "'" not in value and "\r" not in value and not value.endswith("\\"):
        return f"'{value}'"
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'


def print_env(values: list[tuple[str, str, str]]) -> None:
    folder = "/"
    first = True
    for path, name, value in values:
        if path != folder:
            folder = path
            if not first:
                print("")
            print(f"# {path}")
        first = False
        print(f"{name}={quote(value)}")


def parse_address(address: str) -> tuple[str | None, str, str]:
    """Группа, проект и окружение из "группа/проект/окружение" или "проект/окружение".

    Группа None - любая (адрес из двух частей). "-" - проект без группы: так его
    печатает list, и адрес из списка должен работать как есть.
    """
    # "/проект/окружение" - тоже без группы: так адрес из list можно передать
    # и там, где аргумент с минусом в начале argparse принял бы за ключ.
    explicit_none = address.startswith("/")
    parts = [p for p in address.split("/") if p]
    if len(parts) == 3:
        group, project, env = parts
        return ("" if group == "-" else group), project, env
    if len(parts) == 2:
        return ("" if explicit_none else None), parts[0], parts[1]
    sys.exit(
        t(
            "Адрес окружения выглядит так: группа/проект/окружение",
            "An environment address looks like this: group/project/environment",
        )
    )


def one_project(candidates: list[dict], project: str, group_key: str) -> dict:
    """Единственный проект с таким именем. Одноименные проекты разных групп без
    группы в адресе - отказ, а не первый попавшийся: в аварии легко взять
    значения чужого прода."""
    if len(candidates) > 1:
        groups = ", ".join(sorted((row.get(group_key) or "-") for row in candidates))
        sys.exit(
            t(
                f"Проектов «{project}» несколько — уточните группу: {groups}",
                f"There are several projects \"{project}\": name the group: {groups}",
            )
        )
    return candidates[0]


def find_env(tables: dict[str, list[dict]], address: str) -> int:
    """Номер окружения по адресу "группа/проект/окружение" или "проект/окружение"."""
    group, project, env = parse_address(address)
    candidates = [
        row
        for row in tables["projects"]
        if row["slug"] == project and (group is None or (row["group_slug"] or "") == group)
    ]
    if not candidates:
        sys.exit(t(f"Проект «{project}» в дампе не найден", f"Project \"{project}\" not found in the dump"))
    project_id = int(one_project(candidates, project, "group_slug")["id"])
    for row in tables["environments"]:
        if int(row["project_id"]) == project_id and row["name"] == env:
            return int(row["id"])
    sys.exit(
        t(
            f"Окружение «{env}» у проекта «{project}» не найдено",
            f"Environment \"{env}\" of project \"{project}\" not found",
        )
    )


def load_root(args) -> bytes:
    """Корневой ключ: из файла, из строки или собранный из долей."""
    if args.key_file:
        return base64.b64decode(open(args.key_file, encoding="utf-8").read().strip())
    if args.key:
        return base64.b64decode(args.key.strip())
    shares = list(args.share or [])
    if not shares:
        print(
            t(
                "Вводите доли по одной, пустая строка — закончить.",
                "Enter the shares one by one, an empty line to finish.",
            ),
            file=sys.stderr,
        )
        while True:
            line = input(t("доля: ", "share: ")).strip()
            if not line:
                break
            shares.append(line)
    if not shares:
        sys.exit(t("Без корневого ключа значения не расшифровать", "Values cannot be decrypted without the root key"))
    return combine(shares)


# --- команды ---------------------------------------------------------------


def cmd_open(args) -> None:
    password = args.password or getpass.getpass(t("Пароль файла: ", "File password: "))
    with open(args.file, "rb") as src:
        if args.output == "-":
            head = unseal(src, sys.stdout.buffer, password)
        else:
            # Открытый файл создаем сразу с правами 0600: содержимое дампа не
            # должно даже на секунду оказаться читаемым всем.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as dst:
                head = unseal(src, dst, password)
    note = head.get("note") or head.get("kind") or ""
    print(
        t("Открыт файл от ", "Opened a file from ")
        + str(head.get("created", "?"))
        + (f" ({note})" if note else ""),
        file=sys.stderr,
    )


def _archive(args) -> dict:
    password = args.password or getpass.getpass(t("Пароль архива: ", "Archive password: "))
    plain = io.BytesIO()
    with open(args.archive, "rb") as src:
        unseal(src, plain, password)
    return json.loads(plain.getvalue().decode())


def cmd_list(args) -> None:
    data = _archive(args)
    print(t("Архив от ", "Archive from ") + str(data.get("created", "?")))
    for project in data["projects"]:
        group = project.get("group") or "-"
        for env in project["environments"]:
            count = len(env["values"])
            # Проект с шифрованием в браузере значений в архиве не имеет: "0
            # ключей" выглядело бы как пустое окружение.
            what = (
                t("шифрование в браузере, значений в архиве нет", "browser-side encryption, no values in the archive")
                if env.get("note") and not count
                else t(f"{count} ключей", f"{count} keys")
            )
            print(f"  {group}/{project['slug']}/{env['name']}: {what}")


def cmd_env(args) -> None:
    data = _archive(args)
    group, project, env_name = parse_address(args.address)
    candidates = [
        item
        for item in data["projects"]
        if item["slug"] == project and (group is None or (item.get("group") or "") == group)
    ]
    if candidates:
        item = one_project(candidates, project, "group")
        for env in item["environments"]:
            if env["name"] != env_name:
                continue
            if env.get("note") and not env["values"]:
                # Пустой вывод ушел бы в .env, и приложение поднялось бы без
                # значений. Отказ с причиной и ненулевым кодом.
                sys.exit(
                    t(
                        f'Окружение "{args.address}" в проекте с шифрованием в браузере: '
                        "значений в архиве нет, их знает только владелец пароля проекта",
                        f"Environment \"{args.address}\" is in a project with browser-side "
                        "encryption: the archive has no values, only the project password owner knows them",
                    )
                )
            if env.get("unreadable"):
                # В stderr: stdout уходит в .env.
                print(
                    t(
                        "Внимание: эти значения в архив не попали, их не открыть (нет ключа окружения): ",
                        "Warning: these values are missing from the archive, they cannot be opened (no environment key): ",
                    )
                    + ", ".join(env["unreadable"]),
                    file=sys.stderr,
                )
            print_env([(v["path"], v["name"], v["value"]) for v in env["values"]])
            return
    sys.exit(
        t(
            f"В архиве нет окружения «{args.address}» — посмотрите список: команда list",
            f"The archive has no environment \"{args.address}\": see the list with the list command",
        )
    )


def cmd_dump(args) -> None:
    tables = read_tables(
        args.file,
        {"projects", "environments", "env_keys", "secrets", "secret_versions"},
        args.password,
    )
    root = load_root(args)
    if args.list:
        for project in sorted(tables["projects"], key=lambda r: (r["group_slug"], r["slug"])):
            mark = (
                t("  (шифрование в браузере)", "  (browser-side encryption)")
                if project.get("e2e") == "t"
                else ""
            )
            for env in tables["environments"]:
                if int(env["project_id"]) == int(project["id"]):
                    print(f"{project['group_slug'] or '-'}/{project['slug']}/{env['name']}{mark}")
        return
    if not args.env:
        sys.exit(
            t(
                "Укажите окружение: --env группа/проект/окружение (или --list)",
                "Name the environment: --env group/project/environment (or --list)",
            )
        )
    env_id = find_env(tables, args.env)
    env_row = next(r for r in tables["environments"] if int(r["id"]) == env_id)
    project = next(r for r in tables["projects"] if int(r["id"]) == int(env_row["project_id"]))
    if project.get("e2e") == "t":
        # В базе у такого проекта только блобы, запечатанные в браузере. Отдать
        # их файлом .env значило бы подсунуть приложению "e2e:v1:..." вместо
        # значений. Аварийный архив говорит о таких проектах так же прямо.
        sys.exit(
            t(
                f'Проект "{project["slug"]}" зашифрован в браузере: в дампе только '
                "запечатанные блобы, и открыть их может лишь тот, кто знает пароль проекта",
                f"Project \"{project['slug']}\" uses browser-side encryption: the dump holds "
                "only sealed blobs, and only someone who knows the project password can open them",
            )
        )
    print_env(env_values(tables, root, env_id))


EPILOG_EN = """Emergency access to the secrets when there is no panel.

Three ways to the values, from simple to hard:

  1. The emergency archive, built in advance in the Maintenance section and
     sealed with a password. Only the password is needed:

         python3 breakglass.py env sekvyr-emergency.sealed acme/web/prod

  2. A database backup and the root key: a pg_dump dump (sealed by
     ops/backup.sh or not) plus the key from a file or Shamir shares:

         python3 breakglass.py dump sekvyr-2026-09-08.sql.sealed \\
             --env acme/web/prod --share SEKVYR-1-... --share SEKVYR-1-...

  3. Just unseal the file and take it from there by hand:

         python3 breakglass.py open sekvyr-2026-09-08.sql.sealed -o dump.sql

The tool never goes to the network, never writes to a database and never asks
the panel: it only reads and decrypts. Values go to standard output; redirect
them to a file deliberately, it is plain text. Output language: SEKVYR_LANG=ru
or en.
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description=t("Аварийный доступ к секретам Sekvyr без панели", "Emergency access to Sekvyr secrets without the panel"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__ if RU else EPILOG_EN,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    address = t("группа/проект/окружение", "group/project/environment")

    p_open = sub.add_parser("open", help=t("распечатать запечатанный файл", "unseal a sealed file"))
    p_open.add_argument("file")
    p_open.add_argument(
        "-o", "--output", default="-", help=t("куда писать; «-» — в вывод", 'where to write; "-" for standard output')
    )
    p_open.add_argument("--password", default="")
    p_open.set_defaults(func=cmd_open)

    p_list = sub.add_parser("list", help=t("что лежит в аварийном архиве", "what is in an emergency archive"))
    p_list.add_argument("archive")
    p_list.add_argument("--password", default="")
    p_list.set_defaults(func=cmd_list)

    p_env = sub.add_parser(
        "env", help=t("напечатать .env окружения из архива", "print the .env of an environment from the archive")
    )
    p_env.add_argument("archive")
    p_env.add_argument("address", help=address)
    p_env.add_argument("--password", default="")
    p_env.set_defaults(func=cmd_env)

    p_dump = sub.add_parser(
        "dump",
        help=t("достать значения из дампа базы корневым ключом", "get values out of a database dump with the root key"),
    )
    p_dump.add_argument("file", help=t("дамп pg_dump, можно запечатанный", "a pg_dump dump, sealed or not"))
    p_dump.add_argument("--env", default="", help=address)
    p_dump.add_argument(
        "--list", action="store_true", help=t("показать окружения в дампе", "list the environments in the dump")
    )
    p_dump.add_argument("--key", default="", help=t("корневой ключ в base64", "the root key in base64"))
    p_dump.add_argument("--key-file", default="", help=t("файл с корневым ключом", "a file with the root key"))
    p_dump.add_argument(
        "--share", action="append", help=t("доля Шамира (можно несколько)", "a Shamir share (can repeat)")
    )
    p_dump.add_argument(
        "--password", default="", help=t("пароль запечатанного дампа", "password of a sealed dump")
    )
    p_dump.set_defaults(func=cmd_dump)

    # Адрес "-/проект/окружение" (так list печатает проект без группы) argparse
    # принял бы за неизвестный ключ: передаем его в равнозначном виде
    # "/проект/окружение".
    # Только адрес: значение пароля или пути после -o, --password, --key и
    # других ключей с минусом-слешем в начале - это их значение, и менять его
    # нельзя.
    takes_value = {"-o", "--output", "--password", "--key", "--key-file", "--share"}
    raw = sys.argv[1:]
    argv = [
        a[1:] if a.startswith("-/") and (i == 0 or raw[i - 1] not in takes_value) else a
        for i, a in enumerate(raw)
    ]
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (SealedError, ShareError) as exc:
        sys.exit(t("Не вышло: ", "Failed: ") + str(exc))


if __name__ == "__main__":
    main()
