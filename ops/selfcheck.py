#!/usr/bin/env python3
"""Самопроверка Sekvyr: ищет места, где панель может ПРОМОЛЧАТЬ.

Рядом с кодом всегда живут списки, написанные руками: уровни ролей на фронте и
на бэкенде, подписи действий в журнале, имена переменных окружения в compose.
Когда код уходит вперед, такой список не ломается с ошибкой - интерфейс просто
перестает что-то показывать или показывает раздел, который API закроет. Это не
видно ни в тестах, ни глазами, поэтому расхождения ловим машинно.

Запуск из корня репозитория:  python ops/selfcheck.py
Код возврата 1 = есть расхождения (годится для CI).
"""

from __future__ import annotations

import ast
import io
import json
import os
import re
import sys

PROBLEMS: list[str] = []

# Скрипт запускают и из Windows-консоли, где по умолчанию не UTF-8: без этого
# отчет о расхождениях приезжает нечитаемым, и его перестают читать.
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")


def fail(area: str, msg: str) -> None:
    PROBLEMS.append(f"[{area}] {msg}")


def read(path: str) -> str:
    return io.open(path, encoding="utf-8").read()


# ------------------------------------------------- 1. длина пароля
def check_password_len() -> None:
    """Форма не должна отправлять то, что API отвергнет, и наоборот."""
    back = re.search(r"MIN_PASSWORD_LEN\s*=\s*(\d+)", read("backend/app/security.py"))
    front = re.search(r"MIN_PASSWORD_LEN\s*=\s*(\d+)", read("frontend/src/api.ts"))
    if not back or not front:
        fail("пароль", "не нашёл MIN_PASSWORD_LEN на бэкенде или на фронте")
        return
    if back.group(1) != front.group(1):
        fail(
            "пароль",
            f"MIN_PASSWORD_LEN разошёлся: бэкенд {back.group(1)}, фронт {front.group(1)}",
        )


# ------------------------------------------------- 2. уровни ролей
def _backend_levels() -> dict[str, int]:
    src = read("backend/app/roles.py")
    body = src[src.find("LEVELS: dict[str, int] = {") :]
    body = body[: body.find("}")]
    out: dict[str, int] = {}
    for name, value in re.findall(r"(\w+):\s*(\d+)", body):
        # ключи заданы константами (OWNER и т.п.) - разворачиваем их значения
        const = re.search(rf'^{name}\s*=\s*"([a-z]+)"', src, re.M)
        out[const.group(1) if const else name] = int(value)
    return out


def _frontend_levels() -> dict[str, int]:
    src = read("frontend/src/auth.tsx")
    body = src[src.find("export const LEVELS") :]
    body = body[: body.find("}")]
    return {k: int(v) for k, v in re.findall(r"(\w+):\s*(\d+)", body)}


def check_roles() -> None:
    """Роль, которой нет на фронте, означает пропавший раздел; разъехавшийся
    уровень - кнопку, которая всегда отвечает 403."""
    back, front = _backend_levels(), _frontend_levels()
    if not back or not front:
        fail("роли", "не разобрал таблицы уровней ролей")
        return
    if back != front:
        fail("роли", f"уровни разошлись: бэкенд {back}, фронт {front}")

    page = read("frontend/src/UsersPage.tsx")
    body = page[page.find("const ROLE_TITLES") :]
    body = body[: body.find("}")]
    # кавычки бывают и одинарные, и двойные - prettier/oxlint нормализуют их
    # по-разному, и привязываться к одному виду значит однажды сломаться на форматере
    named = set(re.findall(r"(\w+):\s*['\"]", body))
    missing = set(front) - named
    if missing:
        fail("роли", f"в UsersPage нет подписи для ролей: {sorted(missing)}")


# ------------------------------------------------- 3. действия журнала
def check_audit_actions() -> None:
    """Каждое записываемое действие должно иметь человеческую подпись: журнал,
    в котором половина строк - служебные идентификаторы, читать невозможно."""
    recorded: set[str] = set()
    for root, _, files in os.walk("backend/app"):
        for name in files:
            if not name.endswith(".py"):
                continue
            src = read(os.path.join(root, name))
            # Цифры в имени тоже бывают ("e2e_enabled"), и без них проверка
            # молча пропускала действие вместе с его отсутствующей подписью.
            recorded |= set(re.findall(r'action\s*=\s*"([a-z0-9_]+)"', src))

    page = read("frontend/src/auditActions.ts")
    body = page[page.find("const ACTIONS") :]
    body = body[: body.find("}")]
    known = set(re.findall(r"(\w+):\s*'", body))
    missing = recorded - known
    if missing:
        fail("журнал", f"нет подписи для действий: {sorted(missing)}")


# ------------------------------------------------- 4. переменные окружения
def check_env_names() -> None:
    """Переменная, которой нет в настройках, тихо не действует: панель поднимется
    со значением по умолчанию, а человек будет уверен, что задал свое."""
    settings = read("backend/app/config.py")
    known = {f"SEKVYR_{n.upper()}" for n in re.findall(r"^\s{4}(\w+):", settings, re.M)}
    # Задаются не через Settings, а на уровне compose и образа
    external = {
        "SEKVYR_DB_NAME",
        "SEKVYR_DB_USER",
        "SEKVYR_DB_PASSWORD",
        "SEKVYR_BIND",
        "SEKVYR_DOMAIN",
        "SEKVYR_ALLOW_IPS",
        "SEKVYR_CADDY_NETWORK",
        "SEKVYR_IMAGE_TAG",
        # язык вывода скриптов ops/ и агента, панель его не читает
        "SEKVYR_LANG",
        # читает ops/backup.sh, а не панель
        "SEKVYR_BACKUP_DIR",
        "SEKVYR_BACKUP_KEEP",
        "SEKVYR_BACKUP_OFFSITE",
    }
    used: set[str] = set()
    for path in ("compose.yml", "compose.caddy.yml", "compose.ghcr.yml", ".env.example"):
        used |= set(re.findall(r"\b(SEKVYR_[A-Z0-9_]+)\b", read(path)))
    unknown = used - known - external
    if unknown:
        fail("окружение", f"переменные, которых нет в config.py: {sorted(unknown)}")

    # Обратная сторона: настройка из .env.example, которую compose не передает в
    # контейнер, тоже тихо не действует. .env в образ не попадает, бэкенд видит
    # только перечисленное в compose.yml. Так не работали SEKVYR_ALERT_ON_ENVS и
    # SEKVYR_JWT_TTL_MINUTES.
    documented = set(re.findall(r"^#?\s*(SEKVYR_[A-Z0-9_]+)=", read(".env.example"), re.M))
    passed: set[str] = set()
    for path in ("compose.yml", "compose.caddy.yml"):
        passed |= set(re.findall(r"\b(SEKVYR_[A-Z0-9_]+)\b", read(path)))
    lost = (documented & known) - passed
    if lost:
        fail("окружение", f"описаны в .env.example, но compose их не передает: {sorted(lost)}")


# ------------------------------------------------- 5. машинный контур
# Свойство "сервер не может изменить или удалить секрет" держится не проверкой
# прав, а отсутствием изменяющих маршрутов.
#
# Четвертый в списке - подключение сервера. Он тоже не касается значений:
# заводит машинную личность по одноразовому токену.
# Расширять список дальше - значит расширять то, что машина умеет портить.
MACHINE_WRITE_ALLOWED = {"/token", "/report", "/revoke", "/enroll"}


def check_machine_readonly() -> None:
    path = "backend/app/api/machine.py"
    if not os.path.exists(path):
        return
    src = read(path)
    for method, route in re.findall(r'@router\.(post|put|patch|delete)\("([^"]*)"', src):
        if route not in MACHINE_WRITE_ALLOWED:
            fail(
                "машины",
                f"изменяющий маршрут {method.upper()} {route} в машинном контуре — "
                "сервер не должен уметь менять секреты",
            )

    # Машине выдается только чтение. Список действий живет в одном месте, и если
    # туда однажды допишут `write`, право на запись станет выдаваемым - а
    # выполнять его будет некому, маршрутов-то нет.
    machines_src = read("backend/app/machines.py")
    listed = re.search(r"MACHINE_ACTIONS = \(([^)]*)\)", machines_src)
    if listed is None:
        fail("машины", "в app/machines.py нет списка MACHINE_ACTIONS")
        return
    allowed = {name.strip() for name in listed.group(1).split(",") if name.strip()}
    if allowed - {"access.LIST", "access.READ"}:
        fail(
            "машины",
            f"машине разрешено лишнее: {sorted(allowed)} — только чтение",
        )
    if "machines.MACHINE_ACTIONS" not in read("backend/app/api/policies.py"):
        fail(
            "машины",
            "создание политики не сверяется с MACHINE_ACTIONS — машине можно "
            "будет выдать запись",
        )


def check_agent_signature() -> None:
    """Версия агента должна быть подписана ключом из agent/pubkey.txt.

    Агент обновляет себя сам, то есть выполняет от root то, что ему прислали.
    Единственное, что отделяет это от "панель раздала что угодно", - подпись,
    сделанная ключом, которого на панели нет. Если описание разъедется с ключом,
    ноды перестанут обновляться молча: узнать об этом лучше на сборке.
    """
    manifest_path = os.path.join("agent", "manifest.json")
    pubkey_path = os.path.join("agent", "pubkey.txt")
    if not os.path.exists(manifest_path):
        return  # версия еще не выпускалась - ops/agent_release.py --sign
    if not os.path.exists(pubkey_path):
        fail("агент", "есть manifest.json, но нет pubkey.txt — подпись нечем проверить")
        return

    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    data = json.loads(read(manifest_path))
    digests = {arch: meta["sha256"] for arch, meta in data["files"].items()}
    lines = ["sekvyr-agent", f"version {data['version']}"]
    lines += [f"{arch} {digests[arch]}" for arch in sorted(digests)]
    text = ("\n".join(lines) + "\n").encode()
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(read(pubkey_path).strip()))
    try:
        key.verify(base64.b64decode(data["signature"]), text)
    except Exception:
        fail("агент", "подпись версии агента не сходится с agent/pubkey.txt")
        return
    # Вторая подпись покрывает и дату: без нее новые агенты обновятся, но дату
    # подписи сочтут неизвестной.
    if not data.get("signature_v2"):
        fail("агент", "в manifest.json нет второй подписи (с датой) - python ops/agent_release.py --sign")
        return
    lines = ["sekvyr-agent 2", f"version {data['version']}", f"signed_at {data.get('signed_at', '')}"]
    lines += [f"{arch} {digests[arch]}" for arch in sorted(digests)]
    try:
        key.verify(base64.b64decode(data["signature_v2"]), ("\n".join(lines) + "\n").encode())
    except Exception:
        fail("агент", "вторая подпись версии агента (с датой) не сходится с agent/pubkey.txt")
        return

    declared = read(os.path.join("agent", "VERSION")).strip()
    if data["version"] != declared:
        fail(
            "агент",
            f"подписана версия агента {data['version']}, а собирается {declared} — "
            "выпустите агента: python ops/agent_release.py --sign",
        )


# ------------------------------------------------- 6. версия
def check_version() -> None:
    """Версия живет в четырех местах сразу. Разъезжается она молча: панель
    показывает в "Обзоре" одно, changelog обещает другое, а при частичном
    обновлении (собрали фронт, забыли бэкенд) поди пойми, что именно работает."""
    found = {
        "backend/pyproject.toml": re.search(r'^version = "([\d.]+)"', read("backend/pyproject.toml"), re.M),
        "backend/app/config.py": re.search(r'version: str = "([\d.]+)"', read("backend/app/config.py")),
        "frontend/package.json": re.search(r'"version": "([\d.]+)"', read("frontend/package.json")),
        "CHANGELOG.md": re.search(r"^## \[([\d.]+)\]", read("CHANGELOG.md"), re.M),
    }
    versions = {path: m.group(1) if m else "?" for path, m in found.items()}
    if len(set(versions.values())) > 1:
        fail("версия", f"разошлась: {versions}")



# ------------------------------------------------- 7. охрана маршрутов
# Маршруты, которым аутентификация не нужна по существу. Список короткий и
# закрытый: все, что не здесь, обязано зависеть от учетной записи.
OPEN_ROUTES = {
    ("health.py", "/health"),
    ("auth.py", "/login"),
    # Вход машины: пары "идентификатор + секрет" у нее еще нет во что менять,
    # поэтому учетки здесь и не может быть. Защита та же, что у входа людей -
    # лимитер попыток и одинаковый ответ на любую ошибку.
    ("machine.py", "/token"),
    # Подключение сервера: личности у него еще нет, весь доступ дает одноразовый
    # токен, годный на одно подключение.
    ("machine.py", "/enroll"),
    # Бинарь агента и скрипт установки: их читает чистая нода до всякой
    # аутентификации, и ничего секретного в них нет.
    ("machine.py", "/agent"),
    ("machine.py", "/agent/manifest"),
    ("machine.py", "/install.sh"),
    # Свой логотип: его рисует экран входа, то есть до всякой учетки. Отдаются
    # только картинка и её настройки; загрузка и сброс - по другим путям и
    # только владельцу.
    ("branding.py", ""),
    ("branding.py", "/logo"),
    ("branding.py", "/logo-dark"),
}

# Маршруты секретов, которым не нужна проверка прав на окружение: они её и не
# касаются. Тоже поименно - "наверное, тут можно" здесь не работает.
UNGUARDED_SECRET_ROUTES: set[str] = set()

ROUTE_RE = re.compile(
    r'@router\.(get|post|put|patch|delete)\(\s*"([^"]*)"(?:.|\n)*?\ndef |'
    r'@router\.(get|post|put|patch|delete)\(\s*"([^"]*)"(?:.|\n)*?\nasync def '
)


def _routes(src: str) -> list[tuple[str, str, str]]:
    """(метод, путь, тело функции) для каждого маршрута файла."""
    out: list[tuple[str, str, str]] = []
    for match in re.finditer(r'@router\.(get|post|put|patch|delete)\(\s*"([^"]*)"', src):
        method, path = match.group(1), match.group(2)
        start = src.find("def ", match.end())
        if start < 0:
            continue
        nxt = src.find("@router.", start)
        body = src[start : nxt if nxt > 0 else len(src)]
        out.append((method, path, body))
    return out


def check_routes_are_guarded() -> None:
    """Каждый маршрут требует учетку, а маршруты секретов - еще и право на место.

    Это ровно та проверка, которую невозможно сделать глазами на ревью: забытая
    зависимость выглядит как обычная функция и отвечает 200 кому угодно.
    """
    api_dir = os.path.join("backend", "app", "api")
    for name in sorted(os.listdir(api_dir)):
        if not name.endswith(".py") or name == "__init__.py":
            continue
        src = read(os.path.join(api_dir, name))
        for method, path, body in _routes(src):
            if (name, path) in OPEN_ROUTES:
                continue
            # В машинном контуре вход свой: не учетка, а машинная личность.
            required = (
                r"CurrentMachine"
                if name == "machine.py"
                else r"(CurrentUser|OwnerUser|MaintainerUser)"
            )
            if not re.search(required, body):
                who = "машинной личности" if name == "machine.py" else "учётной записи"
                fail(
                    "охрана",
                    f"{name}: {method.upper()} {path} не требует {who}",
                )
            if name == "secrets.py" and path not in UNGUARDED_SECRET_ROUTES:
                # _guard - одно место, _guard_any - хоть одна папка (дальше
                # фильтр по путям), _guard_whole - все папки окружения.
                if not re.search(r"_guard(_any|_whole)?\(", body):
                    fail(
                        "охрана",
                        f"{name}: {method.upper()} {path} не проверяет права на окружение",
                    )


def check_actions_are_listed() -> None:
    """Набор действий в правах и его подписи на фронте должны совпадать: новое
    действие без подписи означает пустую галочку в форме выдачи прав."""
    back = read("backend/app/access.py")
    # Константы перечислять поименно нельзя: новое действие тогда молча выпадет
    # из проверки - ровно в тот раз, когда подпись к нему и забудут.
    block = back[back.find("ACTIONS = (") : back.find(")", back.find("ACTIONS = ("))]
    names = set()
    for const in re.findall(r"(\w+)", block[len("ACTIONS = (") :]):
        found = re.search(rf'^{const} = "(\w+)"', back, re.M)
        if found:
            names.add(found.group(1))
    page = read("frontend/src/AccessPage.tsx")
    body = page[page.find("const ACTION_TITLES") :]
    body = body[: body.find("}")]
    known = set(re.findall(r"(\w+):\s*'", body))
    missing = names - known
    if missing:
        fail("права", f"в AccessPage нет подписи для действий: {sorted(missing)}")


# ------------------------------------------------- 8. окна панели
def check_no_browser_dialogs() -> None:
    """В панели не должно быть браузерных prompt/confirm/alert.

    Они выглядят чужеродно, блокируют вкладку, по-разному рисуются в разных
    браузерах и не умеют ничего, что здесь нужно каждый день: несколько полей,
    подсказку под полем, выбор из списка, понятную кнопку вместо "OK". Вернуть
    их случайно легко - поэтому запрет держится проверкой, а не памятью.
    """
    for root, _dirs, files in os.walk(os.path.join("frontend", "src")):
        for name in files:
            if not name.endswith((".tsx", ".ts")):
                continue
            src = read(os.path.join(root, name))
            for call in ("window.prompt", "window.confirm", "window.alert"):
                if call in src:
                    fail(
                        "окна",
                        f"{name}: {call} — используйте ask/confirm/notify из Dialogs.tsx",
                    )
            # Клик мимо окна не должен его закрывать: половину этих окон
            # заполняют руками, и промах мышью не повод потерять набранное.
            for tag in re.findall(r"<div[^>]*className=\"modal-backdrop\"[^>]*>", src, re.S):
                if "onClick" in tag:
                    fail(
                        "окна",
                        f"{name}: окно закрывается кликом мимо — уберите onClick с подложки",
                    )


# ------------------------------------------------- 9. бренд
def check_brand_colors() -> None:
    """Цвета берем из бренд-кита, а не подбираем на глаз."""
    tokens = json.loads(read("logos/brand-tokens.json"))["colors"]
    css = read("frontend/src/index.css").lower()
    for role, value in tokens.items():
        if value.lower() not in css:
            fail("бренд", f"цвет {role} ({value}) из бренд-кита не используется в теме")


# ------------------------------------------------- 10. запечатанные файлы
# Формат описан дважды: в панели (backend/app/sealedfile.py) и в аварийной
# утилите (ops/breakglass.py), которая живет без импортов из app/ намеренно -
# в аварии под рукой может не оказаться репозитория. Цена автономности -
# возможность разъехаться, и обнаружиться это должно СЕЙЧАС, а не в тот день,
# когда бэкап понадобится открыть.
SEALED_CONSTANTS = ("MAGIC", "CHUNK", "SCRYPT_N", "SCRYPT_R", "SCRYPT_P", "NONCE_PREFIX", "LENGTH")


def _constants(src: str, names) -> dict:
    out = {}
    for name in names:
        match = re.search(rf"^{name} = (.+?)(?:  #|$)", src, re.M)
        if match:
            out[name] = match.group(1).strip()
    return out


def check_sealed_format() -> None:
    panel = _constants(read("backend/app/sealedfile.py"), SEALED_CONSTANTS)
    tool = _constants(read("ops/breakglass.py"), SEALED_CONSTANTS)
    missing = set(SEALED_CONSTANTS) - set(panel) | set(SEALED_CONSTANTS) - set(tool)
    if missing:
        fail("запечатанный файл", f"не нашёл константы: {sorted(missing)}")
        return
    diff = {k: (panel[k], tool[k]) for k in SEALED_CONSTANTS if panel[k] != tool[k]}
    if diff:
        fail(
            "запечатанный файл",
            f"панель и ops/breakglass.py разошлись в формате: {diff}",
        )
    # Разбор доли Шамира тоже продублирован - префикс должен совпадать.
    prefix_panel = re.search(r'^PREFIX = "(.+?)"', read("backend/app/shamir.py"), re.M)
    prefix_tool = re.search(r'^SHARE_PREFIX = "(.+?)"', read("ops/breakglass.py"), re.M)
    if not prefix_panel or not prefix_tool:
        fail("запечатанный файл", "не нашёл префикс долей")
    elif prefix_panel.group(1) != prefix_tool.group(1):
        fail(
            "запечатанный файл",
            f"префикс долей разошёлся: панель {prefix_panel.group(1)}, "
            f"утилита {prefix_tool.group(1)}",
        )


# ------------------------------------------------- 11. скрипты обслуживания
def check_ops_scripts() -> None:
    """Скрипты обслуживания ничего не ставят в /usr: расписание запускает их
    прямо из каталога панели, а /usr часто исключают из бэкапа хоста, и после
    восстановления сервера обслуживание молча исчезло бы.

    И вторая половина: два языка одного установщика должны понимать одни и те
    же ключи - иначе инструкция из README работает в одной версии и не работает
    в другой."""
    for name in ("backup.sh", "panel-watchdog.sh", "quickstart.sh", "quickstart-ru.sh"):
        src = read(f"ops/{name}")
        for bad in re.findall(r"install -D -m\d+ \S+ (/usr\S*)", src):
            fail("скрипты", f"{name} ставит файл в {bad}: скрипты запускаются из каталога панели")

    def options(text: str) -> set[str]:
        body = text[text.find("while [ $# -gt 0 ]") :]
        body = body[: body.find("done")]
        return set(re.findall(r"^\s+(--[a-z-]+)\)", body, re.M))

    ru, en = options(read("ops/quickstart-ru.sh")), options(read("ops/quickstart.sh"))
    if ru != en:
        fail("скрипты", f"ключи quickstart разошлись: только в одном из них {sorted(ru ^ en)}")


# ------------------------------------------------- 14. полнота перевода
_T_CALL = re.compile(r"t\(\s*'((?:[^'\\]|\\.)*)'")
_MARKED = re.compile(r"//\s*i18n\b[^\n]*\n(?:[^\n]*\n){0,6}?[^\n]*=\s*[{\[](.*?)\n(?:\}|\])", re.S)
_LITERAL = re.compile(r"'((?:[^'\\]|\\.)*)'")
_CYRILLIC = re.compile("[\u0410-\u044f\u0401\u0451]")


def _translatable() -> set[str]:
    """Русские строки, которые панель показывает через перевод.

    Две группы: прямые вызовы `t('...')` и словари, помеченные комментарием
    `// i18n` - их значения тоже уходят в `t()`, но уже переменной, и
    регулярка по вызову их не видит.
    """
    out: set[str] = set()
    root = "frontend/src"
    for name in sorted(os.listdir(root)):
        if not name.endswith((".tsx", ".ts")) or ".test." in name:
            # Тесты интерфейсом не являются, а "it('...')" регулярка по вызову
            # `t(` честно принимает за строку панели: хвост имени совпадает.
            continue
        src = read(os.path.join(root, name))
        for line in _T_CALL.findall(src):
            text = line.replace("\\'", "'")
            if _CYRILLIC.search(text):
                out.add(text)
        for block in _MARKED.findall(src):
            for line in _LITERAL.findall(block):
                text = line.replace("\\'", "'")
                if _CYRILLIC.search(text):
                    out.add(text)
    return out


def check_translations() -> None:
    """Строка без перевода не ломается - она просто остается русской.

    Английский интерфейс от этого выглядит наполовину переведенным, и заметить
    это можно только переключив язык и пройдя по всем страницам руками.
    """
    dictionary = read("frontend/src/i18n.tsx")
    missing = []
    for text in _translatable():
        quoted = "'" + text.replace("'", "\\'") + "'"
        bare = "\n  " + text + ":"
        if quoted not in dictionary and bare not in dictionary:
            missing.append(text)

    for text in sorted(missing)[:10]:
        fail("перевод", f"нет английского для «{text[:60]}»")
    if len(missing) > 10:
        fail("перевод", f"и ещё {len(missing) - 10} строк без перевода")


def check_agent_build_image() -> None:
    """Агента собирают три места, и собирать они должны одинаково.

    backend/Dockerfile собирает бинарь, который панель раздает нодам,
    agent/Dockerfile - образ для Kubernetes, ops/agent_release.py - то, что
    подписывается. Подпись покрывает хеш бинаря, а панель отдает бинарь, только
    если хеш сошелся (api/machine.py). Подписали сборку одним Go, а образ собрал
    другим - и подключение серверов ломается ответом 500. Поэтому и версия Go
    закреплена до патча: другой патч дает другой бинарь.
    """
    images = {
        "backend/Dockerfile": re.search(
            r"^FROM (golang:\S+) AS agent", read("backend/Dockerfile"), re.M
        ),
        "agent/Dockerfile": re.search(
            r"^FROM (?:--platform=\S+ )?(golang:\S+) AS build", read("agent/Dockerfile"), re.M
        ),
        "ops/agent_release.py": re.search(
            r'^GO_IMAGE = "([^"]+)"', read("ops/agent_release.py"), re.M
        ),
    }
    found = {name: m.group(1) for name, m in images.items() if m}
    for name in images:
        if name not in found:
            fail("агент", f"не нашел образ golang в {name}")
    if len(set(found.values())) > 1:
        fail("агент", "агента собирают разные образы Go: " + ", ".join(
            f"{name} - {image}" for name, image in found.items()
        ))
    for name, image in found.items():
        if not re.fullmatch(r"golang:\d+\.\d+\.\d+-alpine[\d.]*(@sha256:[0-9a-f]{64})?", image):
            fail("агент", f"{name}: версия Go не закреплена до патча: {image}")
    # go vet и тесты в CI идут тем же Go, которым собирается бинарь.
    ci = re.search(r'go-version:\s*"([\d.]+)"', read(".github/workflows/ci.yml"))
    go = {re.sub(r"^golang:([\d.]+)-.*$", r"\1", image) for image in found.values()}
    if not ci or go != {ci.group(1)}:
        fail(
            "агент",
            f"CI проверяет агента на Go {ci.group(1) if ci else '?'}, "
            f"а собирается он на {', '.join(sorted(go))}",
        )
    # Флаги сборки тоже должны совпадать, и без -buildid= бинарь зависит даже от
    # комментариев: build ID считается от содержимого исходников.
    for name in images:
        text = read(name)
        for flag in ("-trimpath", "-s -w -buildid=", "CGO_ENABLED=0"):
            if flag not in text:
                fail("агент", f"{name}: в сборке агента нет {flag}")


def check_agent_api_errors() -> None:
    """Отказы машинного контура агент переводит на английский сам.

    Панель отвечает по-русски, а агент, который говорит по-английски,
    переводит известные ответы по таблице в agent/apierrors.go. Новый отказ без
    перевода дошел бы до англоязычного админа русской строкой посреди
    английского вывода.
    """
    table = set(re.findall(r'^\s*"([^"]+)":\s*"', read("agent/apierrors.go"), re.M))

    def details(path: str, only: str = "") -> set[str]:
        found: set[str] = set()
        tree = ast.parse(read(path))
        scope = tree
        if only:
            scope = next(
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == only
            )
        for node in ast.walk(scope):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "HTTPException"):
                continue
            candidates = list(node.args[1:2]) + [k.value for k in node.keywords if k.arg == "detail"]
            for arg in candidates:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
        return found

    wanted = details("backend/app/api/machine.py")
    # Запертая панель отвечает машинам из зависимости, общей с людьми.
    wanted |= details("backend/app/deps.py", only="get_unsealed_box")
    # Общие обработчики ошибок отвечают и машинам: нулевой символ в запросе,
    # значение, не сошедшееся с ключом. Их тексты - строки {"detail": ...} в
    # main.py, прямо или через константу модуля.
    main_tree = ast.parse(read("backend/app/main.py"))
    consts = {
        target.id: node.value.value
        for node in main_tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    for node in ast.walk(main_tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if not (isinstance(key, ast.Constant) and key.value == "detail"):
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                wanted.add(value.value)
            elif isinstance(value, ast.Name) and value.id in consts:
                wanted.add(consts[value.id])
    # Обработчики вида {"detail": str(exc)} отдают текст самого исключения:
    # его постоянные тексты (raise SecretNotFound("...")) машина тоже может
    # получить - например, ключ удалили между списком и чтением.
    passed_through: set[str] = set()
    for node in ast.walk(main_tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        uses_str = any(
            isinstance(n, ast.Call) and getattr(n.func, "id", "") == "str" for n in ast.walk(node)
        )
        for deco in node.decorator_list:
            if uses_str and isinstance(deco, ast.Call) and getattr(deco.func, "attr", "") == "exception_handler":
                for arg in deco.args:
                    name = getattr(arg, "attr", getattr(arg, "id", ""))
                    if name:
                        passed_through.add(name)
    for root, _, files in os.walk("backend/app"):
        for name in files:
            if not name.endswith(".py"):
                continue
            for node in ast.walk(ast.parse(read(os.path.join(root, name)))):
                if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
                    continue
                cls = getattr(node.exc.func, "attr", getattr(node.exc.func, "id", ""))
                if cls in passed_through and node.exc.args:
                    first = node.exc.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        wanted.add(first.value)
    missing = sorted(wanted - table)
    if missing:
        fail("агент", f"нет английского перевода отказов машинного контура: {missing}")


def _skeletons(node) -> list[str]:
    """Текст строки, f-строки или их склейки; на месте подстановок - {}."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return ["".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [a + b for a in _skeletons(node.left) or ["{}"] for b in _skeletons(node.right) or ["{}"]]
    if isinstance(node, ast.IfExp):
        return _skeletons(node.body) + _skeletons(node.orelse)
    return []


def _server_texts() -> set[str]:
    """Русские тексты, которые сервер отдает интерфейсу.

    Ошибки (raise, HTTPException), подробности журнала и ответов (detail=,
    warning=, note=), пункты правок через "; " (changes.append). Машинный
    контур и запуск панели сюда не входят: их переводит агент, а сообщения
    запуска читает администратор в логе контейнера.
    """
    skip_errors = {"api/machine.py", "cli.py", "bootstrap.py", "main.py"}
    out: set[str] = set()
    root = "backend/app"
    for dirpath, _, files in os.walk(root):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace("\\", "/")
            tree = ast.parse(read(path))
            found: list[str] = []
            # Текст отказа бывает вынесен в константу модуля: подставляем ее.
            constants = {
                target.id: node.value
                for node in tree.body
                if isinstance(node, ast.Assign)
                for target in node.targets
                if isinstance(target, ast.Name)
            }

            def texts(arg):
                if isinstance(arg, ast.Name) and arg.id in constants:
                    return _skeletons(constants[arg.id])
                return _skeletons(arg)

            for node in ast.walk(tree):
                if rel not in skip_errors:
                    call = node.exc if isinstance(node, ast.Raise) else node
                    if isinstance(call, ast.Call) and (
                        isinstance(node, ast.Raise)
                        or getattr(call.func, "id", getattr(call.func, "attr", "")) in ("HTTPException", "_fail")
                    ):
                        for arg in list(call.args) + [k.value for k in call.keywords if k.arg == "detail"]:
                            found += texts(arg)
                if isinstance(node, ast.Call):
                    if getattr(node.func, "id", getattr(node.func, "attr", "")) != "HTTPException":
                        for k in node.keywords:
                            if k.arg in ("detail", "warning", "note"):
                                found += _skeletons(k.value)
                    if getattr(node.func, "attr", "") == "append" and getattr(node.func.value, "id", "") == "changes":
                        for arg in node.args:
                            found += _skeletons(arg)
                # Ответы общих обработчиков: JSONResponse(content={"detail": ТЕКСТ}).
                if isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if isinstance(key, ast.Constant) and key.value == "detail":
                            found += texts(value)
                if isinstance(node, (ast.Assign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    names = {getattr(t, "id", getattr(t, "attr", "")) for t in targets}
                    if names & {"detail", "note", "warning"}:
                        prefix = "{}" if isinstance(node, ast.AugAssign) else ""
                        found += [prefix + text for text in _skeletons(node.value)]
            out |= {text for text in found if _CYRILLIC.search(text)}
    return out


def check_server_texts() -> None:
    """Сервер отвечает по-русски, английский интерфейс переводит у себя.

    Словарь лежит в frontend/src/serverText.ts: точные строки и заготовки с {}.
    Строку без перевода англоязычный человек увидел бы русской посреди
    английского окна, поэтому новое сообщение сервера должно приходить вместе
    с переводом.
    """
    src = read("frontend/src/serverText.ts")
    exact_block = src[src.index("const EXACT"):src.index("const TEMPLATES")]
    templates_block = src[src.index("const TEMPLATES"):src.index("function escape")]
    exact = {
        (quoted or bare).replace("\\'", "'")
        for quoted, bare in re.findall(r"^\s*(?:'((?:[^'\\]|\\.)*)'|([\wЀ-ӿ]+)):", exact_block, re.M)
    }
    templates = {t.replace("\\'", "'") for t in re.findall(r"\[\s*'((?:[^'\\]|\\.)*)',", templates_block)}
    dictionary = read("frontend/src/i18n.tsx")
    missing = []
    for text in sorted(_server_texts()):
        if "{}" in text:
            if text not in templates:
                missing.append(text)
        elif text not in exact and ("'" + text.replace("'", "\\'") + "'") not in dictionary:
            missing.append(text)
    for text in missing[:10]:
        fail("перевод", f'нет английского для текста сервера "{text[:70]}"')
    if len(missing) > 10:
        fail("перевод", f"и еще {len(missing) - 10} текстов сервера без перевода")


# ------------------------------------------------- 15. действия CI
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$", re.M)


def check_workflows() -> None:
    """Чужие действия в workflow закреплены коммитом, а не тегом.

    Тег у чужого действия передвигается, и следующий прогон выполнил бы уже
    другой код с токеном этого репозитория, при выпуске еще и с правом писать в
    GHCR. Коммит не передвинуть. Версия рядом, в комментарии, нужна человеку и
    Dependabot: он обновляет коммит и комментарий вместе.

    И права токена: без permissions на уровне workflow задание получает права
    по умолчанию, а они у репозитория бывают на запись во все.
    """
    folder = os.path.join(".github", "workflows")
    for name in sorted(os.listdir(folder)):
        if not name.endswith((".yml", ".yaml")):
            continue
        src = read(os.path.join(folder, name))
        for ref, tail in _USES.findall(src):
            if ref.startswith("./"):
                continue
            if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref) or not re.match(
                r"\s+#\s*v\d", tail
            ):
                fail("CI", f"{name}: {ref} не закреплен коммитом с версией в комментарии")
        if not re.search(r"^permissions:", src, re.M):
            fail("CI", f"{name}: нет permissions на уровне workflow")


# ------------------------------------------------- 16. базовые образы
def check_base_images() -> None:
    """Базовые образы закреплены digest'ом рядом с тегом.

    Тег у образа переезжает на новую сборку без всякого следа в репозитории,
    и тот же коммит через неделю давал бы другой образ. Агента это ломает
    прямо: его бинарь подписан по хешу, и другой golang под тем же тегом
    дал бы 500 вместо агента. Обновляет digest'ы Dependabot, отдельным PR,
    который проходит CI.
    """
    for path in ("backend/Dockerfile", "frontend/Dockerfile", "agent/Dockerfile"):
        for image in re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", read(path), re.M):
            if not re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", image):
                fail("образы", f"{path}: базовый образ не закреплен digest'ом: {image}")


# ------------------------------------------------- 17. хеши Python-пакетов
def check_python_hashes() -> None:
    """У каждой версии в constraints.txt есть хеши, и Dockerfile их требует.

    Образ ставит пакеты с --require-hashes, и версия без хеша оборвала бы
    сборку. Хуже, если флаг из Dockerfile пропадет: хеши останутся лежать в
    файле, а проверяться перестанут, и никто этого не заметит.
    """
    text = read(os.path.join("backend", "constraints.txt")).replace("\\\n", " ")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split()[0]
        if not re.fullmatch(r"[A-Za-z0-9][\w.-]*==[\w.+!-]+", name):
            fail("зависимости", f"constraints.txt: версия не закреплена через ==: {name}")
        elif not re.search(r"--hash=sha256:[0-9a-f]{64}", line):
            fail("зависимости", f"constraints.txt: у {name} нет хешей, запустите python ops/pin_hashes.py")
    if "--require-hashes" not in read(os.path.join("backend", "Dockerfile")):
        fail("зависимости", "backend/Dockerfile: pip install без --require-hashes, хеши не проверяются")


# ------------------------------------------------- невидимые символы
# Знаки нулевой ширины и смены направления строки (U+200B..U+200F,
# U+202A..U+202E, U+2060..U+2069, U+FEFF). В исходнике они делают так, что
# ревьюер видит одно, а Python или Go исполняют другое; GitHub помечает такой
# файл предупреждением. Нужны они только как \\uXXXX внутри строк.
_INVISIBLE = re.compile("[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2069\\ufeff]")
_TEXT_EXT = (".py", ".ts", ".tsx", ".go", ".sh", ".md", ".yml", ".yaml", ".json", ".html",
             ".css", ".conf", ".toml", ".ini", ".txt", ".mako", ".example")
_SKIP_DIRS = {"node_modules", ".venv", "dist", "__pycache__", ".git", "logos"}


def check_invisible_chars() -> None:
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if not name.endswith(_TEXT_EXT) and name not in ("Dockerfile", ".env.example"):
                continue
            path = os.path.join(root, name)
            try:
                text = read(path)
            except (UnicodeDecodeError, OSError):
                continue
            for number, line in enumerate(text.split("\n"), 1):
                if _INVISIBLE.search(line):
                    fail("невидимые символы", f"{path}:{number}: замените на \\uXXXX")


def main() -> int:
    for check in (
        check_agent_signature,
        check_agent_build_image,
        check_agent_api_errors,
        check_password_len,
        check_roles,
        check_audit_actions,
        check_env_names,
        check_machine_readonly,
        check_routes_are_guarded,
        check_actions_are_listed,
        check_no_browser_dialogs,
        check_version,
        check_brand_colors,
        check_sealed_format,
        check_ops_scripts,
        check_translations,
        check_server_texts,
        check_workflows,
        check_base_images,
        check_python_hashes,
        check_invisible_chars,
    ):
        try:
            check()
        except FileNotFoundError as exc:
            fail(check.__name__, f"нет файла: {exc.filename}")

    if PROBLEMS:
        print("Самопроверка нашла расхождения:\n")
        for problem in PROBLEMS:
            print(" ", problem)
        return 1
    print("Самопроверка: расхождений нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
