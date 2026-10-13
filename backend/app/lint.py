"""Замечания к значениям: то, что почти наверняка ошибка.

Панель хранит чужие значения и не должна их оценивать - кроме случаев, где
ошибка видна без всякого понимания смысла. Пробел на конце пароля, `changeme` в
проде, отладка, включенная на боевом окружении: это не "стиль", это причина
инцидента, и заметить её на экране дешевле, чем в три часа ночи по логам.

Правило отбора проверок одно: ложное срабатывание дороже пропуска. Замечание,
которое человек привыкает игнорировать, хуже, чем его отсутствие, поэтому здесь
только те случаи, где ошибку видно наверняка.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Значения, которые в живом окружении не значат ничего, кроме "забыли заменить".
PLACEHOLDERS = {
    "changeme",
    "change_me",
    "change-me",
    "example",
    "password",
    "passw0rd",
    "qwerty",
    "secret",
    "test",
    "todo",
    "xxx",
    "xxxx",
    "your_value_here",
    "123456",
    "12345678",
}

# Имена, за которыми стоит секрет: по ним строже требования к пустоте и длине.
SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY|DSN|CREDENTIAL)",
    re.I,
)

DEBUG_NAME = re.compile(r"(^|_)(DEBUG|VERBOSE|TRACE)($|_)", re.I)
DEBUG_ON = {"1", "true", "yes", "on", "да"}

LOCAL_HOST = re.compile(r"\b(localhost|127\.0\.0\.1|::1|host\.docker\.internal)\b", re.I)

# Ключи платежных и почтовых сервисов помечают тестовый режим прямо в значении.
TEST_KEY = re.compile(r"\b(?:(?:sk|pk|rk)_test_\w+|test_[a-z0-9]{8,}|sandbox)\b", re.I)

# Окружения, к которым применяются "боевые" проверки. Имя - единственное, что
# панель про окружение знает: специального флага "это прод" у нее нет и заводить
# его ради подсказок дороже, чем разобрать имя.
PRODUCTION = re.compile(r"^(prod|production|prd|live|боевое)$", re.I)


# Текст замечания живет рядом с кодом, а не в месте, где проверка написана:
# принятые замечания панель показывает списком, и ей нужен текст по коду.
TITLES: dict[str, str] = {
    "trailing_space": "значение начинается или кончается пробелом",
    "empty_secret": "пусто, хотя имя обещает секрет",
    "placeholder": "это заготовка, а не значение",
    "short_secret": "слишком короткое для секрета",
    "debug_on_prod": "отладка включена на боевом окружении",
    "local_in_prod": "локальный адрес на боевом окружении",
    "test_key_in_prod": "тестовый ключ на боевом окружении",
    "plain_http": "адрес без шифрования: http вместо https",
}


@dataclass(frozen=True)
class Note:
    """Замечание к одному ключу.

    `code` - машинное имя проверки. Оно нужно, чтобы человек мог сказать "так и
    надо" про конкретный случай, а не про все замечания сразу: текст со
    временем можно переписать, код останется прежним.

    `level` - насколько это похоже на ошибку.
    """

    path: str
    name: str
    code: str
    level: str  # "bad" - почти наверняка ошибка, "warn" - стоит посмотреть
    text: str


def _production(environment: str) -> bool:
    return bool(PRODUCTION.match(environment.strip()))


def inspect(name: str, path: str, value: str, environment: str) -> list[Note]:
    """Замечания к одному значению. Пустой список - вопросов нет."""
    notes: list[Note] = []

    def add(code: str, level: str) -> None:
        notes.append(Note(path=path, name=name, code=code, level=level, text=TITLES[code]))

    secret_like = bool(SECRET_NAME.search(name))

    # 1. Хвост из пробелов - но только у однострочного значения. Файл в
    # значении (JSON ключа сервиса, кусок compose) почти всегда кончается
    # переводом строки, и это норма формата, а не прилипший при копировании
    # хвост. У однострочного же пробел на конце - самая частая и самая
    # незаметная поломка: приложение получает не то, что видно на экране.
    if value and "\n" not in value and value != value.strip():
        add("trailing_space", "bad")

    if not value:
        if secret_like:
            add("empty_secret", "bad")
    else:
        low = value.strip().lower()

        # 2. Заглушка вместо значения.
        if low in PLACEHOLDERS:
            add("placeholder", "bad")

        # 3. Короткий секрет. Восемь символов - не "слабый пароль", а "сюда
        # что-то положили на минуту и забыли".
        if secret_like and len(value.strip()) < 8:
            add("short_secret", "warn")

        # 4. Отладка на боевом окружении.
        if _production(environment) and DEBUG_NAME.search(name) and low in DEBUG_ON:
            add("debug_on_prod", "bad")

        # 5. Локальный адрес на боевом окружении.
        if _production(environment) and LOCAL_HOST.search(value):
            add("local_in_prod", "bad")

        # 6. Тестовый ключ на боевом окружении.
        if _production(environment) and TEST_KEY.search(value):
            add("test_key_in_prod", "bad")

        # 7. Незашифрованный протокол наружу. Локальные адреса не в счет: там
        # http - норма.
        if value.strip().lower().startswith("http://") and not LOCAL_HOST.search(value):
            add("plain_http", "warn")

    return notes
