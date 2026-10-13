"""Формат .env: значение доходит до приложения тем же, каким его задали.

Записи сверены с настоящим docker compose: в двойных кавычках он подставляет
переменные, поэтому "P@ss$word1" доходил до приложения как "P@ss". Те же
правила у агента (agent/main.go, quote; тест agent/quote_test.go) и у
аварийной утилиты ops/breakglass.py: все трое пишут один и тот же файл.
"""

import importlib.util
from pathlib import Path

import pytest

from app.secrets_store import _quote, parse_env

CASES = [
    ("", '""'),
    ("plain", "plain"),
    ("user@db:5432/app", "user@db:5432/app"),
    ("P@ss$word1", "'P@ss$word1'"),
    ("a b", "'a b'"),
    ("a;rm -rf /", "'a;rm -rf /'"),
    ("https://x/y?a=1&b=2", "'https://x/y?a=1&b=2'"),
    ("пароль", "'пароль'"),
    ("`cmd`", "'`cmd`'"),
    ("line one\nline two", "'line one\nline two'"),
    ("C:\\path\\to", "'C:\\path\\to'"),
    ("ends\\", '"ends\\\\"'),
    ("it's $5", '"it\'s \\$5"'),
    ("it's `cmd`", '"it\'s `cmd`"'),
    ('a"b\'c', '"a\\"b\'c"'),
    ("cr\rx", '"cr\\rx"'),
    ("<?php\nreturn ['db' => $x];\n", '"<?php\nreturn [\'db\' => \\$x];\n"'),
]


def _breakglass():
    path = Path(__file__).resolve().parents[2] / "ops" / "breakglass.py"
    spec = importlib.util.spec_from_file_location("breakglass", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("value,written", CASES)
def test_quote(value, written):
    assert _quote(value) == written


@pytest.mark.parametrize("value,written", CASES)
def test_breakglass_writes_the_same(value, written):
    assert _breakglass().quote(value) == written


@pytest.mark.parametrize("value,_written", CASES)
def test_import_reads_back_what_export_wrote(value, _written):
    """Файл, выгруженный отсюда, возвращается тем же значением."""
    text = f"V={_quote(value)}\nW=after\n"
    assert parse_env(text) == [("/", "V", value), ("/", "W", "after")]


def test_single_quotes_with_comment_and_trailing_spaces():
    text = "A='x y' # заметка\nB='first line  \nsecond'\n"
    assert parse_env(text) == [("/", "A", "x y"), ("/", "B", "first line  \nsecond")]


# Символы, которые str.splitlines() считает концом строки, хотя для .env это
# обычная часть значения. Импорт резал по ним, и круг выгрузка -> импорт
# портил значение, а обломок вида "x=y" заводил лишний ключ.
SPLITLINES_TRAPS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]


@pytest.mark.parametrize("char", SPLITLINES_TRAPS)
def test_unicode_line_breaks_stay_inside_the_value(char):
    value = f"a{char}B=c'd"
    text = f"K={_quote(value)}\nNEXT=1\n"
    assert parse_env(text) == [("/", "K", value), ("/", "NEXT", "1")]


def test_random_values_survive_export_and_import():
    """Тысячи случайных значений из "опасного" алфавита: что выгрузка
    записала, то импорт и прочитал, и ни одного лишнего ключа."""
    import random

    rnd = random.Random(20261011)
    alphabet = list("'\"\\$`#=;&|<>(){}[]*?!~^%,.:/@+- \tab01") + ["\n", "\r"] + SPLITLINES_TRAPS
    alphabet += ["é", "中", "🚀", "\u00a0", "\ufeff", "\u202e", "\x01", "\x1b", "\x7f"]
    values = [
        "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 24))) for _ in range(3000)
    ]
    text = "".join(f"K{i}={_quote(v)}\n" for i, v in enumerate(values))
    assert parse_env(text) == [("/", f"K{i}", v) for i, v in enumerate(values)]


def test_windows_line_endings_are_read():
    text = "A=1\r\nB='two\r\nlines'\r\nC=\"x\ny\"\r\n"
    assert parse_env(text) == [("/", "A", "1"), ("/", "B", "two\nlines"), ("/", "C", "x\ny")]
