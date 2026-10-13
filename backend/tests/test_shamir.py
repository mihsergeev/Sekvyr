"""Доли корневого ключа."""

import itertools
import os

import pytest

from app import shamir


def test_any_threshold_subset_restores():
    secret = os.urandom(32)
    parts = shamir.split(secret, shares=5, threshold=3)
    # проверяем ВСЕ тройки, а не одну: ошибка в интерполяции обычно проявляется
    # на конкретных наборах номеров, а не на первом попавшемся
    for subset in itertools.combinations(parts, 3):
        assert shamir.combine(list(subset)) == secret


def test_below_threshold_gives_nothing():
    secret = os.urandom(32)
    parts = shamir.split(secret, shares=5, threshold=3)
    guess = shamir.combine(parts[:2])
    assert guess != secret
    # и это видно по отпечатку - панель не примет такой ключ за настоящий
    assert not shamir.matches(guess, parts[:2])


def test_corrupted_share_is_rejected():
    parts = shamir.split(os.urandom(32), shares=3, threshold=2)
    broken = parts[0][:-1] + ("A" if parts[0][-1] != "A" else "B")
    with pytest.raises(shamir.ShareError):
        shamir.combine([broken, parts[1]])


def test_same_share_twice_is_not_two_shares():
    """Иначе порог 3 обходится одной долей, поданной трижды."""
    parts = shamir.split(os.urandom(32), shares=5, threshold=3)
    with pytest.raises(shamir.ShareError):
        shamir.combine([parts[0], parts[0], parts[0]])


def test_shares_from_different_keys_do_not_mix():
    a = shamir.split(os.urandom(32), shares=3, threshold=2)
    b = shamir.split(os.urandom(32), shares=3, threshold=2)
    with pytest.raises(shamir.ShareError):
        shamir.combine([a[0], b[1]])


def test_share_looks_like_a_share():
    parts = shamir.split(os.urandom(32), shares=2, threshold=2)
    assert all(p.startswith(shamir.PREFIX) for p in parts)
    assert shamir.share_index(parts[1]) == 2
    with pytest.raises(shamir.ShareError):
        shamir.share_index("просто строка")


def test_threshold_must_be_sane():
    with pytest.raises(ValueError):
        shamir.split(os.urandom(32), shares=3, threshold=4)
