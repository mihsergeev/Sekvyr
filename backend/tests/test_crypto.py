"""Шифрование значений и привязка шифротекста к его месту."""

import pytest

from app import crypto


def test_roundtrip():
    key = crypto.new_key()
    aad = crypto.value_aad(env_id=1, secret_id=2, name="DB_PASSWORD", version=3)
    nonce, ct = crypto.encrypt(key, b"s3cret", aad)
    assert crypto.decrypt(key, nonce, ct, aad) == b"s3cret"


def test_wrong_key_fails():
    aad = crypto.value_aad(env_id=1, secret_id=2, name="A", version=1)
    nonce, ct = crypto.encrypt(crypto.new_key(), b"x", aad)
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(crypto.new_key(), nonce, ct, aad)


@pytest.mark.parametrize(
    "moved",
    [
        {"env_id": 2},  # перенесли строку в другое окружение
        {"secret_id": 99},  # подставили на место другого ключа
        {"name": "OTHER"},  # переименовали в обход панели
        {"version": 2},  # выдали старую версию за новую
    ],
)
def test_ciphertext_is_bound_to_its_place(moved):
    """Строку с шифротекстом нельзя переставить в базе: любое изменение адреса
    ломает расшифровку, а не дает "просто другое значение"."""
    key = crypto.new_key()
    place = {"env_id": 1, "secret_id": 2, "name": "DB_PASSWORD", "version": 1}
    nonce, ct = crypto.encrypt(key, b"prod-password", crypto.value_aad(**place))
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, nonce, ct, crypto.value_aad(**{**place, **moved}))


def test_nonce_is_never_reused():
    """Повторение пары ключ+nonce в GCM компрометирует не запись, а сам ключ."""
    key = crypto.new_key()
    aad = crypto.value_aad(env_id=1, secret_id=1, name="A", version=1)
    nonces = {crypto.encrypt(key, b"same value", aad)[0] for _ in range(200)}
    assert len(nonces) == 200
