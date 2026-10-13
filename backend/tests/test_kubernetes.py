"""Кластер: под входит своим ServiceAccount-токеном, без статического секрета."""

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import kube
from tests.conftest import login

ISSUER = "https://kubernetes.example/cluster-a"
AUDIENCE = "sekvyr"


def _keypair():
    """Ключ "кластера": настоящую подпись подделать нечем, поэтому в тестах она
    настоящая, просто ключ свой."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()

    def b64(value: int, length: int) -> str:
        import base64

        return base64.urlsafe_b64encode(value.to_bytes(length, "big")).decode().rstrip("=")

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "use": "sig",
                "alg": "RS256",
                "n": b64(numbers.n, 256),
                "e": b64(numbers.e, 3),
            }
        ]
    }
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem, json.dumps(jwks)


def _sa_token(
    pem: bytes,
    *,
    namespace: str = "billing",
    account: str = "app",
    audience: str = AUDIENCE,
    issuer: str = ISSUER,
    ttl: int = 600,
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": [audience],
        "exp": now + ttl,
        "iat": now,
        "sub": f"system:serviceaccount:{namespace}:{account}",
        "kubernetes.io": {"namespace": namespace, "serviceaccount": {"name": account}},
    }
    return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": "test-key"})


async def _cluster(client, owner_headers, jwks: str) -> dict:
    res = await client.post(
        "/api/machines/clusters",
        headers=owner_headers,
        json={"name": "cluster-a", "issuer": ISSUER, "audience": AUDIENCE, "jwks": jwks},
    )
    assert res.status_code == 201, res.text
    return res.json()


async def _identity(client, owner_headers, cluster_id: int, env_id: int) -> dict:
    res = await client.post(
        "/api/machines",
        headers=owner_headers,
        json={
            "name": "billing/app",
            "cluster_id": cluster_id,
            "k8s_namespace": "billing",
            "k8s_service_account": "app",
        },
    )
    assert res.status_code == 201, res.text
    machine = res.json()
    granted = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "machine",
            "subject_id": machine["id"],
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": ["read"],
            "effect": "allow",
        },
    )
    assert granted.status_code == 201, granted.text
    return machine


async def test_pod_reads_secrets_without_any_static_secret(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Ради этого все и затевалось: на ноде не лежит ничего, что можно украсть
    и потом использовать где угодно."""
    pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    machine = await _identity(client, owner_headers, cluster["id"], env_id)
    assert machine["client_secret"] == ""

    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "секрет"},
    )

    got = await client.post(
        "/api/v1/machine/token", json={"kubernetes_token": _sa_token(pem)}
    )
    assert got.status_code == 200, got.text
    values = await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": "Bearer " + got.json()["access_token"]},
        params={"project": "billing", "env": "prod"},
    )
    assert values.status_code == 200
    assert values.json()["values"][0]["value"] == "секрет"


async def test_token_for_another_audience_is_refused(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Токен, выписанный "для kubernetes", к панели подходить не должен: под
    просит отдельный, и такой токен бесполезен где-то еще."""
    pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    res = await client.post(
        "/api/v1/machine/token",
        json={"kubernetes_token": _sa_token(pem, audience="kubernetes")},
    )
    assert res.status_code == 401


async def test_token_from_a_stranger_key_is_refused(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Подпись чужим ключом - это и есть подделка, и проверяется она первой."""
    pem, jwks = _keypair()
    other_pem, _ = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    res = await client.post(
        "/api/v1/machine/token", json={"kubernetes_token": _sa_token(other_pem)}
    )
    assert res.status_code == 401


async def test_unknown_service_account_is_refused(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Закрыто по умолчанию: настоящий токен настоящего кластера ничего не дает,
    пока для этого ServiceAccount не заведена личность."""
    pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    res = await client.post(
        "/api/v1/machine/token",
        json={"kubernetes_token": _sa_token(pem, namespace="billing", account="другой")},
    )
    assert res.status_code == 401


async def test_expired_token_is_refused(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    res = await client.post(
        "/api/v1/machine/token", json={"kubernetes_token": _sa_token(pem, ttl=-600)}
    )
    assert res.status_code == 401


async def test_cluster_identity_has_no_secret_to_rotate(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """У кластерной личности нечего менять: секрета нет, и "сменить" его -
    предложение, за которым ничего не стоит."""
    _pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    machine = await _identity(client, owner_headers, cluster["id"], env_id)
    res = await client.post(f"/api/machines/{machine['id']}/secret", headers=owner_headers)
    assert res.status_code == 400


async def test_broken_jwks_is_refused_at_registration(client: httpx.AsyncClient, owner_headers):
    """Запись с нечитаемыми ключами выглядела бы рабочей до первого пода."""
    res = await client.post(
        "/api/machines/clusters",
        headers=owner_headers,
        json={"name": "битый", "issuer": ISSUER, "audience": AUDIENCE, "jwks": "{}"},
    )
    assert res.status_code == 400


async def test_basic_auth_works_for_external_operators(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """External Secrets Operator ходит одним запросом: два шага (сначала токен,
    потом чтение) он не делает, поэтому чтение принимает и basic-пару."""
    import base64

    made = await client.post(
        "/api/machines",
        headers=owner_headers,
        json={"name": "eso", "description": "", "allow_ips": "", "expires_at": ""},
    )
    machine = made.json()
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "machine",
            "subject_id": machine["id"],
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": ["read"],
            "effect": "allow",
        },
    )
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "API_KEY", "value": "значение"},
    )

    pair = f"{machine['client_id']}:{machine['client_secret']}".encode()
    res = await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": "Basic " + base64.b64encode(pair).decode()},
        params={"project": "billing", "env": "prod"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["values"][0]["value"] == "значение"

    wrong = await client.get(
        "/api/v1/machine/secrets",
        headers={
            "Authorization": "Basic "
            + base64.b64encode(f"{machine['client_id']}:не тот".encode()).decode()
        },
        params={"project": "billing", "env": "prod"},
    )
    assert wrong.status_code == 401


async def test_removing_cluster_revokes_rights_of_its_identities(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Права личностей уходят вместе с кластером. Раньше их оставлял каскад базы:
    на стенде так висело право удаленной личности, показанное номером "#3"."""
    _pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    machine = await _identity(client, owner_headers, cluster["id"], env_id)

    res = await client.delete(
        f"/api/machines/clusters/{cluster['id']}",
        headers=owner_headers,
        params={"confirm": "cluster-a"},
    )
    assert res.status_code == 204, res.text

    machines = (await client.get("/api/machines", headers=owner_headers)).json()
    assert all(row["id"] != machine["id"] for row in machines)
    policies = (await client.get("/api/policies", headers=owner_headers)).json()
    assert not [
        row
        for row in policies
        if row["subject_type"] == "machine" and row["subject_id"] == machine["id"]
    ]


async def test_new_cluster_keys_keep_identities_and_rights(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Кластер сменил ключи подписи. Раньше запись можно было только удалить и
    завести заново, и вместе с ней уходили личности подов и их права."""
    old_pem, old_jwks = _keypair()
    new_pem, new_jwks = _keypair()
    cluster = await _cluster(client, owner_headers, old_jwks)
    machine = await _identity(client, owner_headers, cluster["id"], env_id)

    async def login(pem: bytes) -> int:
        res = await client.post("/api/v1/machine/token", json={"kubernetes_token": _sa_token(pem)})
        return res.status_code

    assert await login(new_pem) == 401

    bad = await client.patch(
        f"/api/machines/clusters/{cluster['id']}", headers=owner_headers, json={"jwks": "{}"}
    )
    assert bad.status_code == 400
    res = await client.patch(
        f"/api/machines/clusters/{cluster['id']}",
        headers=owner_headers,
        json={"issuer": "", "audience": "", "jwks": new_jwks},
    )
    assert res.status_code == 200, res.text
    assert res.json()["issuer"] == ISSUER
    assert res.json()["identities"] == 1

    assert await login(new_pem) == 200
    assert await login(old_pem) == 401
    policies = (await client.get("/api/policies", headers=owner_headers)).json()
    assert [row for row in policies if row["subject_id"] == machine["id"]]
    log = (await client.get("/api/audit", headers=owner_headers)).json()["entries"]
    assert [e["detail"] for e in log if e["action"] == "cluster_updated"] == ["ключи"]


async def test_maintainer_cannot_swap_keys_of_a_cluster_reaching_beyond_them(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Своими ключами кластера можно выписывать токены его подам. Поэтому менять
    ключи может только тот, кто сам читает все, что эти поды."""
    _old_pem, old_jwks = _keypair()
    _new_pem, new_jwks = _keypair()
    cluster = await _cluster(client, owner_headers, old_jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    res = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "maint", "password": "maint-pass-2026", "role": "maintainer"},
    )
    assert res.status_code == 201, res.text
    maint = await login(client, "maint", "maint-pass-2026")
    res = await client.patch(
        f"/api/machines/clusters/{cluster['id']}", headers=maint, json={"jwks": new_jwks}
    )
    assert res.status_code == 403
    # Кластер без выданных окружений ответственному править можно.
    other = await client.post(
        "/api/machines/clusters",
        headers=maint,
        json={"name": "cluster-b", "issuer": ISSUER + "-b", "audience": AUDIENCE, "jwks": old_jwks},
    )
    assert other.status_code == 201, other.text
    res = await client.patch(
        f"/api/machines/clusters/{other.json()['id']}", headers=maint, json={"jwks": new_jwks}
    )
    assert res.status_code == 200, res.text


def _forged(header: dict, payload: dict, secret: bytes = b"public-key-as-hmac") -> str:
    """Токен с любым заголовком и подписью HMAC: так подделывают, когда
    проверка берет алгоритм из заголовка."""
    import base64
    import hashlib
    import hmac

    def part(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signing = f"{part(header)}.{part(payload)}"
    sig = hmac.new(secret, signing.encode(), hashlib.sha256).digest()
    return signing + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


async def test_token_algorithm_comes_from_the_cluster_key(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Алгоритм берется у ключа кластера: подпись HMAC или "none" в заголовке
    дают аккуратный отказ, а не 500 мимо лимитера."""
    _pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "exp": now + 600,
        "iat": now,
        "sub": "system:serviceaccount:billing:app",
    }
    for alg in ("HS256", "none", "ES256"):
        token = _forged({"alg": alg, "kid": "test-key", "typ": "JWT"}, payload)
        res = await client.post("/api/v1/machine/token", json={"kubernetes_token": token})
        assert res.status_code == 401, f"{alg}: {res.status_code} {res.text}"


async def test_long_lived_token_is_refused(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Удаления пода панель не видит, поэтому токен дольше суток - это снова
    статический секрет. Час, как у kubelet, и даже сутки проходят."""
    pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    year = await client.post(
        "/api/v1/machine/token", json={"kubernetes_token": _sa_token(pem, ttl=365 * 86400)}
    )
    assert year.status_code == 401
    day = await client.post(
        "/api/v1/machine/token", json={"kubernetes_token": _sa_token(pem, ttl=86400)}
    )
    assert day.status_code == 200, day.text


async def test_one_identity_per_service_account(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Вторая личность на тот же ServiceAccount перехватила бы его поды."""
    _pem, jwks = _keypair()
    cluster = await _cluster(client, owner_headers, jwks)
    await _identity(client, owner_headers, cluster["id"], env_id)
    again = await client.post(
        "/api/machines",
        headers=owner_headers,
        json={
            "name": "billing/app-2",
            "cluster_id": cluster["id"],
            "k8s_namespace": "billing",
            "k8s_service_account": "app",
        },
    )
    assert again.status_code == 409, again.text


@pytest.mark.parametrize("jwks", ["true", "[]", "1", '"x"', '{"keys": 5}', '{"keys": [1, "a", null]}'])
def test_jwks_that_is_not_an_object_is_refused(jwks):
    """Нашел фаззинг схемы: JSON, который не объект, ронял создание кластера с 500."""
    with pytest.raises(kube.TokenError):
        kube.load_keys(jwks)
