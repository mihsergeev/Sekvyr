"""Машины людей, которые ушли (1.0.1).

Падает на 1.0.0: сервер отключенного ответственного получал токен и читал
прод дальше, право, выданное машине человеком, переживало его собственное
право, а забрать сервер или кластер на себя было нечем.
"""

from tests.conftest import login
from tests.pass11_helpers import PASS, _policy, _project_id, _put, _threshold, _user
from tests.test_kubernetes import _keypair, _sa_token


# --- 3. машины людей, которые ушли ------------------------------------------


async def _lead_machine(client, oh, env_id) -> tuple[int, dict, dict]:
    mid = await _user(client, oh, "lead", "maintainer")
    pol = await _policy(
        client, oh, subject_type="user", subject_id=mid, environment_id=env_id,
        actions=["list", "read"],
    )
    lead = await login(client, "lead", PASS)
    res = await client.post(
        "/api/machines", headers=lead,
        json={"name": "lead-laptop", "description": "", "allow_ips": "", "expires_at": ""},
    )
    assert res.status_code == 201, res.text
    machine = res.json()
    res = await client.post(
        f"/api/machines/{machine['id']}/attach", headers=lead, json={"environment_id": env_id}
    )
    assert res.status_code == 200, res.text
    return mid, pol, machine


async def _machine_read(client, machine, token=None):
    if token is None:
        tok = await client.post(
            "/api/v1/machine/token",
            json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
        )
        if tok.status_code != 200:
            return tok
        token = tok.json()["access_token"]
    return await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": f"Bearer {token}"},
        params={"project": "billing", "env": "prod"},
    )


async def test_machine_of_disabled_maintainer_stops_reading(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "DB_PASSWORD", "prod-secret")).status_code == 200
    mid, _pol, machine = await _lead_machine(client, oh, env_id)
    tok = await client.post(
        "/api/v1/machine/token",
        json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
    )
    assert tok.status_code == 200
    early = tok.json()["access_token"]
    assert (await _machine_read(client, machine, early)).status_code == 200

    deps = await client.get(f"/api/users/{mid}/dependents", headers=oh)
    assert deps.json() == {"machines": 1, "clusters": 0, "proposals": 0}
    res = await client.patch(f"/api/users/{mid}", headers=oh, json={"disabled": True})
    assert res.status_code == 200, res.text
    assert (res.json()["machines_stopped"], res.json()["clusters_stopped"]) == (1, 0)

    # Новый токен не выдается, а уже выданный ничего не открывает.
    tok = await client.post(
        "/api/v1/machine/token",
        json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
    )
    assert tok.status_code == 401, tok.text
    assert (await _machine_read(client, machine, early)).status_code == 403
    listed = {m["id"]: m for m in (await client.get("/api/machines", headers=oh)).json()}
    assert listed[machine["id"]]["stalled"] is True

    # Владелец забирает сервер на себя, и тот снова читает.
    res = await client.post(f"/api/machines/{machine['id']}/adopt", headers=oh)
    assert res.status_code == 200, res.text
    assert res.json()["created_by"] == "owner" and res.json()["stalled"] is False
    read = await _machine_read(client, machine)
    assert read.status_code == 200, read.text
    assert {r["name"]: r["value"] for r in read.json()["values"]}["DB_PASSWORD"] == "prod-secret"


async def test_machine_stops_when_granter_loses_environment(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "DB_PASSWORD", "prod-secret")).status_code == 200
    mid, pol, machine = await _lead_machine(client, oh, env_id)
    assert (await _machine_read(client, machine)).status_code == 200
    assert (await client.delete(f"/api/policies/{pol['id']}", headers=oh)).status_code == 204

    # Ответственный на месте, токен машине дается, но окружение, которое он
    # больше не читает, через нее не читается тоже.
    read = await _machine_read(client, machine)
    assert read.status_code == 403, read.text
    whoami = await client.post(
        "/api/v1/machine/token",
        json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
    )
    me = await client.get(
        "/api/v1/machine/whoami",
        headers={"Authorization": f"Bearer {whoami.json()['access_token']}"},
    )
    assert me.json()["environments"] == []

    # Забрать на себя может только тот, кто сам читает все, что открывает сервер.
    await _user(client, oh, "other", "maintainer")
    other = await login(client, "other", PASS)
    res = await client.post(f"/api/machines/{machine['id']}/adopt", headers=other)
    assert res.status_code == 403, res.text
    res = await client.post(f"/api/machines/{machine['id']}/adopt", headers=oh)
    assert res.status_code == 200, res.text
    assert (await _machine_read(client, machine)).status_code == 200


async def test_pods_stop_when_cluster_keeper_is_disabled(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "DB_PASSWORD", "prod-secret")).status_code == 200
    mid = await _user(client, oh, "lead", "maintainer")
    await _policy(
        client, oh, subject_type="user", subject_id=mid, environment_id=env_id,
        actions=["list", "read"],
    )
    lead = await login(client, "lead", PASS)
    pem, jwks = _keypair()
    cluster = await client.post(
        "/api/machines/clusters", headers=lead,
        json={"name": "cluster-a", "issuer": "https://kubernetes.example/cluster-a",
              "audience": "sekvyr", "jwks": jwks},
    )
    assert cluster.status_code == 201, cluster.text
    pod = await client.post(
        "/api/machines", headers=oh,
        json={"name": "billing/app", "cluster_id": cluster.json()["id"],
              "k8s_namespace": "billing", "k8s_service_account": "app"},
    )
    assert pod.status_code == 201, pod.text
    await _policy(
        client, oh, subject_type="machine", subject_id=pod.json()["id"], environment_id=env_id,
        actions=["read"],
    )

    async def pod_token():
        return await client.post(
            "/api/v1/machine/token",
            json={"kubernetes_token": _sa_token(pem, issuer="https://kubernetes.example/cluster-a")},
        )

    assert (await pod_token()).status_code == 200
    res = await client.patch(f"/api/users/{mid}", headers=oh, json={"disabled": True})
    assert (res.json()["machines_stopped"], res.json()["clusters_stopped"]) == (0, 1)
    assert (await pod_token()).status_code == 401

    res = await client.post(f"/api/machines/clusters/{cluster.json()['id']}/adopt", headers=oh)
    assert res.status_code == 200, res.text
    tok = await pod_token()
    assert tok.status_code == 200, tok.text
    read = await _machine_read(client, {}, tok.json()["access_token"])
    assert read.status_code == 200, read.text


async def test_dependents_count_pending_proposals(client, owner_headers, env_id):
    """Окно отключения говорит и о правках, которые снимутся: у разработчика
    серверов нет, а ожидающая правка есть."""
    oh = owner_headers
    pid = await _project_id(client, oh)
    await _threshold(client, oh, 30)
    did = await _user(client, oh, "dev", "developer")
    await _policy(
        client, oh, subject_type="user", subject_id=did, project_id=pid,
        actions=["list", "read", "write"],
    )
    dev = await login(client, "dev", PASS)
    assert (await _put(client, dev, env_id, "API_KEY", "x")).json()["pending"] is True
    deps = await client.get(f"/api/users/{did}/dependents", headers=oh)
    assert deps.status_code == 200, deps.text
    assert deps.json() == {"machines": 0, "clusters": 0, "proposals": 1}
    lead = await _user(client, oh, "lead", "maintainer")
    res = await client.get(f"/api/users/{lead}/dependents", headers=await login(client, "lead", PASS))
    assert res.status_code == 403  # о равном не спрашивают
