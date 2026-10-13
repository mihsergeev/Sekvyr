#!/usr/bin/env python3
"""Живая проверка прав: ходит по РАБОТАЮЩЕЙ панели и пробует достать чужое.

Зачем отдельно от тестов. Тесты проверяют код, а эта проверка - установку: тот
самый экземпляр, с его миграциями, его политиками и его настройками. Между
"в тестах права работают" и "на этой панели права работают" помещается,
например, недопримененная миграция или маршрут, добавленный в обход общей
проверки.

Скрипт заводит временные учетки, выдает им права, дергает API от их имени и
убирает за собой: учетки отключаются (удалять их нельзя - иначе из журнала
пропадут имена), политики и тестовый проект удаляются.

    python ops/audit_live.py --url https://sekvyr.example.com \\
        --owner admin --password '...'

Код возврата 1 = панель отдала то, что не должна была.
"""

from __future__ import annotations

import argparse
import secrets
import sys

import httpx

PREFIX = "sekvyr-audit"
PASSWORD = "audit-" + secrets.token_urlsafe(12)

PROBLEMS: list[str] = []

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")


def check(ok: bool, what: str) -> None:
    print(("  ok  " if ok else "ПЛОХО ") + what)
    if not ok:
        PROBLEMS.append(what)


def refused(res: httpx.Response, because: str, code: int = 403) -> bool:
    """Отказ именно по проверяемой причине. Голый код 403 засчитывал и отказ по
    другой причине (нет права заводить окружения вовсе), и проверка правила
    "копировать можно только читаемое" проходила, ничего не проверив."""
    if res.status_code != code:
        return False
    try:
        detail = res.json().get("detail", "")
    except ValueError:
        return False
    return because in str(detail)


class Panel:
    def __init__(self, url: str, verify: bool) -> None:
        self.client = httpx.Client(base_url=url.rstrip("/"), timeout=30, verify=verify)

    def login(self, username: str, password: str) -> dict[str, str]:
        res = self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        res.raise_for_status()
        return {"Authorization": f"Bearer {res.json()['access_token']}"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--owner", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--insecure", action="store_true", help="не проверять сертификат (самоподписанный)"
    )
    args = parser.parse_args()

    panel = Panel(args.url, verify=not args.insecure)
    c = panel.client
    owner = panel.login(args.owner, args.password)

    health = c.get("/api/health").json()
    if health.get("sealed"):
        print("Панель заперта — сначала отоприте её, иначе проверять нечего")
        return 2

    # --- готовим песочницу -------------------------------------------------
    slug = f"{PREFIX}-{secrets.token_hex(3)}"
    project = c.post("/api/projects", headers=owner, json={"slug": slug, "title": "проверка прав"})
    project.raise_for_status()
    project_id = project.json()["id"]
    made = []
    for name in ("one", "two"):
        res = c.post(f"/api/projects/{project_id}/environments", headers=owner, json={"name": name})
        res.raise_for_status()
        made.append(res.json()["id"])
    env_a, env_b = made
    # Песочница должна быть настоящей: ключ, которого нет, дает 404 вместо
    # 403, и часть проверок проходила бы, ничего не проверив.
    for env in (env_a, env_b):
        c.put(
            f"/api/environments/{env}/secrets",
            headers=owner,
            json={"name": "PROBE", "value": "значение-" + str(env)},
        ).raise_for_status()
        c.put(
            f"/api/environments/{env}/secrets",
            headers=owner,
            json={"name": "DEEP", "value": "значение", "path": "/inner"},
        ).raise_for_status()

    dev_name = f"{PREFIX}-dev-{secrets.token_hex(2)}"
    dev = c.post(
        "/api/users",
        headers=owner,
        json={"username": dev_name, "password": PASSWORD, "role": "developer"},
    )
    dev.raise_for_status()
    dev_id = dev.json()["id"]
    dev_headers = panel.login(dev_name, PASSWORD)

    created_policies: list[int] = []
    created_machines: list[tuple[int, str]] = []
    maint_id = None

    def grant(**body) -> int:
        body.setdefault("subject_type", "user")
        body.setdefault("subject_id", dev_id)
        body.setdefault("effect", "allow")
        body.setdefault("path_prefix", "/")
        res = c.post("/api/policies", headers=owner, json=body)
        res.raise_for_status()
        created_policies.append(res.json()["id"])
        return res.json()["id"]

    try:
        print("\nБез прав:")
        check(
            c.get(f"/api/environments/{env_a}/secrets", headers=dev_headers).status_code == 403,
            "список ключей закрыт",
        )
        listed = c.get("/api/projects", headers=dev_headers)
        check(
            listed.status_code == 200 and slug not in listed.text,
            "чужой проект не виден в списке",
        )
        check(
            c.get(f"/api/projects/{project_id}/environments", headers=dev_headers).status_code
            == 404,
            "окружения чужого проекта не отдаются по номеру",
        )
        check(
            c.get(f"/api/projects/{project_id}/export", headers=dev_headers).status_code == 404,
            "выгрузка чужого проекта не называет его окружений",
        )

        print("\nПраво «видеть ключи» в одном окружении:")
        grant(environment_id=env_a, actions=["list"])
        check(
            c.get(f"/api/environments/{env_a}/secrets", headers=dev_headers).status_code == 200,
            "список ключей открылся там, где право выдано",
        )
        check(
            c.get(f"/api/environments/{env_b}/secrets", headers=dev_headers).status_code == 403,
            "соседнее окружение осталось закрытым",
        )
        value = c.get(
            f"/api/environments/{env_a}/secret", headers=dev_headers, params={"name": "PROBE"}
        )
        check(value.status_code == 403, "значение не отдаётся без права «читать значения»")
        check(
            c.get(f"/api/environments/{env_a}/export", headers=dev_headers).status_code == 403,
            "выгрузка окружения закрыта",
        )

        print("\nПраво по пути:")
        grant(environment_id=env_a, path_prefix="/inner", actions=["read"])
        check(
            c.get(
                f"/api/environments/{env_a}/secret",
                headers=dev_headers,
                params={"name": "DEEP", "path": "/inner"},
            ).status_code
            == 200,
            "значение внутри разрешённой папки читается",
        )
        check(
            c.get(
                f"/api/environments/{env_a}/secret", headers=dev_headers, params={"name": "PROBE"}
            ).status_code
            == 403,
            "значение вне разрешённой папки закрыто",
        )

        print("\nЗапрет сильнее разрешения:")
        grant(environment_id=env_a, actions=["read"])
        grant(environment_id=env_a, path_prefix="/inner", actions=["read"], effect="deny")
        check(
            c.get(
                f"/api/environments/{env_a}/secret",
                headers=dev_headers,
                params={"name": "DEEP", "path": "/inner"},
            ).status_code
            == 403,
            "запрет перекрыл выданное разрешение",
        )

        print("\nЧужие разделы панели:")
        check(c.get("/api/policies", headers=dev_headers).status_code == 403, "права закрыты")
        check(c.get("/api/users", headers=dev_headers).status_code == 403, "учётки закрыты")
        check(c.get("/api/audit", headers=dev_headers).status_code == 403, "журнал закрыт")
        check(
            c.post("/api/vault/seal", headers=dev_headers).status_code == 403,
            "запереть панель может только владелец",
        )
        check(
            c.post(
                "/api/policies",
                headers=dev_headers,
                json={"subject_type": "user", "subject_id": dev_id, "actions": ["read"]},
            ).status_code
            == 403,
            "выписать себе право нельзя",
        )

        print("\nПодтверждение изменений:")
        c.patch(
            f"/api/projects/{project_id}", headers=owner, json={"approval_min_level": 30}
        ).raise_for_status()
        grant(environment_id=env_a, actions=["write"])
        put = c.put(
            f"/api/environments/{env_a}/secrets",
            headers=dev_headers,
            json={"name": "PROBE", "value": "правка снизу"},
        )
        check(put.status_code == 200 and put.json().get("pending") is True, "правка ушла в ожидание")
        current = c.get(
            f"/api/environments/{env_a}/secret", headers=owner, params={"name": "PROBE"}
        ).json()
        check(current["value"] != "правка снизу", "значение не подменилось до подтверждения")
        self_approve = c.post(
            f"/api/environments/{env_a}/secret/approve",
            headers=dev_headers,
            json={"name": "PROBE", "version": put.json()["version"]},
        )
        check(self_approve.status_code == 403, "автор не подтверждает себя сам")

        print("\nМашины:")
        # Ответственный заводит серверы, но значения выдаются только политиками:
        # подключить машину к окружению, выписать на него токен или забрать
        # секрет чужой машины - это то же чтение, и без права читать самому
        # его быть не должно.
        maint_name = f"{PREFIX}-maint-{secrets.token_hex(2)}"
        maint = c.post(
            "/api/users",
            headers=owner,
            json={"username": maint_name, "password": PASSWORD, "role": "maintainer"},
        )
        maint.raise_for_status()
        maint_id = maint.json()["id"]
        maint_headers = panel.login(maint_name, PASSWORD)
        own_box = c.post(
            "/api/machines",
            headers=maint_headers,
            json={"name": f"{PREFIX}-box-{secrets.token_hex(2)}"},
        )
        own_box.raise_for_status()
        created_machines.append((own_box.json()["id"], own_box.json()["name"]))
        reach = "открывают окружение, которое вам не выдано"
        check(
            refused(
                c.post(
                    f"/api/machines/{own_box.json()['id']}/attach",
                    headers=maint_headers,
                    json={"environment_id": env_a},
                ),
                reach,
            ),
            "свою машину к чужому окружению не подключить",
        )
        check(
            refused(
                c.post(
                    "/api/machines/enroll-token",
                    headers=maint_headers,
                    json={"environment_id": env_a, "allow_ips": "", "minutes": 5},
                ),
                reach,
            ),
            "токен подключения на чужое окружение не выписать",
        )
        prod_box = c.post(
            "/api/machines", headers=owner, json={"name": f"{PREFIX}-prod-{secrets.token_hex(2)}"}
        )
        prod_box.raise_for_status()
        created_machines.append((prod_box.json()["id"], prod_box.json()["name"]))
        c.post(
            f"/api/machines/{prod_box.json()['id']}/attach",
            headers=owner,
            json={"environment_id": env_a},
        ).raise_for_status()
        check(
            refused(
                c.post(f"/api/machines/{prod_box.json()['id']}/secret", headers=maint_headers),
                reach,
            ),
            "секрет чужой машины с доступом не перевыпустить",
        )
        check(
            refused(
                c.patch(
                    f"/api/machines/{prod_box.json()['id']}",
                    headers=maint_headers,
                    json={"expires_at": "2099-01-01"},
                ),
                reach,
            ),
            "срок чужой машины с доступом не продлить",
        )

        print("\nОтветственный без прав на соседа:")
        # Наследник отдает значения родителя всем, кто читает его самого, а
        # чужой пароль - это вход под чужим именем со всеми его правами.
        grant(
            subject_id=maint_id,
            environment_id=env_a,
            actions=["list", "read", "write"],
        )
        check(
            refused(
                c.patch(
                    f"/api/environments/{env_a}", headers=maint_headers, json={"parent_id": env_b}
                ),
                "Родителем можно назначить только окружение, которое вы читаете целиком",
            ),
            "соседнее окружение не назначить родителем своему",
        )
        # Заводить окружения ответственный может в проекте, выданном целиком на
        # запись: иначе отказ был бы по другой причине, и правило про копию
        # оставалось непроверенным.
        grant(subject_id=maint_id, project_id=project_id, actions=["write"])
        check(
            refused(
                c.post(
                    f"/api/projects/{project_id}/environments",
                    headers=maint_headers,
                    json={"name": "copy", "copy_from": env_b},
                ),
                "Скопировать можно только окружение, которое вы читаете целиком",
            ),
            "соседнее окружение не скопировать в новое",
        )
        grant(environment_id=env_b, actions=["list"])
        check(
            refused(
                c.post(
                    f"/api/users/{dev_id}/password",
                    headers=maint_headers,
                    json={"new_password": PASSWORD + "-x"},
                ),
                "У этой учетной записи есть права, которых нет у вас",
            ),
            "пароль учетке с правами, которых нет у себя, не задать",
        )

    finally:
        print("\nУбираю за собой:")
        for machine_id, name in created_machines:
            c.delete(f"/api/machines/{machine_id}", headers=owner, params={"confirm": name})
        if maint_id is not None:
            c.patch(f"/api/users/{maint_id}", headers=owner, json={"disabled": True})
        for policy_id in created_policies:
            c.delete(f"/api/policies/{policy_id}", headers=owner)
        c.patch(f"/api/projects/{project_id}", headers=owner, json={"approval_min_level": 0})
        gone = c.delete(
            f"/api/projects/{project_id}", headers=owner, params={"confirm": slug}
        )
        print("  проект удалён" if gone.status_code == 204 else f"  проект остался: {gone.text}")
        off = c.patch(f"/api/users/{dev_id}", headers=owner, json={"disabled": True})
        print("  учётка отключена" if off.status_code == 200 else f"  учётка осталась: {off.text}")

    if PROBLEMS:
        print(f"\nПанель отдала лишнее ({len(PROBLEMS)}):")
        for problem in PROBLEMS:
            print("  -", problem)
        return 1
    print("\nПрава держатся: панель не отдала ничего лишнего")
    return 0


if __name__ == "__main__":
    sys.exit(main())
