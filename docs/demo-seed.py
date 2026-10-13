"""Демо-данные для кадров README: выдуманные проекты, люди, серверы и права.

Ходит в API работающей панели (docs/make-shots.py поднимает ее на временной
базе), а потом двигает время в самой базе: иначе все версии, чтения и отчеты
серверов случились бы в одну и ту же минуту, и кадры выглядели бы как первый
час после установки. Цепочка журнала после сдвига пересчитывается.

Имена, домены и адреса выдуманы: домены из RFC 2606, адреса из RFC 5737.
Значения генерируются при запуске и нигде не хранятся.

    python docs/demo-seed.py --url http://127.0.0.1:8111 --db demo.db --lang en --password ...
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.audit import GENESIS, digest  # noqa: E402

URL = ""
NOW = datetime.now(timezone.utc)
rnd = random.Random(2026)

# Подписи, комментарии и описания на языке кадров. Имена ключей и проектов
# одни на оба языка: так их и пишут люди.
TEXT = {
    "en": {
        "backend": "Backend team",
        "api": "Public API",
        "web": "Storefront",
        "worker": "Order worker",
        "billing": "Billing",
        "bot": "Support bot",
        "payments": "Payments gateway",
        "portal": "Customer portal",
        "crm": "CRM",
        "reports": "Reports",
        "landing": "Marketing site",
        "status": "Status page",
        "note_db": "Primary database, the app user only",
        "note_stripe": "Live key; rotate after the yearly audit",
        "note_smtp": "Mail relay, shared with the storefront",
        "note_jwt": "Signs session tokens; changing it logs everyone out",
        "note_s3": "Uploads bucket, write-only policy",
        "c_db1": "first deploy",
        "c_db2": "move to the new database host",
        "c_db3": "rotate after the contractor left",
        "c_db4": "pool size in the URL",
        "c_stripe": "new key from the dashboard",
        "c_flag": "turn the new checkout on for everyone",
        "ci": "CI runner: builds and migrations",
        "old": "Old reporting box, waiting to be shut down",
    },
    "ru": {
        "backend": "Бэкенд",
        "api": "Публичный API",
        "web": "Витрина",
        "worker": "Обработчик заказов",
        "billing": "Биллинг",
        "bot": "Бот поддержки",
        "payments": "Платежный шлюз",
        "portal": "Кабинет клиента",
        "crm": "CRM",
        "reports": "Отчеты",
        "landing": "Сайт",
        "status": "Страница статуса",
        "note_db": "Основная база, только пользователь приложения",
        "note_stripe": "Боевой ключ, менять после годовой проверки",
        "note_smtp": "Почтовый релей, общий с витриной",
        "note_jwt": "Подписывает сессии; смена выкинет всех из системы",
        "note_s3": "Бакет загрузок, только запись",
        "c_db1": "первый выкат",
        "c_db2": "переезд на новый сервер базы",
        "c_db3": "смена после ухода подрядчика",
        "c_db4": "размер пула в адресе",
        "c_stripe": "новый ключ из кабинета",
        "c_flag": "новая корзина для всех",
        "ci": "Сборка в CI: образы и миграции",
        "old": "Старый сервер отчетов, ждет выключения",
    },
}


def call(method: str, path: str, body=None, token: str = "", headers=None, ok=(200, 201, 204)):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", token if " " in token else "Bearer " + token)
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req) as res:
            raw = res.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code in ok:
            return None
        raise SystemExit(f"{method} {path}: {exc.code} {exc.read().decode()[:400]}") from exc


def login(user: str, password: str) -> str:
    return call("POST", "/api/auth/login", {"username": user, "password": password})["access_token"]


def word(n: int = 20) -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def values(project: str, env: str) -> dict[str, str]:
    """Правдоподобные, но выдуманные значения. Префиксы не настоящие: иначе
    сканеры секретов принимали бы кадры и этот файл за утечку."""
    host = f"{project}-{env}"
    return {
        "DATABASE_URL": f"postgres://{project}:{word(16)}@db-1.{host}.internal.example:5432/{project}",
        "REDIS_URL": f"redis://cache.{host}.internal.example:6379/0",
        "JWT_SECRET": word(48),
        "SMTP_PASSWORD": word(24),
        "SENTRY_DSN": f"https://{word(32).lower()}@errors.example.com/{rnd.randint(10, 99)}",
        "S3_ACCESS_KEY_ID": "DEMO" + word(16).upper(),
        "S3_SECRET_ACCESS_KEY": word(40),
        "LOG_LEVEL": "info" if env == "prod" else "debug",
    }


def main() -> None:
    global URL
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--lang", default="en", choices=("en", "ru"))
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    URL = args.url.rstrip("/")
    T = TEXT[args.lang]

    owner = login("admin", args.password)
    root = call("POST", "/api/vault/init", {"mode": "env", "auto_unseal": False}, owner)
    if call("GET", "/api/vault/status", token=owner)["sealed"]:
        call("POST", "/api/vault/unseal", {"root_key": root["root_key"]}, owner)

    # --- люди -------------------------------------------------------------------
    people = {}
    for name, role in (("alice", "maintainer"), ("bob", "developer"), ("dan", "developer"), ("carol", "viewer")):
        password = "Demo-" + word(16)
        res = call("POST", "/api/users", {"username": name, "password": password, "role": role}, owner)
        people[name] = {"id": res["id"], "password": password}
    team = call("POST", "/api/groups", {"name": T["backend"]}, owner)
    for name in ("alice", "bob", "dan"):
        call("POST", f"/api/groups/{team['id']}/members", {"user_id": people[name]["id"]}, owner)

    # --- проекты ----------------------------------------------------------------
    layout = [
        ("Acme", "api", T["api"], ["dev", "stage", "prod"]),
        ("Acme", "web", T["web"], ["dev", "stage", "prod"]),
        ("Acme", "worker", T["worker"], ["stage", "prod"]),
        ("Acme", "billing", T["billing"], ["dev", "prod"]),
        ("Globex", "bot", T["bot"], ["dev", "prod"]),
        ("Globex", "payments", T["payments"], ["dev", "stage", "prod"]),
        ("Globex", "portal", T["portal"], ["dev", "prod"]),
        ("Initech", "crm", T["crm"], ["dev", "prod"]),
        ("Initech", "reports", T["reports"], ["prod"]),
        ("", "landing", T["landing"], ["prod"]),
        ("", "status", T["status"], ["prod"]),
    ]
    projects: dict[str, dict] = {}
    envs: dict[tuple[str, str], dict] = {}
    for group, slug, title, names in layout:
        project = call(
            "POST",
            "/api/projects",
            {"slug": slug, "title": title, "group_name": group, "environments": names},
            owner,
        )
        projects[slug] = project
        for env in call("GET", f"/api/projects/{project['id']}/environments", token=owner):
            envs[(slug, env["name"])] = env

    call(
        "PATCH",
        f"/api/projects/{projects['api']['id']}",
        {"required_keys": "DATABASE_URL REDIS_URL JWT_SECRET SENTRY_DSN", "stale_after_days": 180},
        owner,
    )
    # правки разработчика в биллинге подтверждает ответственный и выше
    call("PATCH", f"/api/projects/{projects['billing']['id']}", {"approval_min_level": 30}, owner)

    # --- права ------------------------------------------------------------------
    def grant(subject_type, subject_id, slug, env, actions, **extra):
        body = {
            "subject_type": subject_type,
            "subject_id": subject_id,
            "project_id": projects[slug]["id"],
            "environment_id": envs[(slug, env)]["id"] if env else None,
            "path_prefix": "/",
            "actions": actions,
            "effect": extra.pop("effect", "allow"),
        }
        body.update(extra)
        return call("POST", "/api/policies", body, owner)

    soon = (NOW + timedelta(days=30)).date().isoformat()
    grant("group", team["id"], "api", "dev", ["list", "read", "write"])
    grant("group", team["id"], "api", "stage", ["list", "read", "write"])
    for slug in ("api", "web", "billing"):
        grant("group", team["id"], slug, "prod", ["list", "read"], require_2fa=True)
    grant("group", team["id"], "worker", "", ["list", "read", "write"])
    grant("user", people["alice"]["id"], "api", "prod", ["list", "read", "write"])
    grant("user", people["alice"]["id"], "billing", "prod", ["list", "read", "write"])
    grant("user", people["bob"]["id"], "billing", "prod", ["list", "read", "write"], expires_at=soon)
    grant("user", people["dan"]["id"], "billing", "prod", ["read"], effect="deny")
    grant("user", people["carol"]["id"], "api", "prod", ["list"])
    grant("user", people["carol"]["id"], "payments", "prod", ["list", "read"])

    # --- значения ---------------------------------------------------------------
    def put(slug, env, name, value, token=owner, comment=""):
        env_id = envs[(slug, env)]["id"]
        call("PUT", f"/api/environments/{env_id}/secrets", {"name": name, "value": value, "comment": comment}, token)

    def meta(slug, env, name, note="", expires=""):
        env_id = envs[(slug, env)]["id"]
        call("POST", f"/api/environments/{env_id}/secret/meta", {"name": name, "note": note, "expires_at": expires}, owner)

    for (slug, env) in envs:
        base = values(slug, env)
        keys = list(base)
        if slug in ("landing", "status"):
            keys = ["SENTRY_DSN", "LOG_LEVEL"]
        elif slug in ("reports", "crm", "bot"):
            keys = keys[:5]
        if slug == "api" and env == "stage":
            keys.remove("SENTRY_DSN")  # обязательный ключ, которого нет: панель это покажет
        for name in keys:
            put(slug, env, name, base[name], comment=T["c_db1"] if name == "DATABASE_URL" else "")
    for env in ("dev", "stage", "prod"):
        put("api", env, "FEATURE_NEW_CHECKOUT", "false")
    put("api", "prod", "STRIPE_SECRET_KEY", "sk_demo_" + word(32), comment=T["c_stripe"])
    put("web", "stage", "ADMIN_PASSWORD", "changeme")
    put("payments", "prod", "ACQUIRER_API_KEY", word(32))
    put("billing", "prod", "INVOICE_SIGNING_KEY", word(40))

    meta("api", "prod", "DATABASE_URL", T["note_db"])
    meta("api", "prod", "STRIPE_SECRET_KEY", T["note_stripe"], (NOW + timedelta(days=19)).date().isoformat())
    meta("api", "prod", "SMTP_PASSWORD", T["note_smtp"])
    meta("api", "prod", "JWT_SECRET", T["note_jwt"])
    meta("api", "prod", "S3_SECRET_ACCESS_KEY", T["note_s3"], (NOW + timedelta(days=74)).date().isoformat())

    # история одного ключа: правят разные люди
    alice = login("alice", people["alice"]["password"])
    bob = login("bob", people["bob"]["password"])
    db = values("api", "prod")["DATABASE_URL"]
    put("api", "prod", "DATABASE_URL", db.replace("db-1.", "db-2."), alice, T["c_db2"])
    put("api", "prod", "DATABASE_URL", db.replace("db-1.", "db-2.").replace(db.split(":")[2].split("@")[0], word(16)), alice, T["c_db3"])
    put("api", "prod", "DATABASE_URL", db.replace("db-1.", "db-2.") + "?pool=20", alice, T["c_db4"])
    put("api", "prod", "FEATURE_NEW_CHECKOUT", "true", alice, T["c_flag"])
    put("api", "stage", "FEATURE_NEW_CHECKOUT", "true", bob)
    # правка разработчика в защищенном проекте ждет подтверждения
    put("billing", "prod", "INVOICE_SIGNING_KEY", word(40), bob)

    # --- серверы ----------------------------------------------------------------
    def enroll(host: str, slug: str, env: str, ip: str, version: str, os_name: str, local_ip: str):
        ticket = call("POST", "/api/machines/enroll-token", {"environment_id": envs[(slug, env)]["id"], "minutes": 15}, owner)
        xff = {"X-Forwarded-For": ip}
        me = call("POST", "/api/v1/machine/enroll", {"token": ticket["token"], "hostname": host, "agent_version": version}, headers=xff)
        return {"client_id": me["client_id"], "secret": me["client_secret"], "ip": ip, "version": version, "os": os_name, "local_ip": local_ip}

    def pull(machine: dict, slug: str, env: str, group: str):
        xff = {"X-Forwarded-For": machine["ip"]}
        token = call("POST", "/api/v1/machine/token", {"client_id": machine["client_id"], "client_secret": machine["secret"]}, headers=xff)["access_token"]
        query = f"project={slug}&env={env}" + (f"&group={group}" if group else "")
        res = call("GET", f"/api/v1/machine/secrets?{query}", token=token, headers=xff)
        call(
            "POST",
            "/api/v1/machine/report",
            {
                "agent_version": machine["version"],
                "applied": f"keys {len(res['values'])}",
                "project": slug,
                "env": env,
                "group": group,
                "path": f"/run/sekvyr/{slug}.env",
                "os": machine["os"],
                "local_ip": machine["local_ip"],
            },
            token,
            headers=xff,
        )

    fleet = {
        "web-1": enroll("web-1", "web", "prod", "203.0.113.21", "1.0.0", "Ubuntu 24.04.2 LTS", "10.10.0.21"),
        "web-2": enroll("web-2", "web", "prod", "203.0.113.22", "1.0.0", "Ubuntu 24.04.2 LTS", "10.10.0.22"),
        "worker-1": enroll("worker-1", "worker", "prod", "203.0.113.31", "1.0.0", "Debian GNU/Linux 12 (bookworm)", "10.10.0.31"),
        "api-1": enroll("api-1", "api", "prod", "198.51.100.11", "1.0.0", "Ubuntu 24.04.2 LTS", "10.20.0.11"),
        "reports-old": enroll("reports-old", "reports", "prod", "192.0.2.40", "0.28.0", "Ubuntu 22.04.5 LTS", "10.30.0.40"),
    }
    listed = {m["name"]: m for m in call("GET", "/api/machines", token=owner)}
    for host in ("web-2",):
        call("POST", f"/api/machines/{listed[host]['id']}/attach", {"environment_id": envs[("api", "prod")]["id"]}, owner)
    pull(fleet["web-1"], "web", "prod", "acme")
    pull(fleet["web-2"], "web", "prod", "acme")
    pull(fleet["web-2"], "api", "prod", "acme")
    pull(fleet["worker-1"], "worker", "prod", "acme")
    pull(fleet["api-1"], "api", "prod", "acme")
    pull(fleet["reports-old"], "reports", "prod", "initech")

    ci = call("POST", "/api/machines", {"name": "ci-runner", "description": T["ci"], "allow_ips": "203.0.113.0/24"}, owner)
    grant("machine", ci["id"], "api", "stage", ["list", "read"])
    basic = base64.b64encode(f"{ci['client_id']}:{ci['client_secret']}".encode()).decode()
    call("GET", "/api/v1/machine/secrets?project=api&env=stage&group=acme", token="Basic " + basic, headers={"X-Forwarded-For": "203.0.113.90"})
    call("PATCH", f"/api/machines/{listed['reports-old']['id']}", {"description": T["old"]}, owner)

    from cryptography.hazmat.primitives.asymmetric import rsa

    numbers = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()

    def b64(value: int, length: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(length, "big")).decode().rstrip("=")

    jwks = {"keys": [{"kty": "RSA", "kid": "demo", "use": "sig", "alg": "RS256", "n": b64(numbers.n, 256), "e": b64(numbers.e, 3)}]}
    cluster = call(
        "POST",
        "/api/machines/clusters",
        {"name": "prod-eu", "issuer": "https://kubernetes.default.svc.cluster.local", "audience": "sekvyr", "jwks": json.dumps(jwks)},
        owner,
    )
    pod = call(
        "POST",
        "/api/machines",
        {"name": "billing/app", "cluster_id": cluster["id"], "k8s_namespace": "billing", "k8s_service_account": "app"},
        owner,
    )
    grant("machine", pod["id"], "billing", "prod", ["list", "read"])

    shift(args.db, people)
    print("демо-данные готовы")


def shift(path: str, people: dict) -> None:
    """Разнести события по времени и пересчитать цепочку журнала."""
    con = sqlite3.connect(path)
    cur = con.cursor()

    def iso(moment: datetime) -> str:
        return moment.strftime("%Y-%m-%d %H:%M:%S.%f")

    # Версии: у каждого ключа своя история, первая версия - от полугода до
    # двух лет назад, следующие ближе к сегодняшнему дню.
    rows = cur.execute("SELECT id, secret_id, version FROM secret_versions ORDER BY secret_id, version").fetchall()
    by_secret: dict[int, list[tuple[int, int]]] = {}
    for vid, sid, ver in rows:
        by_secret.setdefault(sid, []).append((vid, ver))
    for sid, versions in by_secret.items():
        age = rnd.uniform(15, 230)
        for index, (vid, _ver) in enumerate(versions):
            if index:
                age = age * rnd.uniform(0.25, 0.6)
            moment = NOW - timedelta(days=age, minutes=rnd.randint(0, 600))
            cur.execute("UPDATE secret_versions SET created_at = ? WHERE id = ?", (iso(moment), vid))
            if index == 0:
                cur.execute("UPDATE secrets SET created_at = ? WHERE id = ?", (iso(moment), sid))
    # Ожидающая подтверждения правка - сегодняшняя.
    cur.execute(
        "UPDATE secret_versions SET created_at = ? WHERE status = 'pending'",
        (iso(NOW - timedelta(hours=3)),),
    )
    for table in ("projects", "environments", "groups", "clusters"):
        cur.execute(f"UPDATE {table} SET created_at = ?", (iso(NOW - timedelta(days=430)),))
    for name in people:
        cur.execute("UPDATE users SET created_at = ? WHERE username = ?", (iso(NOW - timedelta(days=rnd.uniform(60, 400))), name))
    cur.execute("UPDATE policies SET created_at = ?", (iso(NOW - timedelta(days=rnd.uniform(5, 120))),))

    seen = {
        "web-1": timedelta(seconds=40),
        "web-2": timedelta(seconds=12),
        "worker-1": timedelta(seconds=55),
        "api-1": timedelta(seconds=25),
        "reports-old": timedelta(days=2, hours=5),
        "ci-runner": timedelta(hours=3),
    }
    for name, ago in seen.items():
        moment = iso(NOW - ago)
        cur.execute("UPDATE machine_identities SET last_seen_at = ?, created_at = ? WHERE name = ?", (moment, iso(NOW - timedelta(days=90)), name))
        cur.execute(
            "UPDATE machine_apps SET last_seen_at = ? WHERE machine_id = (SELECT id FROM machine_identities WHERE name = ?)",
            (moment, name),
        )

    # Журнал: события сида по порядку растянуты на последние трое суток, и
    # цепочка пересчитана заново - иначе проверка журнала сказала бы правду о
    # том, что строки правили в обход панели.
    entries = cur.execute("SELECT id, actor, action, target, detail, ip FROM audit_log ORDER BY id").fetchall()
    span = timedelta(days=3)
    prev = GENESIS
    for index, (eid, actor, action, target, detail, ip) in enumerate(entries):
        moment = NOW - span + span * (index / max(len(entries), 1))
        chain = digest(ts=moment, actor=actor, action=action, target=target, detail=detail, ip=ip, prev=prev)
        cur.execute(
            "UPDATE audit_log SET ts = ?, prev_chain = ?, chain = ? WHERE id = ?",
            (iso(moment), prev, chain, eid),
        )
        prev = chain
    con.commit()
    con.close()


if __name__ == "__main__":
    started = time.time()
    main()
    print(f"за {time.time() - started:.1f} с")
