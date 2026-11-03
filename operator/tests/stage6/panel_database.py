"""Use only the explicitly reserved empty database in the owned trial PVC.

This helper never resets a database. SQL output is consumed privately and only
fixed, non-sensitive assertions are returned to the coordinator.
"""

import json


OWNER_SQL = """SELECT json_build_object(
 'current_user', current_user,
 'exists', EXISTS(SELECT 1 FROM pg_database WHERE datname='trial_panel'),
 'owner', (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='trial_panel'),
 'template', (SELECT datistemplate FROM pg_database WHERE datname='trial_panel'),
 'allow_connections', (SELECT datallowconn FROM pg_database WHERE datname='trial_panel'));"""

EMPTY_SQL = """WITH user_namespace AS (
 SELECT oid, nspname FROM pg_namespace
 WHERE nspname NOT IN ('pg_catalog','information_schema','pg_toast')
 AND nspname !~ '^pg_(temp|toast_temp)_[0-9]+$'
)
SELECT json_build_object(
 'database', current_database(), 'current_user', current_user,
 'owner', (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),
 'objects',
 (SELECT count(*) FROM pg_class WHERE relnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_proc WHERE pronamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_type WHERE typnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_operator WHERE oprnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_opclass WHERE opcnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_opfamily WHERE opfnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_collation WHERE collnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_conversion WHERE connamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_ts_config WHERE cfgnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_ts_dict WHERE dictnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_ts_parser WHERE prsnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM pg_ts_template WHERE tmplnamespace IN (SELECT oid FROM user_namespace)) +
 (SELECT count(*) FROM user_namespace WHERE nspname <> 'public') +
 (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql') +
 (SELECT count(*) FROM pg_language WHERE lanname NOT IN ('internal','c','sql','plpgsql')) +
 (SELECT count(*) FROM pg_cast WHERE oid >= 16384) +
 (SELECT count(*) FROM pg_am WHERE oid >= 16384) +
 (SELECT count(*) FROM pg_transform WHERE oid >= 16384) +
 (SELECT count(*) FROM pg_largeobject_metadata) +
 (SELECT count(*) FROM pg_event_trigger) +
 (SELECT count(*) FROM pg_foreign_server) +
 (SELECT count(*) FROM pg_foreign_data_wrapper) +
 (SELECT count(*) FROM pg_user_mapping) +
 (SELECT count(*) FROM pg_publication) +
 (SELECT count(*) FROM pg_subscription) +
 (SELECT count(*) FROM pg_default_acl) +
 (SELECT count(*) FROM pg_db_role_setting WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()))
);"""


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def database_resources(panel):
    deployment = panel.get("Deployment", "database")
    pvc = panel.get("PersistentVolumeClaim", "trial-database")
    require(deployment.get("apiVersion") == "apps/v1" and pvc.get("apiVersion") == "v1", "Unexpected database resource version")
    pod = deployment.get("spec", {}).get("template", {}).get("spec", {})
    containers = pod.get("containers", [])
    require(len(containers) == 1 and containers[0].get("name") == "database", "Unexpected database container")
    container = containers[0]
    env = container.get("env", [])
    names = [item.get("name") for item in env]
    require(len(names) == len(set(names)), "Ambiguous database environment")
    values = {item["name"]: item.get("value") for item in env if "valueFrom" not in item}
    require(values.get("POSTGRES_USER") == "trial_admin" and isinstance(values.get("POSTGRES_DB"), str)
        and bool(values["POSTGRES_DB"]) and values.get("PGDATA") == "/data/pgdata", "Unexpected database initialization identity")
    volumes = [item for item in pod.get("volumes", []) if item.get("name") == "data"]
    mounts = [item for item in container.get("volumeMounts", []) if item.get("name") == "data"]
    require(len(volumes) == 1 and volumes[0].get("persistentVolumeClaim") == {"claimName": "trial-database"}
        and len(mounts) == 1 and mounts[0].get("mountPath") == "/data" and not mounts[0].get("subPath")
        and not mounts[0].get("subPathExpr") and not mounts[0].get("readOnly"), "Database PVC binding differs from owned fixture")
    return values["POSTGRES_DB"], deployment, pvc


def ensure_trial_database(panel):
    reserved, original_deployment, original_pvc = database_resources(panel)

    def revalidate():
        current, deployment, pvc = database_resources(panel)
        require(current == reserved and deployment["metadata"]["uid"] == original_deployment["metadata"]["uid"]
            and deployment.get("spec") == original_deployment.get("spec")
            and pvc["metadata"]["uid"] == original_pvc["metadata"]["uid"], "Database fixture changed during preparation")

    def sql(database, statement):
        revalidate()
        # Explicit local socket, no .psqlrc, no interactive password and no
        # connection string or credential in argv. Identifiers are fixed here.
        try:
            result = panel.cluster.kube("exec", "deployment/database", "-n", panel.namespace, "-c", "database", "--",
                "psql", "-X", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
                "-p", "5432", "-U", "trial_admin", "-d", database, "-c", statement)
        except Exception:
            raise RuntimeError("Trial database command failed") from None
        return result.stdout

    def query(database, statement):
        raw = sql(database, statement)
        require(len(raw) <= 4096, "Unexpected trial database response")
        try:
            result = json.loads(raw)
        except (ValueError, TypeError):
            raise RuntimeError("Unexpected trial database response") from None
        require(isinstance(result, dict), "Unexpected trial database response")
        return result

    owner = query("postgres", OWNER_SQL)
    require(owner.get("current_user") == "trial_admin" and type(owner.get("exists")) is bool, "Unexpected trial database identity")
    created = False
    if owner["exists"]:
        require(reserved == "trial_panel", "Existing database is not the explicitly reserved fixture")
    else:
        require(reserved != "trial_panel", "Reserved fixture database is missing")
        sql("postgres", "CREATE DATABASE trial_panel OWNER trial_admin;")
        created = True
        owner = query("postgres", OWNER_SQL)
    require(owner.get("exists") is True and owner.get("current_user") == "trial_admin"
        and owner.get("owner") == "trial_admin" and owner.get("template") is False
        and owner.get("allow_connections") is True, "Trial database owner or flags differ")
    empty = query("trial_panel", EMPTY_SQL)
    require(empty.get("database") == "trial_panel" and empty.get("current_user") == "trial_admin"
        and empty.get("owner") == "trial_admin", "Trial database owner differs")
    require(type(empty.get("objects")) is int and empty["objects"] == 0, "Trial database is not empty; reset is forbidden")
    revalidate()
    return {"databaseReady": True, "databaseCreated": created, "reservedDatabaseReused": not created, "production": False}
