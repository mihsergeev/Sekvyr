"""Real coordinator fault cases for old state and a stale derived panel index.

This models ordinary UID-pinned Kubernetes updates with NEW resourceVersions,
not raw etcd/RV rewind. The derived panel pointer is explicitly not authority.
Only an approved disposable own panel database and view may be modified.
"""

import base64
import copy
import json
import re

from application import RELEASE, RESOURCE, REVISION, TARGET, wait
from fixture import canonical, write_private
from panel_database import database_resources


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HASH = re.compile(r"[0-9a-f]{64}")
COUNTER = re.compile(r"0|[1-9][0-9]{0,19}")
ROW = """json_build_object('view_id',id,'realm_id',realm_uuid,'project_id',project_uuid,
'environment_id',environment_uuid,'log_id',log_uuid,'numeric_project_id',project_id,
'numeric_environment_id',environment_id,'sequence',indexed_sequence,'hash',indexed_hash)"""
SCOPE_WHERE = """id=:'view' AND realm_uuid=:'realm' AND project_uuid=:'project'
AND environment_uuid=:'environment' AND log_uuid=:'log'
AND project_id=:'numeric_project'::integer AND environment_id=:'numeric_environment'::integer"""
OWNER_WHERE = """current_database()='trial_panel' AND current_user='trial_admin'
AND (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database())='trial_admin'"""
READ_SQL = """SELECT json_build_object('database',current_database(),'current_user',current_user,
'owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),
'row',(SELECT """ + ROW + " FROM e2e2_views WHERE " + SCOPE_WHERE + "));"
CAS_SQL = """WITH changed AS (UPDATE e2e2_views SET indexed_sequence=:'new_sequence',indexed_hash=:'new_hash'
WHERE """ + SCOPE_WHERE + " AND " + OWNER_WHERE + """
AND indexed_sequence=:'expected_sequence' AND indexed_hash=:'expected_hash'
RETURNING *) SELECT json_build_object('changed',(SELECT count(*) FROM changed),
'row',(SELECT """ + ROW + " FROM changed));"


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def pointer(sequence, digest):
    require(isinstance(sequence, str) and COUNTER.fullmatch(sequence) is not None
        and int(sequence) <= 18446744073709551615 and isinstance(digest, str) and HASH.fullmatch(digest) is not None,
        "Invalid bounded panel index pointer")
    return {"sequence": sequence, "hash": digest}


def sql_input(scope, meta, statement, values=None):
    require(set(scope) == {name + "_id" for name in ("realm", "project", "environment", "view", "log")}
        and all(isinstance(value, str) and UUID.fullmatch(value) is not None for value in scope.values()), "Invalid exact rollback view scope")
    require(type(meta.get("project_id")) is int and 0 < meta["project_id"] <= 2147483647
        and type(meta.get("environment_id")) is int and 0 < meta["environment_id"] <= 2147483647, "Invalid own panel numeric identity")
    require(statement in (READ_SQL, CAS_SQL), "Unapproved rollback SQL")
    params = {name: scope[name + "_id"] for name in ("realm", "project", "environment", "view", "log")}
    params.update(numeric_project=str(meta["project_id"]), numeric_environment=str(meta["environment_id"]))
    if statement == CAS_SQL:
        require(isinstance(values, dict) and set(values) == {"expected", "new"}, "Exact rollback CAS values required")
        for prefix in ("expected", "new"):
            value = pointer(values[prefix]["sequence"], values[prefix]["hash"])
            params[prefix + "_sequence"], params[prefix + "_hash"] = value["sequence"], value["hash"]
    else:
        require(values is None, "Unexpected read parameters")
    # All values above have a closed ASCII grammar. psql variables are quoted
    # by :'name'; no untrusted SQL, password or connection URL enters argv.
    return "\n".join("\\set " + key + " '" + value + "'" for key, value in sorted(params.items())) + "\n" + statement + "\n"


class RollbackCases:
    def __init__(self, coordinator):
        self.c, self.app, self.panel = coordinator, coordinator.app, coordinator.panel
        self.root = coordinator.private / "rollback-cases"
        self.root.mkdir(mode=0o700, exist_ok=True)

    def __repr__(self):
        return "<isolated actual rollback cases [redacted]>"

    def sql(self, statement, values=None):
        reserved, deployment, pvc = database_resources(self.panel)
        require(reserved == "trial_panel", "Rollback requires the explicitly reserved owned panel database")
        metadata = json.loads((self.c.private / "database-metadata.json").read_bytes())
        require(metadata.get("namespace") == self.panel.namespace and metadata.get("service") == "database"
            and metadata.get("panel_database_reserved") == "trial_panel" and metadata.get("superuser") == "trial_admin"
            and metadata.get("production") is False, "Database ownership authorization differs")
        meta = json.loads((self.c.private / "panel-bootstrap.json").read_bytes())
        raw = sql_input(self.c.protocol.scope, meta, statement, values)
        _, again, again_pvc = database_resources(self.panel)
        require(again["metadata"]["uid"] == deployment["metadata"]["uid"] and again.get("spec") == deployment.get("spec")
            and again_pvc["metadata"]["uid"] == pvc["metadata"]["uid"], "Database changed before scoped rollback SQL")
        try:
            result = self.c.cluster.kube("exec", "-i", "deployment/database", "-n", self.panel.namespace, "-c", "database", "--",
                "psql", "-X", "-q", "-A", "-t", "-w", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql", "-p", "5432",
                "-U", "trial_admin", "-d", "trial_panel", data=raw)
            require(len(result.stdout) <= 4096, "Rollback SQL response bounds exceeded")
            output = json.loads(result.stdout)
            require(isinstance(output, dict), "Rollback SQL response invalid")
        except Exception:
            raise RuntimeError("Scoped trial rollback SQL failed") from None
        return output

    def read_index(self):
        output = self.sql(READ_SQL)
        require(output.get("database") == "trial_panel" and output.get("current_user") == "trial_admin"
            and output.get("owner") == "trial_admin" and isinstance(output.get("row"), dict), "Rollback database owner or scoped view differs")
        row = output["row"]
        require({name: row.get(name) for name in self.c.protocol.scope} == self.c.protocol.scope, "Rollback row escaped exact view scope")
        meta = json.loads((self.c.private / "panel-bootstrap.json").read_bytes())
        require(row.get("numeric_project_id") == meta["project_id"] and row.get("numeric_environment_id") == meta["environment_id"],
            "Rollback row escaped owned panel identity")
        return pointer(row["sequence"], row["hash"])

    def set_index(self, expected, new):
        expected, new = pointer(expected["sequence"], expected["hash"]), pointer(new["sequence"], new["hash"])
        current = self.read_index()
        if current == new:
            return {"exactResultAlreadyPresent": True}
        require(current == expected, "Rollback index CAS changed; explicit review required")
        try:
            output = self.sql(CAS_SQL, {"expected": expected, "new": new})
        except RuntimeError:
            # Resolve only these exact two prepared pointer fields after a lost
            # response, never overwrite an unrelated or newer current index.
            if self.read_index() == new:
                return {"exactResultAlreadyPresent": True}
            raise
        require(type(output.get("changed")) is int and output["changed"] == 1
            and isinstance(output.get("row"), dict) and pointer(output["row"]["sequence"], output["row"]["hash"]) == new,
            "Rollback index CAS rejected")
        require(self.read_index() == new, "Rollback index exact result differs")
        return {"exactPointerCAS": True}

    def same_application(self, baseline):
        target = self.app.get("Secret", TARGET)
        require(target["metadata"]["uid"] == baseline["target_uid"] and target["data"] == baseline["target_data"]
            and target["metadata"]["annotations"][REVISION] == baseline["target_revision"], "Rollback changed target bytes or opaque revision")
        self.app.frozen(baseline["footprint"], seconds=2)
        status = wait(self.app.status)
        require(status["pod_uid"] == baseline["app_status"]["pod_uid"] and status["boot_id"] == baseline["app_status"]["boot_id"],
            "Rollback replayed an application restart")

    def fresh_current(self, snapshot):
        previous = self.app.get("SekvyrSecret", RESOURCE).get("status", {}).get("lastSuccessfulSyncTime")
        self.app.poke()

        def changed():
            value = self.app.current(snapshot, True)
            return value if value and value.get("status", {}).get("lastSuccessfulSyncTime") != previous else False

        return wait(changed)

    def capture(self):
        path = self.root / "captured.json"
        require(not path.exists(), "Rollback capture may not replace an earlier reviewed baseline")
        current = self.c.current()
        wait(lambda: self.app.current(current["snapshot"], True))
        state, target = self.app.get("Secret", self.app.state_name), self.app.get("Secret", TARGET)
        raw = state.get("data", {}).get("state.json")
        require(isinstance(raw, str) and raw and len(base64.b64decode(raw, validate=True)) <= 1 << 20, "Protected old state is missing or oversized")
        index = self.read_index()
        require(index == pointer(current["snapshot"]["sequence"], current["snapshot"]["envelope_hash"]), "Capture needs actual current committed panel index")
        captured = {"scope": self.c.protocol.scope, "genesis_hash": self.c.protocol.genesis_hash, "current": current,
            "state_name": self.app.state_name, "state_uid": state["metadata"]["uid"], "state_resource_version": state["metadata"]["resourceVersion"],
            "old_state_json": raw, "installation_marker": state["data"]["installation.json"], "index": index,
            "target_uid": target["metadata"]["uid"], "target_data": target["data"], "target_revision": target["metadata"]["annotations"][REVISION],
            "footprint": self.app.footprint(), "app_status": wait(self.app.status)}
        write_private(path, canonical(captured))
        return {"oldProtectedStateCaptured": True, "snapshot": current["snapshot"], "production": False}

    def restore_old_state(self, captured):
        require(self.app.state_name == captured["state_name"], "State rollback may not change bootstrap references")
        state = self.app.get("Secret", self.app.state_name)
        require(state["metadata"]["uid"] == captured["state_uid"] and state.get("data", {}).get("installation.json") == captured["installation_marker"],
            "State rollback target UID or bootstrap marker changed")
        before = state["metadata"]["resourceVersion"]
        operations = [{"op": "test", "path": "/metadata/uid", "value": captured["state_uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": before},
            {"op": "replace", "path": "/data/state.json", "value": captured["old_state_json"]}]
        self.c.cluster.kube("patch", "Secret", self.app.state_name, "-n", self.app.namespace, "--type=json", "--patch-file", "/dev/stdin",
            "-o", "json", data=json.dumps(operations))
        after = self.app.get("Secret", self.app.state_name)
        require(after["metadata"]["uid"] == captured["state_uid"] and after["metadata"]["resourceVersion"] != before
            and after["data"]["state.json"] == captured["old_state_json"], "Old state fault was not a same-UID new-resourceVersion update")

    def operator_absent(self):
        deployment = self.app.get("Deployment", RELEASE + "-operator")
        labels = deployment["spec"]["selector"]["matchLabels"]
        selector = ",".join(name + "=" + value for name, value in sorted(labels.items()))
        sets = json.loads(self.c.cluster.kube("get", "replicasets", "-n", self.app.namespace, "-l", selector, "-o", "json").stdout)["items"]
        require(all(any(ref.get("uid") == deployment["metadata"]["uid"] and ref.get("kind") == "Deployment"
            for ref in value["metadata"].get("ownerReferences", [])) for value in sets), "Operator ReplicaSet has foreign owner")
        uids = {value["metadata"]["uid"] for value in sets}
        pods = json.loads(self.c.cluster.kube("get", "pods", "-n", self.app.namespace, "-l", selector, "-o", "json").stdout)["items"]
        require(all(any(ref.get("uid") in uids and ref.get("kind") == "ReplicaSet"
            for ref in value["metadata"].get("ownerReferences", [])) for value in pods), "Operator pod has foreign owner")
        return not pods

    def run_after_advance(self, generation, demo_value):
        captured = json.loads((self.root / "captured.json").read_bytes())
        require(captured["scope"] == self.c.protocol.scope and captured["genesis_hash"] == self.c.protocol.genesis_hash,
            "Rollback baseline differs from immutable journal scope")
        require(isinstance(generation, str) and isinstance(demo_value, str) and len(generation) <= 200 and len(demo_value) <= 200,
            "Bounded current selected values required")
        require(captured["target_data"] == {"GENERATION": base64.b64encode(generation.encode()).decode(),
            "DEMO_VALUE": base64.b64encode(demo_value.encode()).decode()}, "Advance must preserve exact selected plaintext")
        current = self.c.current()
        require(int(current["snapshot"]["sequence"]) > int(captured["current"]["snapshot"]["sequence"])
            and current["snapshot"]["envelope_hash"] != captured["current"]["snapshot"]["envelope_hash"]
            and current["authority"] == captured["current"]["authority"], "Actual same-authority journal advance is required")
        wait(lambda: self.app.current(current["snapshot"], True))
        self.same_application(captured)
        state = self.app.get("Secret", self.app.state_name)
        prepared = self.root / "advanced.json"
        advanced = {"current": current, "current_state_json": state["data"]["state.json"], "index": self.read_index()}
        if prepared.exists():
            saved = json.loads(prepared.read_bytes())
            require(saved["current"]["snapshot"] == current["snapshot"] and saved["index"] == advanced["index"],
                "Rollback retry differs from prepared advanced snapshot")
            advanced = saved
        else:
            write_private(prepared, canonical(advanced))
        require(advanced["index"] == pointer(current["snapshot"]["sequence"], current["snapshot"]["envelope_hash"]), "Advanced panel index differs from actual head")
        operator = self.app.get("Deployment", RELEASE + "-operator")
        require(operator["spec"]["replicas"] == 2, "Rollback case needs the current two-operator installation")
        try:
            self.c._scale_own("apps", RELEASE + "-operator", 0)
            wait(self.operator_absent)
            with self.c.outage("witness"):
                self.restore_old_state(captured)
                self.c._scale_own("apps", RELEASE + "-operator", 2)
                self.app.poke()
                wait(self.app.unavailable)
                self.same_application(captured)
        finally:
            self.c._scale_own("apps", RELEASE + "-operator", 2)
        self.fresh_current(current["snapshot"])
        self.same_application(captured)
        # A stale derived pointer is not an authenticated old envelope response:
        # the actual reader asks for the fresh witness's exact immutable hash.
        try:
            self.set_index(advanced["index"], captured["index"])
            require(self.c.current()["snapshot"] == current["snapshot"], "Derived pointer changed canonical witness head")
            self.fresh_current(current["snapshot"])
            self.same_application(captured)
        finally:
            self.set_index(captured["index"], advanced["index"])
        self.fresh_current(current["snapshot"])
        self.same_application(captured)
        result = {"production": False, "sameUIDNewResourceVersionStateRestore": True,
            "witnessOutageDataCurrentFalseNoDataWriteOrRestart": True, "freshWitnessHealsForwardNoHistoricalRollout": True,
            "derivedIndexRollbackIgnoredFreshExactHashWins": True, "derivedIndexRestoredByExactCAS": True,
            "rawEtcdResourceVersionRewindTested": False, "restoredCiphertextServerTested": False}
        receipt = self.root / "complete.json"
        if receipt.exists():
            require(json.loads(receipt.read_bytes()) == result, "Rollback completion receipt differs")
        else:
            write_private(receipt, canonical(result))
        return result
