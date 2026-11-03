"""One incremental, read-only metadata/status diagnostic; no replay load loop."""

from datetime import datetime, timezone
import json
import os
import re
import time

from application import RESOURCE, STORE
from app_modes import require
from fixture import canonical, write_private


def _reason(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,79}", value) else "Unclassified"


def run(e, expected_snapshot, expected_authority, expected_enrollment):
    root = e.root / "readiness-upgrade"
    path = root / "diagnostic-300s.ndjson"
    require(not path.exists() and not path.is_symlink(), "Existing diagnostic cannot silently restart")
    namespace = e.app.namespace
    expected_cr = e.app.created[("SekvyrSecret", RESOURCE)]["uid"]
    expected_store = e.app.created[("SekvyrStore", STORE)]["uid"]
    expected_deploy = {role: e.app.created[("Deployment", "stage6-" + role)]["uid"] for role in ("operator", "fencer")}
    def bookend():
        value = e.c.current()
        return {"scopeMatches": value["scope"] == e.c.protocol.scope, "genesisMatches": value["genesis_hash"] == e.c.protocol.genesis_hash,
            "snapshotMatches": value["snapshot"] == expected_snapshot, "authorityMatches": value["authority"] == expected_authority,
            "enrollmentMatches": value["enrollments"].get(e.c.protocol.installation_id) == expected_enrollment}
    initial = bookend()
    require(all(initial.values()), "Diagnostic canonical context differs from the retained candidate")
    started, samples, failures, errors, maximum_gap = time.monotonic(), 0, 0, 0, 0
    reasons, first_failure, previous_time = {}, None, None
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        while True:
            tick = time.monotonic()
            if previous_time is not None:
                maximum_gap = max(maximum_gap, tick - previous_time)
            previous_time = tick
            sample = {"utc": datetime.now(timezone.utc).isoformat(), "elapsedSeconds": round(tick - started, 3)}
            try:
                raw = e.c.cluster.kube("get", "deployments,replicasets,pods,sekvyrsecrets,sekvyrstores", "-n", namespace,
                    "-o", "json", "--request-timeout=5s").stdout
                require(len(raw.encode()) < 2 << 20, "Diagnostic metadata inventory exceeds bounds")
                items = json.loads(raw)["items"]
                require(isinstance(items, list) and len(items) <= 256, "Diagnostic metadata inventory invalid")
                by_kind_name = {(item["kind"], item["metadata"]["name"]): item for item in items}
                deployments, pods = {}, {}
                for role, uid in expected_deploy.items():
                    deployment = by_kind_name[("Deployment", "stage6-" + role)]
                    require(deployment["metadata"]["uid"] == uid, "Diagnostic Deployment replaced")
                    state = deployment.get("status", {})
                    deployments[role] = {"uid": uid, "generation": deployment["metadata"]["generation"], "observedGeneration": state.get("observedGeneration"),
                        "desired": deployment["spec"]["replicas"], **{key: state.get(key, 0) for key in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas")}}
                    owners = {item["metadata"]["uid"] for item in items if item["kind"] == "ReplicaSet" and any(ref.get("kind") == "Deployment" and ref.get("uid") == uid for ref in item["metadata"].get("ownerReferences", []))}
                    selected = [item for item in items if item["kind"] == "Pod" and not item["metadata"].get("deletionTimestamp") and any(ref.get("kind") == "ReplicaSet" and ref.get("uid") in owners for ref in item["metadata"].get("ownerReferences", []))]
                    pods[role] = [{"uid": item["metadata"]["uid"], "ready": any(condition.get("type") == "Ready" and condition.get("status") == "True" for condition in item.get("status", {}).get("conditions", [])),
                        "containers": [{"name": status["name"], "cid": status.get("containerID"), "restarts": status["restartCount"], "ready": status.get("ready"), "running": bool(status.get("state", {}).get("running"))} for status in item.get("status", {}).get("containerStatuses", [])]} for item in selected]
                cr, store = by_kind_name[("SekvyrSecret", RESOURCE)], by_kind_name[("SekvyrStore", STORE)]
                require(cr["metadata"]["uid"] == expected_cr and store["metadata"]["uid"] == expected_store, "Diagnostic CR or Store replaced")
                status = cr.get("status", {})
                conditions = [{key: condition.get(key) for key in ("type", "status", "reason", "observedGeneration", "lastTransitionTime")} for condition in status.get("conditions", [])]
                sample.update(deployments=deployments, pods=pods, cr={"uid": expected_cr, "generation": cr["metadata"]["generation"],
                    "observedGeneration": status.get("observedGeneration"), "observedStoreUID": status.get("observedStoreUID"), "observedStoreGeneration": status.get("observedStoreGeneration"),
                    "storeUID": expected_store, "storeGeneration": store["metadata"]["generation"], "lastAttemptTime": status.get("lastAttemptTime"), "lastSuccessfulSyncTime": status.get("lastSuccessfulSyncTime"),
                    "conditions": conditions, "lastError": _reason(status.get("lastError")) if status.get("lastError") else None,
                    "checkpointSequence": status.get("lastVerifiedCheckpoint", {}).get("sequence"),
                    "checkpointMatches": status.get("lastVerifiedCheckpoint") == {"sequence": expected_snapshot["sequence"], "envelopeHash": expected_snapshot["envelope_hash"]}})
                replica_good = all(value["desired"] == 2 and value["observedGeneration"] == value["generation"] and all(value[key] == 2 for key in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas")) for value in deployments.values())
                pod_good = all(len(values) == 2 and all(value["ready"] and value["containers"] and all(container["ready"] and container["running"] for container in value["containers"]) for value in values) for values in pods.values())
                named = {condition["type"]: condition for condition in conditions}
                cr_good = status.get("observedGeneration") == cr["metadata"]["generation"] and status.get("observedStoreUID") == expected_store and status.get("observedStoreGeneration") == store["metadata"]["generation"] and sample["cr"]["checkpointMatches"] and all(named.get(name, {}).get("status") == "True" and named[name].get("observedGeneration") == cr["metadata"]["generation"] for name in ("Ready", "DataCurrent", "BootstrapReady", "WitnessReady", "RolloutReady"))
                sample.update(replicaHealthy=replica_good, podsHealthy=pod_good, verifiedCurrentHealthy=cr_good)
                if not (replica_good and pod_good and cr_good):
                    failures += 1
                    for condition in conditions:
                        if condition["status"] != "True":
                            name = _reason(condition["type"]) + "/" + _reason(condition["reason"])
                            reasons[name] = reasons.get(name, 0) + 1
                    if first_failure is None:
                        first_failure = bookend()
                        sample["canonicalAtFirstFailure"] = first_failure
            except Exception:
                errors += 1
                sample["readError"] = "MetadataDiagnosticUnavailable"
            stream.write(canonical(sample) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
            samples += 1
            elapsed = time.monotonic() - started
            if elapsed >= 300:
                break
            time.sleep(max(0, min(2 - (time.monotonic() - tick), 300 - elapsed)))
    final = bookend()
    result = {"production": False, "durationSeconds": round(time.monotonic() - started, 3), "samples": samples,
        "requestedIntervalSeconds": 2, "maximumSampleGapSeconds": round(maximum_gap, 3), "unhealthySamples": failures,
        "metadataReadErrors": errors, "falseConditionReasons": reasons, "canonicalBookendsMatch": all(initial.values()) and all(final.values()),
        "canonicalAtFirstFailure": first_failure, "original120SecondAttemptReclassified": False}
    write_private(root / "diagnostic-300s-summary.json", canonical(result))
    return result
