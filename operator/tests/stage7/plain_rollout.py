"""Explicit coordinator-only Plain rollout OFF -> ON transition.

The bootstrap, source, target and Secret data never change here. The existing
captured Helm lifecycle is required; this helper cannot adopt an installation
or rebuild missing provenance from live names. No live action runs on import.
"""

import base64
import copy
import hashlib
import json

from app_modes import NAME, require
from helm_lifecycle import canonical, private_exact
from plain_installation import REVISION


def target_proof(installation):
    reference = installation.target_ref()
    value = json.loads(installation.cluster.kube("get", "Secret", reference["name"], "-n", installation.namespace, "-o", "json").stdout)
    require(value["metadata"]["uid"] == reference["uid"] and not value["metadata"].get("deletionTimestamp"), "Plain rollout target was replaced")
    return {"reference": reference, "revision": value["metadata"]["annotations"][REVISION],
        "dataDigest": hashlib.sha256(canonical(value.get("data", {}))).hexdigest()}


def app_proof(installation, names):
    proof = {}
    for name in names:
        deployment = installation.owned.get("Deployment", name)
        require(name != installation.release + "-operator" and not deployment["metadata"].get("deletionTimestamp"), "Plain rollout cannot target its operator")
        labels = deployment["spec"]["selector"].get("matchLabels")
        require(isinstance(labels, dict) and labels and not deployment["spec"]["selector"].get("matchExpressions"), "Exact fixture app selector required")
        selector = ",".join(key + "=" + value for key, value in sorted(labels.items()))
        def listed(kind):
            return json.loads(installation.cluster.kube("get", kind, "-n", installation.namespace, "-l", selector, "-o", "json").stdout)["items"]
        sets, pods = listed("replicasets"), listed("pods")
        require(all(value["metadata"].get("namespace") == installation.namespace and any(ref.get("uid") == deployment["metadata"]["uid"] and ref.get("kind") == "Deployment" and ref.get("controller") is True
            for ref in value["metadata"].get("ownerReferences", [])) for value in sets), "Plain app ReplicaSet has foreign owner")
        set_uids = {value["metadata"]["uid"] for value in sets}
        require(all(value["metadata"].get("namespace") == installation.namespace and not value["metadata"].get("deletionTimestamp")
            and any(ref.get("uid") in set_uids and ref.get("kind") == "ReplicaSet" and ref.get("controller") is True
                for ref in value["metadata"].get("ownerReferences", [])) for value in pods), "Plain app Pod has foreign owner or is replacing")
        require(len(pods) == deployment["spec"].get("replicas", 1), "Plain app Pod count is not stable")
        instances = []
        for pod in pods:
            statuses = pod.get("status", {}).get("containerStatuses", [])
            require(len(statuses) == len(pod["spec"]["containers"]) and all(item.get("containerID") and item.get("state", {}).get("running") for item in statuses),
                "Plain app process observation is incomplete")
            instances.append({"uid": pod["metadata"]["uid"], "containers": sorted(item["containerID"] for item in statuses)})
        proof[name] = {"uid": deployment["metadata"]["uid"], "template": deployment["spec"]["template"],
            "replicas": deployment["spec"].get("replicas"), "replicaSets": sorted(set_uids), "pods": sorted(instances, key=lambda item: item["uid"])}
    return proof


def patch_spec(installation, kind, name, old, new, uid):
    current = installation.owned.get(kind, name)
    require(current["metadata"]["uid"] == uid, "Plain rollout custom resource UID changed")
    if current["spec"] == new:
        return
    require(current["spec"] == old, "Plain rollout custom resource differs from exact reviewed plan")
    installation.owned.patch(kind, name, [{"op": "test", "path": "/spec", "value": old},
        {"op": "replace", "path": "/spec", "value": new}])


def inactive_state(installation):
    state = installation.owned.get("Secret", installation.state_name)
    body = json.loads(base64.b64decode(state["data"]["state.json"], validate=True))
    store = installation.owned.get("SekvyrStore", installation.store_name)
    record = body["bindings"][store["metadata"]["uid"] + "/" + installation.context["bindingID"]]
    require(record.get("mode") == "Plain" and record.get("head") is None and "head" in record,
        "Plain rollout state mode differs")
    authorization = record.get("rollout") or {}
    require(isinstance(authorization, dict), "Plain rollout authorization is malformed")
    intent = authorization.get("intent") or {}
    require(isinstance(intent, dict) and not intent.get("eligible"), "Plain enable must not revive historical eligible intent")


def enable_rollout(installation, deployment_names):
    p = installation
    require(isinstance(deployment_names, (list, tuple)) and 1 <= len(deployment_names) <= 16
        and all(isinstance(name, str) and NAME.fullmatch(name) for name in deployment_names),
        "Plain rollout requires exact unique bounded app names")
    names = sorted(deployment_names)
    require(len(set(names)) == len(names), "Plain rollout requires exact unique bounded app names")
    require(p.lifecycle is not None and p.lifecycle.managed and p.values is not None and p.binding is not None,
        "Plain rollout requires the original captured installation lifecycle")
    directory = p.root / "rollout-enable"
    directory.mkdir(mode=0o700, exist_ok=True)
    require(not directory.is_symlink(), "Unsafe Plain rollout input directory")
    path = directory / "plan.json"
    if path.exists():
        require(not path.is_symlink(), "Unsafe Plain rollout plan")
        plan = json.loads(path.read_bytes())
        require(plan["context"] == p.context and plan["deployments"] == names and p.values in (plan["old_values"], plan["new_values"])
            and p.binding in (plan["old_binding"], plan["new_binding"]), "Plain rollout retry changed reviewed input")
    else:
        current = p.current()
        require(current and p.values["ha"]["enabled"] is False and p.values["rollout"] == {"enabled": False, "allowedDeployments": []}
            and p.binding["rollout"] == {"allowedDeployments": []}, "Plain enable must start from an explicit current OFF installation")
        store = p.owned.get("SekvyrStore", p.store_name)
        cr = p.owned.get("SekvyrSecret", p.cr_name)
        require(cr["spec"]["rollout"] == {"enabled": False, "deployments": []} and len(store["spec"]["bindings"]) == 1
            and store["spec"]["bindings"][0] == p.binding, "Plain OFF custom resources differ")
        inactive_state(p)
        new_binding, next_values = copy.deepcopy(p.binding), copy.deepcopy(p.values)
        new_binding["rollout"]["allowedDeployments"] = names
        next_values["rollout"] = {"enabled": True, "allowedDeployments": names}
        next_store, next_cr = copy.deepcopy(store["spec"]), copy.deepcopy(cr["spec"])
        next_store["bindings"][0] = new_binding
        next_cr["rollout"] = {"enabled": True, "deployments": names}
        plan = {"context": p.context, "deployments": names, "store_uid": store["metadata"]["uid"], "cr_uid": cr["metadata"]["uid"],
            "old_store": store["spec"], "new_store": next_store, "old_cr": cr["spec"], "new_cr": next_cr,
            "old_binding": p.binding, "new_binding": new_binding, "old_values": p.values, "new_values": next_values,
            "before_success": current["status"]["lastSuccessfulSyncTime"], "target": target_proof(p), "apps": app_proof(p, names)}
        private_exact(path, canonical(plan))
    # Exact delta guard also catches accidental changes in a saved resume plan.
    old_values = copy.deepcopy(plan["new_values"])
    old_values["rollout"] = plan["old_values"]["rollout"]
    old_binding = copy.deepcopy(plan["new_binding"])
    old_binding["rollout"] = plan["old_binding"]["rollout"]
    expected_store = copy.deepcopy(plan["old_store"])
    expected_store["bindings"] = [plan["new_binding"]]
    expected_cr = copy.deepcopy(plan["old_cr"])
    expected_cr["rollout"] = {"enabled": True, "deployments": names}
    require(old_values == plan["old_values"] and old_binding == plan["old_binding"] and plan["new_values"]["rollout"] == {"enabled": True, "allowedDeployments": names}
        and plan["new_binding"]["rollout"] == {"allowedDeployments": names}
        and plan["new_store"] == expected_store and plan["new_cr"] == expected_cr
        and plan["old_store"]["bindings"] == [plan["old_binding"]], "Plain rollout plan changes bootstrap or source identity")
    require(target_proof(p) == plan["target"] and app_proof(p, names) == plan["apps"], "Plain rollout preflight differs from reviewed target/apps")
    inactive_state(p)
    private_exact(directory / "reviewed-active-values.json", canonical(plan["new_values"]))
    if not (directory / "helm-complete.json").exists():
        p.lifecycle.upgrade(plan["new_values"])
        private_exact(directory / "helm-complete.json", canonical({"upgraded": True}))
    else:
        p.lifecycle._external_guard()
        p.lifecycle._retained_guard()
        for saved in p.lifecycle.managed.values():
            live = p.lifecycle._get(saved["manifest"])
            p.lifecycle._owned(live, saved["uid"])
            p.lifecycle._matches(live, saved["manifest"])
    # Broaden the administrative allowlist first, then opt in the exact Store
    # binding and CR. Every public API mutation retains its UID/RV/spec CAS.
    patch_spec(p, "SekvyrStore", p.store_name, plan["old_store"], plan["new_store"], plan["store_uid"])
    patch_spec(p, "SekvyrSecret", p.cr_name, plan["old_cr"], plan["new_cr"], plan["cr_uid"])
    p.binding, p.values = copy.deepcopy(plan["new_binding"]), copy.deepcopy(plan["new_values"])
    from app_modes import wait
    def fresh():
        cr = p.current(after_success=plan["before_success"])
        if not cr:
            return False
        conditions = {item["type"]: item for item in cr["status"].get("conditions", [])}
        rollout = conditions.get("RolloutReady", {})
        return cr if rollout.get("status") == "True" and rollout.get("observedGeneration") == cr["metadata"]["generation"] else False
    wait(fresh)
    require(target_proof(p) == plan["target"] and app_proof(p, names) == plan["apps"], "Plain enable changed data/revision or restarted an app")
    inactive_state(p)
    result = {"plainRolloutExplicitlyEnabled": True, "bootstrapAndSourceUnchanged": True,
        "targetDataAndRevisionUnchanged": True, "noHistoricalAppRestart": True, "production": False}
    private_exact(directory / "complete.json", canonical(result))
    return result
