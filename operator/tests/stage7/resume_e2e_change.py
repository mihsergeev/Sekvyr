"""Finish the same published change from its retained original call frame.

The coordinator must preserve the actual pre-publication observations. No
inference from current history, new publication, bootstrap or resource adoption.
"""

import copy
import hashlib

from app_modes import require, wait


def run(case, original):
    require(case.installed and isinstance(original, dict) and set(original) == {"before", "old", "snapshot"},
        "Change continuation needs the actual original observations")
    current = case.c.current()
    require(current["snapshot"] == original["snapshot"] and case.selected == case.pair("changed"),
        "Change continuation may not rebase a publication")
    wait(lambda: case.app.current(original["snapshot"], True), timeout=180)
    new = wait(lambda: value if (value := case.app.status()) and value["generation"] == case.selected["generation"] else False)
    after, old = case.app.footprint(), original["old"]
    require(new["pod_uid"] != old["pod_uid"] and new["boot_id"] != old["boot_id"]
        and new["value_digest"] == hashlib.sha256(case.selected["demo"].encode()).hexdigest(),
        "Original change did not reach a new exact envFrom process")
    require(len(set(after["replica_sets"]) - set(original["before"]["replica_sets"])) == 1,
        "Original change must add exactly one ReplicaSet")
    from application import TARGET, REVISION
    target = case.app.get("Secret", TARGET)
    expected = copy.deepcopy(original["before"]["template"])
    expected["metadata"].setdefault("annotations", {})["secrets.sekvyr.ru/restart-" + target["metadata"]["uid"]] = target["metadata"]["annotations"][REVISION]
    require(after["template"] == expected, "Change continuation found another template mutation")
    return case.proof("e2e2-changed", {"actualCanonicalAdvance": True, "newEnvFromPodAndBoot": True,
        "newReplicaSets": 1, "onlyOwnRestartAnnotation": True,
        "sameOriginalPublicationResumedAfterFixtureRepair": True, "repeatPublication": False})
