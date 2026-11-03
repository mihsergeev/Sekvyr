"""Exact tail after a retained first Plain publish; never publish again."""

import hashlib
import json
from pathlib import Path

from app_modes import IMAGE, LABEL, ROLE, require, wait
from fixture import canonical, write_private


def _validated_initial_modes(cases, originals):
    """Read only the two creation-pinned apps; restore no topology by name."""
    apps = cases.apps
    require(isinstance(apps.modes, dict) and IMAGE.fullmatch(apps.python_image),
        "Original application modes and pinned Python image required")
    output = {}
    for name, mode, source_path in ((cases.env_name, "env", Path(__file__).resolve().parents[1] / "stage5" / "app.py"),
            (cases.volume_name, "volume", Path(__file__).resolve().with_name("file_app.py"))):
        require(name not in apps.modes or apps.modes[name] == mode, "Conflicting initial application mode")
        value = apps.owned.get("Deployment", name)
        meta, spec = value["metadata"], value["spec"]
        pin = apps.owned.pins.get(("Deployment", name), {})
        require(pin.get("uid") == meta["uid"] == originals[name]["uid"] and spec == originals[name]["spec"],
            "Initial application differs from creation UID or retained template")
        template = spec.get("template", {})
        pod = template.get("spec", {})
        require(spec.get("selector") == {"matchLabels": {LABEL: name}}
            and template.get("metadata", {}).get("labels") == {LABEL: name, ROLE: "application"}
            and pod.get("automountServiceAccountToken") is False and not pod.get("initContainers")
            and len(pod.get("containers", [])) == 1, "Initial application template differs")
        container = pod["containers"][0]
        command = ["python", "-B", "/app/app.py"] + (["--mode", "volume"] if mode == "volume" else [])
        mounts = [{"name": "source", "mountPath": "/app", "readOnly": True}]
        if mode == "volume":
            mounts.append({"name": "secrets", "mountPath": "/secrets", "readOnly": True})
        require(container.get("name") == "app" and container.get("image") == apps.python_image
            and container.get("command") == command and not container.get("args") and not container.get("env")
            and container.get("volumeMounts") == mounts
            and container.get("envFrom", []) == ([{"secretRef": {"name": cases.target_name}}] if mode == "env" else []),
            "Initial application image, command or target flow differs")
        source_name = name + "-source"
        volumes = pod.get("volumes", [])
        require(len(volumes) == (2 if mode == "volume" else 1)
            and len({item.get("name") for item in volumes}) == len(volumes), "Initial application volume set differs")
        byname = {item["name"]: item for item in volumes}
        config = byname.get("source", {}).get("configMap", {})
        require(set(byname.get("source", {})) == {"name", "configMap"}
            and set(config).issubset({"name", "defaultMode"}) and config.get("name") == source_name
            and config.get("defaultMode", 420) == 420, "Initial application source mount differs")
        if mode == "volume":
            require(byname.get("secrets") == {"name": "secrets", "secret": {"secretName": cases.target_name, "defaultMode": 288}},
                "Initial volume application target differs")
        source = apps.owned.get("ConfigMap", source_name)
        source_pin = apps.owned.pins.get(("ConfigMap", source_name), {})
        require(source_pin.get("uid") == source["metadata"]["uid"] and source.get("immutable") is True
            and source.get("data") == {"app.py": source_path.read_text(encoding="utf-8")} and not source.get("binaryData"),
            "Initial application immutable source differs")
        output[name] = mode
    return output


def resume_initial_after_publish(cases, retained_publish_frame):
    """Supply the retained frame or separately reviewed exact durable locals.

    A dictionary is not claimed to be a live traceback frame. Its provenance
    must be independently reviewed against the original durable captures; this
    helper additionally checks identities and saved values, never rebases them.

    Only the remaining two app scale operations run after readonly current /
    protected-state / target proof. A partial tail needs a separately reviewed
    continuation; this function never resets or adopts its completed steps.
    """
    frame = retained_publish_frame.f_locals if hasattr(retained_publish_frame, "f_locals") else retained_publish_frame
    p = cases.installation
    require(isinstance(frame, dict) and frame.get("self") is cases and frame.get("p") is p
        and {"pair", "before"}.issubset(frame) and "target" not in frame,
        "Exact incomplete original Plain publish frame required")
    require(not any(hasattr(cases, field) for field in ("selected", "reference", "baselines")),
        "Initial Plain publish tail already advanced")
    pair, before = frame["pair"], frame["before"]
    require(isinstance(pair, dict) and set(pair) == {"generation", "demo"}
        and all(isinstance(value, str) and 0 < len(value) <= 256 for value in pair.values())
        and (before is None or isinstance(before, str)), "Retained initial Plain values invalid")
    path = cases.root / "initial-values.json"
    require(path.is_file() and not path.is_symlink() and json.loads(path.read_bytes()) == pair,
        "Retained publish differs from saved initial values")
    require(not (cases.root / "plain-initial-proof.json").exists()
        and not (cases.root / "initial-resume-input.json").exists(), "Initial Plain tail already attempted")
    require((cases.env_name, cases.volume_name) == ("plain-env-app", "plain-volume-app")
        and p.binding["target"]["name"] == cases.target_name and p.lifecycle and p.lifecycle.managed,
        "Original captured initial Plain fixture required")
    require(cases.apps.namespace == p.namespace, "Initial applications outside Plain namespace")
    p.lifecycle._external_guard()
    p.lifecycle._retained_guard()
    for saved in p.lifecycle.managed.values():
        value = p.lifecycle._get(saved["manifest"])
        p.lifecycle._owned(value, saved["uid"])
        p.lifecycle._matches(value, saved["manifest"])
    originals = {}
    for name in (cases.env_name, cases.volume_name):
        value = cases.apps.owned.get("Deployment", name)
        pods = json.loads(cases.c.cluster.kube("get", "pods", "-n", p.namespace, "-l", LABEL + "=" + name, "-o", "json").stdout)["items"]
        require(value["spec"]["replicas"] == 0 and pods == [],
            "Initial application was already started")
        originals[name] = {"uid": value["metadata"]["uid"], "spec": value["spec"]}
    modes = _validated_initial_modes(cases, originals)
    wait(lambda: p.current(after_success=before))
    target = p.target_ref(pair["generation"], pair["demo"], after_success=before)
    # No repeated source read, owner publish, pair generation, Helm install or
    # CR poke occurs. Keep an exclusive private phase marker before app writes.
    write_private(cases.root / "initial-resume-input.json", canonical({"format": "sekvyr-stage7-plain-initial-resume-v1",
        "initialValuesSHA256": hashlib.sha256(path.read_bytes()).hexdigest(), "lastSuccessBeforePublish": before,
        "target": target, "applications": originals, "production": False}))
    require(_validated_initial_modes(cases, originals) == modes, "Initial application modes changed before tail")
    cases.apps.modes.update(modes)
    cases.selected = pair
    for name in (cases.env_name, cases.volume_name):
        current = cases.apps.owned.get("Deployment", name)
        require(current["metadata"]["uid"] == originals[name]["uid"] and current["spec"] == originals[name]["spec"],
            "Initial application changed after retained publish")
        cases.apps.owned.patch("Deployment", name, [{"op": "replace", "path": "/spec/replicas", "value": 1}])
        status = wait(lambda: value if (value := cases.apps.status(name)) and value["generation"] == pair["generation"] else False)
        require(status.get("value_digest") == hashlib.sha256(pair["demo"].encode("utf-8")).hexdigest(),
            "Initial application value differs from retained publish")
        require(len(cases.apps.footprint(name)["replica_sets"]) == 1, "Initial application gained historical ReplicaSets")
    cases.reference = target
    cases.baselines = {name: cases.apps.capture(name) for name in (cases.env_name, cases.volume_name)}
    return cases.proof("plain-initial", {"actualHelmInstall": True, "plainTargetUIDFromProtectedState": True,
        "initialEnvAndVolumeVerified": True, "noHistoricalRollout": True})
