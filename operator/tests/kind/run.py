#!/usr/bin/env python3
"""Real local Kubernetes admission/RBAC/scaffold checks; no E2E2 synchronization.

Runs only against the fixed sekvyr-stage2 kind node. Bootstrap data is generated
in the temporary cluster and never written to source files. Requires PyYAML.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import yaml

NODE = "sekvyr-stage2-control-plane"
NAMESPACE = "stage2"
FOREIGN = "stage2-foreign"
SERVICE_ACCOUNT = "sekvyr-operator"
RELEASE = "stage2"
RESULTS = []


def run(args, value=None, check=True):
    if args[:3] == ["sudo", "-n", "docker"]:
        args = args[:3] + ["--host=unix:///var/run/docker.sock"] + args[3:]
    result = subprocess.run(args, input=value, text=True, capture_output=True)
    if check and result.returncode:
        # Do not print submitted objects or command output: they may contain tokens.
        raise RuntimeError("command failed: " + " ".join(args[:5]))
    return result


def k(*args, value=None, check=True):
    return run(["sudo", "-n", "docker", "exec", "-i", NODE, "kubectl",
                "--kubeconfig=/etc/kubernetes/admin.conf", *args], value, check)


def obj(kind, name, spec=None, api="v1", namespace=NAMESPACE):
    value = {"apiVersion": api, "kind": kind, "metadata": {"name": name}}
    if namespace:
        value["metadata"]["namespace"] = namespace
    if spec is not None:
        value["spec"] = spec
    return value


def create(value):
    return json.loads(k("create", "-f", "-", "-o", "json", value=json.dumps(value)).stdout)


def get(kind, name, namespace=NAMESPACE):
    return json.loads(k("get", kind, name, "-n", namespace, "-o", "json").stdout)


def record(name):
    RESULTS.append(name)
    print("PASS " + name, flush=True)


def deny(name, value):
    candidate = copy.deepcopy(value)
    candidate["metadata"]["name"] = "negative-" + uuid.uuid4().hex[:12]
    result = k("create", "--dry-run=server", "--validate=strict", "-f", "-",
               value=json.dumps(candidate), check=False)
    if result.returncode == 0:
        raise AssertionError("admission accepted: " + name)
    record("admission denies " + name)


def condition_reason(kind, name, expected, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = get(kind, name)
        conditions = {c["type"]: c for c in current.get("status", {}).get("conditions", [])}
        ready = conditions.get("Ready", {})
        if ready.get("reason") == expected:
            assert ready["status"] == "False"
            assert conditions["DataCurrent"]["status"] == "False"
            assert not current["status"].get("lastSuccessfulSyncTime")
            assert not current["status"].get("lastAppliedRevision")
            assert not current["status"].get("lastVerifiedCheckpoint")
            return current
        time.sleep(1)
    raise AssertionError("missing sanitized condition: " + expected)


def poke(name):
    k("annotate", "sekvyrsecret", name, "-n", NAMESPACE,
      "stage2-test-reconcile=" + uuid.uuid4().hex, "--overwrite")


def auth(verb, resource, expected, namespace=NAMESPACE, subject=SERVICE_ACCOUNT):
    resource_args = [resource]
    if resource in ("sekvyrsecrets/status", "deployments/scale", "serviceaccounts/token"):
        base, subresource = resource.split("/")
        resource_args = [base, "--subresource=" + subresource]
    result = k("auth", "can-i", verb, *resource_args, "-n", namespace,
               "--as=system:serviceaccount:" + NAMESPACE + ":" + subject, check=False)
    assert result.stdout.strip() == ("yes" if expected else "no"), (verb, resource, namespace)
    record("RBAC " + ("allows " if expected else "denies ") + verb + " " + resource + " in " + namespace)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chart", type=Path, required=True)
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args()
    assert args.task_dir.resolve().parent == Path("/tmp")
    assert args.task_dir.name.startswith("sekvyr-stage2.")
    assert (args.task_dir / "kubeconfig").is_file()
    label = run(["sudo", "-n", "docker", "inspect", "--format",
                 '{{index .Config.Labels "io.x-k8s.kind.cluster"}}', NODE]).stdout.strip()
    assert label == "sekvyr-stage2", "not the isolated test cluster"
    for namespace in (NAMESPACE, FOREIGN):
        create(obj("Namespace", namespace, namespace=None))
    installation_id = str(uuid.uuid4())
    secrets = []
    sensitive = []
    for name, key, content, immutable in (
        ("stage2-node", "node.key", base64.b64encode(os.urandom(32)).decode() + "\n", True),
        ("stage2-trust", "trust.json", '{"fixture":"fake-stage2-no-crypto-trust"}', True),
        ("stage2-state", "installation.json", json.dumps({"installationID": installation_id,
                                                        "bootstrapGeneration": 1}), False),
    ):
        value = obj("Secret", name)
        value.update(type="Opaque", immutable=immutable, stringData={key: content})
        if immutable:
            sensitive.append(content.strip())
        created = create(value)
        secrets.append({"name": name, "uid": created["metadata"]["uid"], "key": key})
    values = {
        "image": {"repository": args.image_repository, "digest": args.image_digest, "pullPolicy": "Never"},
        "installation": {
            "installationID": installation_id, "namespace": NAMESPACE,
            "serviceAccount": SERVICE_ACCOUNT, "bootstrapGeneration": 1,
            "allowedPanelOrigins": ["https://sekvyr.example.com"],
            "allowedWitnessOrigins": ["https://witness.example.com"],
            "identityKeySecret": secrets[0], "trustBundleSecret": secrets[1], "stateSecret": secrets[2],
            "protectedSecretNames": [], "protectedSecretUIDs": [],
            "protectedPrefixes": ["sh.helm.release.v1."], "caConfigMaps": [],
        },
    }
    # Values contain references/UIDs only, never private keys or projected tokens.
    values_path = args.task_dir / "values.json"
    values_path.write_text(json.dumps(values), encoding="utf-8")
    run(["helm", "lint", str(args.chart), "--namespace", NAMESPACE, "-f", str(values_path)])
    run(["helm", "upgrade", "--install", RELEASE, str(args.chart), "-n", NAMESPACE,
         "--kubeconfig", str(args.task_dir / "kubeconfig"), "-f", str(values_path), "--wait", "--timeout", "180s"])
    record("Helm installs digest-pinned scaffold with existing immutable key/trust Secrets")
    examples = args.chart.resolve().parents[1] / "design" / "examples"
    store = yaml.safe_load((examples / "01-store-e2e.yaml").read_text())
    store["metadata"]["namespace"] = NAMESPACE
    store_created = create(store)
    secret = yaml.safe_load((examples / "02-secret-e2e.yaml").read_text())
    secret["metadata"]["namespace"] = NAMESPACE
    secret["spec"]["storeRef"]["uid"] = store_created["metadata"]["uid"]
    sentinel = obj("Secret", "billing-env")
    sentinel.update(type="Opaque", stringData={"PRESERVE": "fake-stage2-preserved-" + uuid.uuid4().hex})
    original_target = create(sentinel)
    deployment = obj("Deployment", "billing-api", {
        "replicas": 0, "selector": {"matchLabels": {"app": "stage2-sentinel"}},
        "template": {"metadata": {"labels": {"app": "stage2-sentinel"}}, "spec": {"containers": [{
            "name": "app", "image": args.image_repository + "@" + args.image_digest,
            "envFrom": [{"secretRef": {"name": "billing-env"}}],
        }]}},
    }, api="apps/v1")
    original_template = create(deployment)["spec"]["template"]
    create(secret)
    condition_reason("sekvyrsecret", secret["metadata"]["name"], "VerificationNotImplemented")
    condition_reason("sekvyrstore", store["metadata"]["name"], "VerificationNotImplemented")
    record("E2E2 has no success/checkpoint/data/rollout claims without implementation")

    bad = copy.deepcopy(store); bad["spec"]["endpoint"]["url"] = "http://sekvyr.example.com"
    deny("HTTP origin", bad)
    bad = copy.deepcopy(secret); bad["spec"]["endpoint"] = {"url": "https://other.example.com"}
    deny("app URL override / unknown spec", bad)
    bad = copy.deepcopy(secret); bad["spec"]["storeRef"]["namespace"] = FOREIGN
    deny("cross-namespace reference", bad)
    bad = copy.deepcopy(store); bad["spec"]["bindings"][0]["encryption"]["protocol"] = "e2e1"
    deny("E2E1 fallback", bad)
    bad = copy.deepcopy(store); bad["spec"]["bindings"][0]["encryption"]["freshness"]["mode"] = "Offline"
    deny("offline freshness fallback", bad)
    bad = copy.deepcopy(secret); bad["spec"]["refreshIntervalSeconds"] = 1
    deny("unbounded polling", bad)
    bad = copy.deepcopy(secret); bad["spec"]["rollout"] = {"enabled": True, "deployments": []}
    deny("empty enabled rollout", bad)
    bad = copy.deepcopy(store); other = copy.deepcopy(bad["spec"]["bindings"][0]); other["name"] = "different"
    bad["spec"]["bindings"].append(other)
    deny("duplicate binding UUID", bad)
    immutable = copy.deepcopy(store_created)
    immutable.pop("status", None)
    immutable["spec"]["bindings"][0]["target"]["name"] = "another-target"
    result = k("replace", "--dry-run=server", "-f", "-", value=json.dumps(immutable), check=False)
    assert result.returncode, "immutable target update accepted"
    record("CEL blocks target rebinding")

    auth("get", "secrets/stage2-node", True)
    auth("list", "secrets", False)
    for verb in ("create", "update", "patch", "delete"):
        auth(verb, "secrets", False)
    auth("get", "secrets/stage2-node", False, FOREIGN)
    auth("get", "sekvyrstores", True)
    auth("get", "sekvyrstores", False, FOREIGN)
    auth("patch", "sekvyrsecrets/status", True)
    auth("patch", "deployments", False)
    auth("patch", "deployments/scale", False)
    auth("delete", "pods", False)
    auth("create", "serviceaccounts/token", False)
    auth("create", "roles", False)
    auth("create", "leases", False)
    auth("update", "leases/sekvyr-operator-leader", True)
    create(obj("ServiceAccount", "application"))
    auth("create", "sekvyrstores", False, subject="application")
    auth("create", "sekvyrsecrets", False, subject="application")
    auth("get", "secrets/stage2-node", False, subject="application")

    # Capture mounted tokens only in process memory; print no JWT or token hash.
    pods = json.loads(k("get", "pods", "-n", NAMESPACE, "-l",
                        "app.kubernetes.io/instance=" + RELEASE, "-o", "json").stdout)["items"]
    assert len(pods) == 1
    pod = pods[0]
    token_base = "/var/lib/kubelet/pods/" + pod["metadata"]["uid"] + "/volumes/kubernetes.io~projected/"
    claims = []
    for volume in ("kube-api", "panel-api"):
        # Inspect AtomicWriter's root-owned projection pointer. Following its
        # user-owned token symlink as root is blocked by protected_symlinks in
        # the sticky kubelet directory; do not weaken that protection.
        token = run(["sudo", "-n", "docker", "exec", NODE, "cat", token_base + volume + "/..data/token"]).stdout.strip()
        sensitive.append(token)
        payload = token.split(".")[1]
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        assert decoded["sub"] == "system:serviceaccount:" + NAMESPACE + ":" + SERVICE_ACCOUNT
        assert decoded["kubernetes.io"]["pod"]["uid"] == pod["metadata"]["uid"]
        assert decoded["exp"] > time.time()
        claims.append(decoded)
        del token
    assert claims[1]["aud"] == ["sekvyr"] and claims[0]["aud"] != claims[1]["aud"]
    assert any(v["name"] == "panel-api" and "serviceAccountToken" in v["projected"]["sources"][0]
               for v in pod["spec"]["volumes"])
    record("real projected tokens have distinct audiences, fixed SA/pod, expiry and renewable projection")

    # Mutating only the test fixture proves the controller does not bless lost/replaced bootstrap.
    k("delete", "secret", "stage2-state", "-n", NAMESPACE)
    poke(secret["metadata"]["name"])
    condition_reason("sekvyrsecret", secret["metadata"]["name"], "StateMissing")
    record("missing state fails closed")
    replacement = obj("Secret", "stage2-state")
    replacement.update(type="Opaque", stringData={"installation.json": json.dumps({
        "installationID": installation_id, "bootstrapGeneration": 1})})
    create(replacement)
    poke(secret["metadata"]["name"])
    condition_reason("sekvyrsecret", secret["metadata"]["name"], "BootstrapMismatch")
    record("same-name replacement UID fails closed")
    current_target = get("secret", "billing-env")
    assert current_target["data"] == original_target["data"]
    assert current_target["metadata"]["resourceVersion"] == original_target["metadata"]["resourceVersion"]
    assert get("deployment", "billing-api")["spec"]["template"] == original_template
    record("target Secret and application Pod template remain byte-equivalent and unpatched")
    logs = k("logs", "deployment/stage2-operator", "-n", NAMESPACE).stdout
    public_status = json.dumps(get("sekvyrsecret", secret["metadata"]["name"]))
    public_status += json.dumps(get("sekvyrstore", store["metadata"]["name"]))
    assert not any(value in logs or value in public_status for value in sensitive)
    sensitive.clear()
    record("controller logs and resource status contain no bootstrap contents or projected JWT")
    output = {
        "scope": "Real local Kubernetes 1.37 admission/RBAC/stage2 scaffold; no E2E2 sync or witness",
        "operatorImage": args.image_repository + "@" + args.image_digest,
        "cluster": "sekvyr-stage2", "passed": RESULTS,
        "limitations": ["bootstrap metadata only, no cryptographic bootstrap verification",
                        "projected claims and renewable mount checked; timed kubelet rotation not awaited",
                        "no production connections and no E2E2 data synchronization"],
    }
    (args.task_dir / "results.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print("PASS_TOTAL=" + str(len(RESULTS)))


if __name__ == "__main__":
    main()
