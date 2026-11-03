#!/usr/bin/env python3
"""Delete one approved test run after UID/schema and cross-namespace guards."""

import argparse
import json
from pathlib import Path

import yaml

from authority import Authority
import common


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--chart-path", type=Path, required=True)
    parser.add_argument("--store-crd-uid", required=True)
    parser.add_argument("--secret-crd-uid", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    task = Authority.safe_task(args.task_dir)
    if task.parent != Path("/opt/sekvyr-trial"):
        raise RuntimeError("Remote cleanup requires the exact approved server task directory")
    common.configure("k0s", task)
    prefix = task.name
    apps = prefix + "-apps"
    expected = {"sekvyrstores.secrets.sekvyr.ru": args.store_crd_uid,
                "sekvyrsecrets.secrets.sekvyr.ru": args.secret_crd_uid}
    metadata = json.loads((task / "private" / "bootstrap.json").read_text())
    namespace_uids = metadata.get("namespace_uids", {})
    namespace_names = {prefix + "-" + suffix for suffix in ("apps", "foreign", "witness", "panel")}
    if set(namespace_uids) != namespace_names or any(not uid for uid in namespace_uids.values()):
        raise RuntimeError("Creation-time namespace UID pins are missing; cleanup refused")
    if metadata.get("crd_uids") != expected:
        raise RuntimeError("Creation-time CRD UID pins differ; cleanup refused")

    def guard_crds():
        for name, uid in expected.items():
            current = json.loads(common.kube("get", "crd", name, "-o", "json").stdout)
            reviewed = yaml.safe_load((args.chart_path / "crds" / (name + ".yaml")).read_text())
            if current["metadata"]["uid"] != uid or current["spec"]["versions"] != reviewed["spec"]["versions"]:
                raise RuntimeError("Test CRD UID/schema changed; cleanup refused")
            objects = json.loads(common.kube("get", name, "-A", "-o", "json").stdout)["items"]
            if any(item["metadata"]["namespace"] != apps for item in objects):
                raise RuntimeError("A CR exists outside this test run; cleanup refused")

    guard_crds()
    for name, uid in namespace_uids.items():
        namespace = json.loads(common.kube("get", "namespace", name, "-o", "json").stdout)
        if namespace["metadata"]["uid"] != uid:
            raise RuntimeError("Test namespace UID changed; cleanup refused")
    store = common.get("sekvyrstore", "application-secrets", apps)
    if store["metadata"]["uid"] != metadata["store_uid"]:
        raise RuntimeError("Test Store identity changed; cleanup refused")
    if not args.execute:
        print("PASS cleanup guards; no resources deleted")
        return
    # The operator is removed before its CRDs. The panel DB is removed only
    # after the coordinator confirms all independent PostgreSQL tests finished.
    for suffix in ("apps", "foreign", "witness", "panel"):
        name = prefix + "-" + suffix
        delete_uid("/api/v1/namespaces/" + name, namespace_uids[name])
        common.wait("isolated namespace removed", lambda name=name: not common.kube(
            "get", "namespace", name, "--ignore-not-found", "-o", "name").stdout.strip())
    guard_crds()
    for name, uid in expected.items():
        delete_uid("/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + name, uid)
        common.wait("isolated CRD removed", lambda name=name: not common.kube(
            "get", "crd", name, "--ignore-not-found", "-o", "name").stdout.strip())
    print("PASS exact isolated namespaces and UID/schema-pinned test CRDs removed")


def delete_uid(path, uid):
    # Both namespaced run infrastructure and the cluster-scoped CRD require a
    # server-enforced UID precondition, closing the GET-then-DELETE race.
    body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid},
            "propagationPolicy": "Background"}
    common.kube("delete", "--raw", path, "-f", "-", value=json.dumps(body))


if __name__ == "__main__":
    main()
