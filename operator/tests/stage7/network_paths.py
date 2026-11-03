"""Additive, create-only product paths for the six owned trial namespaces.

This does not establish packet isolation: the coordinator must test positive
paths and forbidden upstream access with the actual installed network plugin.
No chart, existing policy, cluster network or prior-stage helper is changed.
"""

import copy
import hashlib
import ipaddress
import json
import re

from app_modes import require
from fixture import ROLES, canonical, write_private

ROLE = "secrets.sekvyr.ru/trial-role"
APP = "secrets.sekvyr.ru/stage7-app"
NAME = "app.kubernetes.io/name"
INSTANCE = "app.kubernetes.io/instance"
PREFIX = "stage7-product-"


def _sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _namespaces(cluster):
    path = cluster.task / "private" / "fixture.json"
    require(not path.is_symlink(), "Unsafe trial namespace reservation")
    saved = json.loads(path.read_bytes())
    namespaces = saved.get("namespaces", {})
    require(saved.get("format") == "sekvyr-stage7-fixture-v1" and saved.get("production") is False
        and set(namespaces) == set(ROLES) and len(set(namespaces.values())) == 6
        and namespaces == cluster.fixture.get("namespaces")
        and set(namespaces.values()) == cluster.namespaces, "Trial namespace reservation changed")
    pins = cluster.namespace_pins()
    require(set(pins) == set(namespaces.values()), "All six namespace creation pins required")
    for namespace in namespaces.values():
        value = json.loads(cluster.kube("get", "namespace", namespace, "-o", "json").stdout)
        meta = value.get("metadata", {})
        require(value.get("kind") == "Namespace" and meta.get("name") == namespace
            and meta.get("uid") == pins[namespace] and not meta.get("deletionTimestamp"),
            "Product path namespace replaced or deleting")
    return namespaces, pins


def _endpoints(values, allowed_ports):
    require(isinstance(values, (tuple, list)) and 0 < len(values) <= 16,
        "Bounded explicit endpoint tuples required")
    result = []
    for item in values:
        require(isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[0], str)
            and type(item[1]) is int and item[1] in allowed_ports, "Exact endpoint IP and port required")
        try:
            address = ipaddress.ip_address(item[0])
        except ValueError:
            raise RuntimeError("Literal endpoint IP required") from None
        require(str(address) == item[0] and not (address.is_unspecified or address.is_multicast or address.is_loopback),
            "Non-wildcard canonical endpoint IP required")
        entry = (str(address), item[1])
        require(entry not in result, "Duplicate endpoint tuple refused")
        result.append(entry)
    return sorted(result)


def _peer(namespace, labels):
    # A single peer ANDs namespace and Pod selectors.
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
        "podSelector": {"matchLabels": copy.deepcopy(labels)}}


def _render_selectors(rendered, namespace, release, ha):
    require(isinstance(rendered, list) and 0 < len(rendered) <= 40, "Explicit reviewed Helm render required")
    deployments = [item for item in rendered if item.get("kind") == "Deployment"]
    roles = ("operator", "fencer") if ha else ("operator",)
    require(len(deployments) == len(roles), "Unexpected Helm Deployment set")
    result = {}
    for role in roles:
        expected = {NAME: "sekvyr-" + role, INSTANCE: release}
        matches = [item for item in deployments if item.get("spec", {}).get("selector") == {"matchLabels": expected}]
        require(len(matches) == 1, "Reviewed Helm component selector differs")
        value = matches[0]
        labels = dict(expected, **({ROLE: role} if ha else {}))
        require(value.get("apiVersion") == "apps/v1" and value.get("metadata", {}).get("namespace") == namespace
            and value["spec"]["template"]["metadata"].get("labels") == labels,
            "Reviewed Helm Pod labels differ")
        result[role] = labels
    return result


def _plain(cases, namespaces):
    p, lifecycle = cases.installation, cases.installation.lifecycle
    require(p.namespace == namespaces["isolation"] and p.release == "stage7-plain"
        and lifecycle is not None and lifecycle.cluster is cases.c.cluster
        and lifecycle.namespace == p.namespace and lifecycle.release == p.release and lifecycle.managed,
        "Captured Plain Helm lifecycle required")
    lifecycle._external_guard()
    lifecycle._retained_guard()
    manifests = []
    for saved in lifecycle.managed.values():
        if saved["manifest"].get("kind") == "Deployment":
            current = lifecycle._get(saved["manifest"])
            lifecycle._owned(current, saved["uid"])
            lifecycle._matches(current, saved["manifest"])
            manifests.append(saved["manifest"])
    return _render_selectors(manifests, p.namespace, p.release, False)["operator"]


def _policies(ns, plain, ha, api, admission):
    output = []
    def policy(role, name, labels, ingress=None, egress=None):
        spec = {"podSelector": {"matchLabels": labels}, "policyTypes": []}
        for direction, rules in (("Ingress", ingress), ("Egress", egress)):
            if rules is not None:
                spec["policyTypes"].append(direction)
                spec[direction.lower()] = rules
        output.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"namespace": ns[role], "name": PREFIX + name}, "spec": spec})
    def path(role, labels, port):
        return {"to": [_peer(ns[role], labels)], "ports": [{"protocol": "TCP", "port": port}]}
    def blocks(endpoints, direction):
        return [{direction: [{"ipBlock": {"cidr": address + ("/128" if ":" in address else "/32")}}],
            "ports": [{"protocol": "TCP", "port": port}]} for address, port in endpoints]
    panel, witness, gateway = ({ROLE: value} for value in ("panel", "witness", "journal-gateway"))
    agent = {ROLE: "agent", APP: "legacy-agent-app"}
    relay = {ROLE: "admission-relay"}
    policy("isolation", "plain", plain, egress=blocks(api, "to") + [path("panel", panel, 8443)])
    policy("isolation", "agent", agent, egress=[path("panel", panel, 8443)])
    policy("apps", "operator", ha["operator"], egress=blocks(api, "to") + [path("panel", panel, 8443),
        path("witness", witness, 8443), path("gateway", gateway, 8443), path("apps", ha["fencer"], 9443)])
    policy("apps", "fencer", ha["fencer"], ingress=blocks(admission, "from") + [{
        "from": [_peer(ns["apps"], ha["operator"]), _peer(ns["apps"], relay)],
        "ports": [{"protocol": "TCP", "port": 9443}]}],
        egress=blocks(api, "to") + [path("gateway", gateway, 8443)])
    policy("apps", "relay", relay, ingress=blocks(admission, "from"), egress=[path("apps", ha["fencer"], 9443)])
    policy("panel", "panel", panel, ingress=[{"from": [_peer(ns["isolation"], plain), _peer(ns["isolation"], agent),
        _peer(ns["apps"], ha["operator"]), _peer(ns["witness"], witness)], "ports": [{"protocol": "TCP", "port": 8443}]}],
        egress=[path("witness", witness, 8443)])
    policy("gateway", "journal", gateway, ingress=[{"from": [_peer(ns["apps"], ha["operator"]),
        _peer(ns["apps"], ha["fencer"])], "ports": [{"protocol": "TCP", "port": 8443}]}])
    return output


def _baseline(cluster, namespaces):
    output = []
    for namespace in sorted(namespaces.values()):
        values = json.loads(cluster.kube("get", "networkpolicies", "-n", namespace, "-o", "json").stdout)["items"]
        require(len({item["metadata"]["name"] for item in values}) == len(values), "Ambiguous trial policies")
        deny = [item for item in values if item["metadata"]["name"] == "default-deny"]
        require(len(deny) == 1 and set(deny[0]["spec"]).issubset({"podSelector", "policyTypes", "ingress", "egress"})
            and deny[0]["spec"].get("podSelector") == {}
            and deny[0]["spec"].get("policyTypes") == ["Ingress", "Egress"]
            and deny[0]["spec"].get("ingress", []) == [] and deny[0]["spec"].get("egress", []) == [],
            "Trial default deny missing or changed")
        for item in values:
            meta = item["metadata"]
            require(item.get("kind") == "NetworkPolicy" and meta.get("namespace") == namespace
                and meta.get("uid") and not meta.get("deletionTimestamp")
                and not meta["name"].startswith(PREFIX), "Product policy name already exists or baseline invalid")
            output.append({"namespace": namespace, "name": meta["name"], "uid": meta["uid"], "spec": item["spec"]})
    # This existing component policy supplies panel/witness ingress and witness
    # outbound staging fetches; journal-client supplies witness -> gateway.
    witness = [item for item in output if item["namespace"] == namespaces["witness"] and item["name"] == "witness-canonical"]
    from manifests import peer
    expected = {"podSelector": {"matchLabels": {ROLE: "witness"}}, "policyTypes": ["Ingress", "Egress"],
        "ingress": [{"from": [peer(namespaces["apps"], role) for role in ("operator", "fencer")]
            + [peer(namespaces["panel"], "panel")], "ports": [{"protocol": "TCP", "port": 8443}]}],
        "egress": [{"to": [peer(namespaces["panel"], "panel")], "ports": [{"protocol": "TCP", "port": 8443}]}]}
    require(len(witness) == 1 and witness[0]["spec"] == expected, "Existing witness canonical paths differ")
    return output


def install(cases, *, ha_rendered, reviewed_ha_sha256, api_endpoints, admission_sources):
    """Explicit coordinator call only; endpoint tuples are private live input.

    ha_rendered is the separately reviewed full Helm render for the future HA
    release. It is not installed or adopted here. A partial create is retained
    for explicit review, never retried through implicit policy adoption.
    """
    cluster = cases.c.cluster
    ns, pins = _namespaces(cluster)
    require(isinstance(reviewed_ha_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", reviewed_ha_sha256)
        and _sha(ha_rendered) == reviewed_ha_sha256, "HA render differs from explicit review hash")
    ha = _render_selectors(ha_rendered, ns["apps"], "stage6", True)
    plain = _plain(cases, ns)
    require(cases.agent_name == "legacy-agent-app", "Unreviewed legacy agent identity")
    api, admission = _endpoints(api_endpoints, {443, 6443}), _endpoints(admission_sources, {9443})
    baseline = _baseline(cluster, ns)
    policies = _policies(ns, plain, ha, api, admission)
    root = cluster.task / "private" / "stage7-network-paths"
    require(not root.exists() and not root.is_symlink(), "Network path installation already attempted")
    root.mkdir(mode=0o700)
    plan = {"format": "sekvyr-stage7-network-paths-v1", "namespaceUIDs": pins,
        "reviewedHARenderSHA256": reviewed_ha_sha256, "plainSelector": plain,
        "baseline": baseline, "manifests": policies, "production": False}
    write_private(root / "plan.json", canonical(plan))
    for index, value in enumerate(policies):
        require(_namespaces(cluster) == (ns, pins), "Namespace identity changed during policy installation")
        require(_plain(cases, ns) == plain, "Captured Plain selector changed during policy installation")
        # Preserve every preexisting rule and its exact UID/spec, not just deny.
        for old in baseline:
            current = json.loads(cluster.kube("get", "networkpolicy", old["name"], "-n", old["namespace"], "-o", "json").stdout)
            require(current["metadata"].get("uid") == old["uid"] and current.get("spec") == old["spec"]
                and not current["metadata"].get("deletionTimestamp"), "Existing trial policy changed")
        answer = cluster.create(copy.deepcopy(value))
        require(answer.get("kind") == "NetworkPolicy" and answer.get("spec") == value["spec"]
            and answer["metadata"].get("namespace") == value["metadata"]["namespace"]
            and answer["metadata"].get("name") == value["metadata"]["name"] and answer["metadata"].get("uid"),
            "Network policy CREATE response differs")
        write_private(root / (str(index) + "-created.json"), canonical({"uid": answer["metadata"]["uid"],
            "namespace": value["metadata"]["namespace"], "name": value["metadata"]["name"], "manifestSHA256": _sha(value)}))
    result = {"createdPolicies": len(policies), "namespaceCount": 6, "defaultDenyPreserved": True,
        "packetIsolationVerified": False, "production": False}
    write_private(root / "complete.json", canonical(result))
    return result
