"""Translate the reviewed request schema into structural Kubernetes CRDs.

Print an apply_patch patch; --check checks committed/generated files instead.
Unknown fields are pruned by Kubernetes, or rejected by fieldValidation=Strict.
No additionalProperties:false or preserve-unknown escape hatch is emitted.
"""

import argparse
import copy
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts" / "sekvyr-operator"
UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


def structural(node):
    node = copy.deepcopy(node)
    node.pop("additionalProperties", None)
    node.pop("allOf", None)
    node.pop("uniqueItems", None)
    if "const" in node:
        value = node.pop("const")
        node["type"] = "string"
        node["enum"] = [value]
    if "enum" in node and "type" not in node:
        if not all(isinstance(value, str) for value in node["enum"]):
            raise ValueError("Enum requires an explicit structural type")
        node["type"] = "string"
    if node.get("type") == "string" and "enum" in node:
        node.setdefault("maxLength", max(map(len, node["enum"])))
    if node.get("pattern") == UUID_PATTERN:
        node.setdefault("maxLength", 36)
    if node.get("pattern") == "^[a-z0-9][a-z0-9.-]{0,62}$":
        node.setdefault("maxLength", 63)
    if "oneOf" in node:
        branches = [structural(branch) for branch in node.pop("oneOf")]
        node["type"] = "object"
        node["properties"] = {}
        common = set(branches[0].get("required", []))
        for branch in branches:
            common.intersection_update(branch.get("required", []))
            for name, field in branch["properties"].items():
                if name in node["properties"] and "enum" in field:
                    node["properties"][name]["enum"] += field["enum"]
                    node["properties"][name]["maxLength"] = max(map(len, node["properties"][name]["enum"]))
                else:
                    node["properties"][name] = field
        node["required"] = sorted(common)
    if "properties" in node:
        node["properties"] = {name: structural(value) for name, value in node["properties"].items()}
    if "items" in node:
        node["items"] = structural(node["items"])
    if node.get("required") == []:
        node.pop("required")
    if node.get("type") == "array" and node["items"].get("type") == "string":
        node["x-kubernetes-list-type"] = "set"
    return node


def rules(node, *entries):
    node.setdefault("x-kubernetes-validations", []).extend(
        {"rule": rule, "message": message} for rule, message in entries
    )


def condition_schema():
    return {
        "type": "array", "maxItems": 5,
        "x-kubernetes-list-type": "map", "x-kubernetes-list-map-keys": ["type"],
        "items": {
            "type": "object",
            "required": ["type", "status", "reason", "message", "lastTransitionTime"],
            "properties": {
                "type": {"type": "string", "enum": ["Ready", "DataCurrent", "RolloutReady", "BootstrapReady", "WitnessReady"]},
                "status": {"type": "string", "enum": ["True", "False", "Unknown"]},
                "reason": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z][A-Za-z0-9]*$"},
                "message": {"type": "string", "maxLength": 1024},
                "observedGeneration": {"type": "integer", "format": "int64", "minimum": 0},
                "lastTransitionTime": {"type": "string", "format": "date-time"},
            },
        },
    }


def status_schema():
    return {"type": "object", "properties": {
        "observedGeneration": {"type": "integer", "format": "int64", "minimum": 0},
        "lastSuccessfulSyncTime": {"type": "string", "format": "date-time"},
        "lastAttemptTime": {"type": "string", "format": "date-time"},
        "lastAppliedRevision": {"type": "string", "maxLength": 128},
        "lastVerifiedCheckpoint": {"type": "object", "required": ["sequence", "envelopeHash"], "properties": {
            "sequence": {"type": "string", "maxLength": 20, "pattern": "^[1-9][0-9]{0,19}$"},
            "envelopeHash": {"type": "string", "maxLength": 64, "pattern": "^[0-9a-f]{64}$"},
        }},
        "conditions": condition_schema(),
    }}


def canonical_path(node):
    node["pattern"] = r"^(/|/[^/\\\x00-\x1f\x7f]+(/[^/\\\x00-\x1f\x7f]+)*)$"
    # Dot segments, NFC and all Unicode categories are checked by the runtime.
    # A CEL split/all here is multiplied by 64 bindings * 1024 selected keys.


def build(kind, design):
    schema = structural(design["$defs"][kind])
    schema["properties"]["metadata"] = {"type": "object"}
    schema["properties"]["status"] = status_schema()
    if kind == "SekvyrSecret":
        schema["properties"]["status"]["properties"].update({
            "observedStoreUID": {"type": "string"},
            "observedStoreGeneration": {"type": "integer", "format": "int64", "minimum": 0},
        })
    schema["required"] = ["spec"]
    spec = schema["properties"]["spec"]
    if kind == "SekvyrStore":
        rules(spec["properties"]["endpoint"], ("self == oldSelf", "The endpoint and CA reference are immutable"))
        bindings = spec["properties"]["bindings"]
        bindings["x-kubernetes-list-type"] = "map"
        bindings["x-kubernetes-list-map-keys"] = ["id"]
        rules(bindings,
              ("self.all(b, self.filter(c, c.name == b.name).size() == 1)", "Binding names must be unique"),
              ("self.all(b, self.filter(c, c.resourceName == b.resourceName).size() == 1)", "Binding resource names must be unique"),
              ("self.all(b, self.filter(c, c.target.name == b.target.name).size() == 1)", "Binding target names must be unique"))
        binding = bindings["items"]
        fields = binding["properties"]
        canonical_path(fields["source"]["properties"]["pathPrefix"])
        canonical_path(fields["selection"]["properties"]["keys"]["items"]["properties"]["path"])
        fields["selection"]["properties"]["keys"]["x-kubernetes-list-type"] = "atomic"
        rules(fields["selection"], (
            "self.mode == 'All' ? !has(self.keys) : has(self.keys) && self.keys.size() > 0",
            "All forbids keys; Keys requires a nonempty mapping list"))
        rules(fields["encryption"], (
            "self.mode == 'Plain' ? !has(self.protocol) && !has(self.trustKey) && !has(self.freshness) : has(self.protocol) && has(self.trustKey) && has(self.freshness)",
            "Plain forbids E2E fields; E2E requires e2e2 trust and freshness"))
        fields["target"]["properties"]["type"]["default"] = "Opaque"
        rules(binding,
              ("self.encryption.mode == 'E2E' ? has(self.source.viewId) : !has(self.source.viewId)", "Only E2E bindings require a stable view UUID"),
              ("self.name == oldSelf.name && self.resourceName == oldSelf.resourceName", "Binding name and CR resource name are immutable"),
              ("self.encryption == oldSelf.encryption", "Encryption mode and trust reference are immutable"),
              ("has(self.source.viewId) == has(oldSelf.source.viewId) && (!has(self.source.viewId) || self.source.viewId == oldSelf.source.viewId)", "The stable view UUID is immutable"),
              ("self.encryption.mode != 'Plain' || self.source == oldSelf.source", "Plain source routing is immutable"),
              ("self.target.name == oldSelf.target.name && self.target.type == oldSelf.target.type && self.target.deletionPolicy == oldSelf.target.deletionPolicy", "Target name, type and deletion policy are immutable"))
    else:
        rules(spec["properties"]["storeRef"], ("self == oldSelf", "Store name and UID are immutable"))
        rules(spec["properties"]["binding"], ("self == oldSelf", "The authorized binding is immutable"))
        rules(spec["properties"]["rollout"], (
            "has(self.enabled) && self.enabled ? has(self.deployments) && self.deployments.size() > 0 : !has(self.deployments) || self.deployments.size() == 0",
            "Enabled rollout requires targets; disabled rollout forbids targets"))
    plural = "sekvyrstores" if kind == "SekvyrStore" else "sekvyrsecrets"
    return {
        "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
        "metadata": {"name": plural + ".secrets.sekvyr.ru"},
        "spec": {
            "group": "secrets.sekvyr.ru", "scope": "Namespaced",
            "names": {"plural": plural, "singular": plural[:-1], "kind": kind},
            "versions": [{"name": "v1alpha1", "served": True, "storage": True,
                          "subresources": {"status": {}}, "schema": {"openAPIV3Schema": schema}}],
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    design = json.loads((ROOT / "design" / "resource.schema.json").read_text(encoding="utf-8"))
    patch = ["*** Begin Patch"]
    for kind in ("SekvyrStore", "SekvyrSecret"):
        crd = build(kind, design)
        content = "# Generated by operator/config/generate_crds.py from the reviewed design.\n"
        content += yaml.safe_dump(crd, sort_keys=False, width=120)
        path = CHART / "crds" / (crd["metadata"]["name"] + ".yaml")
        if args.check:
            assert path.read_text(encoding="utf-8") == content, "CRD drift: " + str(path)
        else:
            if path.exists():
                patch.extend(["*** Update File: " + path.as_posix(), "@@"])
                patch.extend("-" + line for line in path.read_text(encoding="utf-8").splitlines())
            else:
                patch.append("*** Add File: " + path.as_posix())
            patch.extend("+" + line for line in content.splitlines())
    if not args.check:
        patch.append("*** End Patch")
        print("\n".join(patch))


if __name__ == "__main__":
    main()
