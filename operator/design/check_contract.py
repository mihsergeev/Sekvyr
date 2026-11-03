"""Static stage-1 schema checks only. Does not connect to a cluster or panel."""
import copy
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent
schema = json.loads((ROOT / "resource.schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
examples = {
    p.name: yaml.safe_load(p.read_text(encoding="utf-8"))
    for p in sorted((ROOT / "examples").glob("*.yaml"))
}
for name, resource in examples.items():
    assert not list(validator.iter_errors(resource)), "invalid example: " + name

secret = examples["02-secret-e2e.yaml"]
store = examples["01-store-e2e.yaml"]
cases = {}


def reject(name, original, mutate):
    resource = copy.deepcopy(original)
    mutate(resource)
    assert list(validator.iter_errors(resource)), "unsafe input accepted: " + name
    cases[name] = "rejected"


reject("HTTP endpoint", store,
       lambda x: x["spec"]["endpoint"].update(url="http://example.com"))
reject("Credentials in URL", store,
       lambda x: x["spec"]["endpoint"].update(url="https://user:example-password@example.com"))
reject("App endpoint override", secret,
       lambda x: x["spec"].update(url="https://example.com"))
reject("Cross-namespace storeRef", secret,
       lambda x: x["spec"]["storeRef"].update(namespace="other"))
reject("App target override", secret,
       lambda x: x["spec"].update(target={"name": "operator-state"}))
reject("ServiceAccount override", secret,
       lambda x: x["spec"].update(serviceAccountRef="other"))
reject("Too frequent polling", secret,
       lambda x: x["spec"].update(refreshIntervalSeconds=29))
reject("E2E without trust", store,
       lambda x: x["spec"]["bindings"][0]["encryption"].pop("trustKey"))
reject("Unsupported protocol", store,
       lambda x: x["spec"]["bindings"][0]["encryption"].update(protocol="e2e1"))
reject("Plain with E2E fields", store,
       lambda x: x["spec"]["bindings"][0]["encryption"].update(mode="Plain"))
reject("Enabled rollout with empty targets", secret,
       lambda x: x["spec"].update(rollout={"enabled": True, "deployments": []}))
reject("Disabled rollout with targets", secret,
       lambda x: x["spec"].update(rollout={"enabled": False, "deployments": ["billing-api"]}))
reject("Implicitly disabled rollout with targets", secret,
       lambda x: x["spec"].update(rollout={"deployments": ["billing-api"]}))
reject("All selection with explicit mapping list", store,
       lambda x: x["spec"]["bindings"][0]["selection"].update(mode="All"))
reject("Unknown spec field", secret,
       lambda x: x["spec"].update(unsafe=True))
reject("Namespace with dots", secret,
       lambda x: x["metadata"].update(namespace="apps.other"))
reject("Namespace too long", secret,
       lambda x: x["metadata"].update(namespace="a" * 64))
reject("Resource name with empty DNS label", secret,
       lambda x: x["metadata"].update(name="billing..runtime"))
reject("E2E without witness mode", store,
       lambda x: x["spec"]["bindings"][0]["encryption"].pop("freshness"))
reject("Offline downgrade", store,
       lambda x: x["spec"]["bindings"][0]["encryption"]["freshness"].update(mode="Offline"))
reject("E2E without view UUID", store,
       lambda x: x["spec"]["bindings"][0]["source"].pop("viewId"))
reject("Plain with view UUID", examples["04-store-plain.yaml"],
       lambda x: x["spec"]["bindings"][0]["source"].update(viewId="66666666-6666-4666-8666-666666666666"))

print(json.dumps({
    "date": "2026-11-01",
    "schemaValid": True,
    "positiveExamples": len(examples),
    "negativeExamplesRejected": len(cases),
    "negativeCases": list(cases),
    "scope": "Static design request schema only; this check does not exercise controller runtime authorization",
}, indent=2))
