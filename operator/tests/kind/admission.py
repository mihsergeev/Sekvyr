#!/usr/bin/env python3
"""Install CRDs and test API admission without building/running the controller."""
import argparse
import copy
import json
from pathlib import Path

import yaml

from run import create, deny, k, obj, record, RESULTS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chart", type=Path, required=True)
    args = parser.parse_args()
    # All kubectl operations use the fixed local kind node and its own admin.conf.
    for path in sorted((args.chart / "crds").glob("*.yaml")):
        result = k("apply", "--server-side", "-f", "-", value=path.read_text(), check=False)
        if result.returncode:
            raise RuntimeError("CRD admission failed: " + result.stderr)
    k("wait", "--for=condition=Established", "--timeout=30s",
      "crd/sekvyrstores.secrets.sekvyr.ru", "crd/sekvyrsecrets.secrets.sekvyr.ru")
    namespace = "stage2-admission"
    create(obj("Namespace", namespace, namespace=None))
    examples = args.chart.resolve().parents[1] / "design" / "examples"
    try:
        store = yaml.safe_load((examples / "01-store-e2e.yaml").read_text())
        store["metadata"]["namespace"] = namespace
        original = create(store)
        secret = yaml.safe_load((examples / "02-secret-e2e.yaml").read_text())
        secret["metadata"]["namespace"] = namespace
        secret["spec"]["storeRef"]["uid"] = original["metadata"]["uid"]
        create(secret)
        record("real API accepts E2E2 Store and exact-UID Secret")
        bad = copy.deepcopy(store); bad["spec"]["endpoint"]["url"] = "http://sekvyr.example.com"
        deny("HTTP origin", bad)
        bad = copy.deepcopy(secret); bad["spec"]["endpoint"] = {"url": "https://other.example.com"}
        deny("app URL override / unknown spec", bad)
        bad = copy.deepcopy(secret); bad["spec"]["storeRef"]["namespace"] = "foreign"
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
        immutable = copy.deepcopy(original)
        immutable["spec"]["bindings"][0]["target"]["name"] = "another-target"
        result = k("replace", "--dry-run=server", "-f", "-", value=json.dumps(immutable), check=False)
        assert result.returncode, "immutable target update accepted"
        record("CEL blocks target rebinding")
        print("ADMISSION_PASS_TOTAL=" + str(len(RESULTS)))
    finally:
        k("delete", "namespace", namespace, "--wait=false")


if __name__ == "__main__":
    main()
