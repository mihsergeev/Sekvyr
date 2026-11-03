"""Mechanical schema/render guards. Real CEL/RBAC acceptance needs a Kubernetes API."""

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "sekvyr-operator"
EXAMPLE = Path(__file__).with_name("values.public.example.yaml")
HELM = os.environ.get("HELM_BIN") or shutil.which("helm")


def walk(node):
    if isinstance(node, dict):
        yield node
        for child in node.values():
            yield from walk(child)
    elif isinstance(node, list):
        for child in node:
            yield from walk(child)


def strict_client_schema(node):
    """Model fieldValidation=Strict, not normal API unknown-field pruning."""
    node = copy.deepcopy(node)
    for item in walk(node):
        if item.get("type") == "object" and "properties" in item:
            item["additionalProperties"] = False
    return node


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crds = {
            resource["spec"]["names"]["kind"]: resource
            for path in sorted((CHART / "crds").glob("*.yaml"))
            for resource in [yaml.safe_load(path.read_text(encoding="utf-8"))]
        }

    def test_generated_crds_match_design(self):
        spec = importlib.util.spec_from_file_location("generate_crds", ROOT / "config" / "generate_crds.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        design = json.loads((ROOT / "design" / "resource.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(self.crds), {"SekvyrStore", "SekvyrSecret"})
        for kind, resource in self.crds.items():
            self.assertEqual(resource, generator.build(kind, design))

    def test_strict_structural_namespaced_status(self):
        for kind, resource in self.crds.items():
            self.assertEqual(resource["spec"]["scope"], "Namespaced")
            version = resource["spec"]["versions"][0]
            self.assertEqual(version["name"], "v1alpha1")
            self.assertEqual(version["subresources"], {"status": {}})
            schema = version["schema"]["openAPIV3Schema"]
            Draft7Validator.check_schema(schema)
            for node in walk(schema):
                self.assertNotIn("x-kubernetes-preserve-unknown-fields", node)
                self.assertNotEqual(node.get("additionalProperties"), False)
                self.assertFalse({"const", "if", "then", "else", "$ref"}.intersection(node))
                if "properties" in node:
                    self.assertEqual(node.get("type"), "object")
                if "items" in node:
                    self.assertEqual(node.get("type"), "array")
                if "enum" in node:
                    self.assertEqual(node.get("type"), "string")
                if node.get("type") == "string" and "pattern" in node:
                    self.assertIn("maxLength", node)
            status = schema["properties"]["status"]
            expected_status = {
                "observedGeneration", "lastSuccessfulSyncTime", "lastAttemptTime",
                "lastAppliedRevision", "lastVerifiedCheckpoint", "conditions",
            }
            if kind == "SekvyrSecret":
                expected_status.update({"observedStoreUID", "observedStoreGeneration"})
                self.assertEqual(status["properties"]["observedStoreUID"], {"type": "string"})
                self.assertEqual(status["properties"]["observedStoreGeneration"], {
                    "type": "integer", "format": "int64", "minimum": 0,
                })
            self.assertEqual(set(status["properties"]), expected_status)
            self.assertEqual(set(status["properties"]["lastVerifiedCheckpoint"]["properties"]), {"sequence", "envelopeHash"})

    def test_design_examples_keep_same_shape(self):
        for path in sorted((ROOT / "design" / "examples").glob("*.yaml")):
            example = yaml.safe_load(path.read_text(encoding="utf-8"))
            schema = self.crds[example["kind"]]["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
            strict = strict_client_schema(schema)
            self.assertEqual(list(Draft7Validator(strict).iter_errors(example)), [], path.name)
            broken = copy.deepcopy(example)
            broken["spec"]["namespace"] = "other"
            self.assertTrue(list(Draft7Validator(strict).iter_errors(broken)))

    def test_immutability_and_cross_field_rules(self):
        store = self.crds["SekvyrStore"]["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
        bindings = store["properties"]["bindings"]
        self.assertEqual(bindings["maxItems"], 64)
        self.assertEqual(bindings["x-kubernetes-list-type"], "map")
        self.assertEqual(bindings["x-kubernetes-list-map-keys"], ["id"])
        serialized = json.dumps(self.crds)
        for rule in ["oldSelf", "self.target.deletionPolicy", "self.source.viewId", "self.encryption", "self.resourceName", "self.filter"]:
            self.assertIn(rule, serialized)
        fields = bindings["items"]["properties"]
        self.assertEqual(fields["encryption"]["properties"]["protocol"]["enum"], ["e2e2"])
        self.assertEqual(fields["target"]["properties"]["deletionPolicy"]["default"], "Retain")
        self.assertEqual(fields["target"]["properties"]["allowEmpty"]["default"], False)

    def test_docker_compiler_pin_and_minimal_runtime(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        baseline = (ROOT.parent / "agent" / "Dockerfile").read_text(encoding="utf-8")
        compiler = lambda content: next(line for line in content.splitlines() if line.startswith("FROM --platform="))
        self.assertEqual(compiler(dockerfile), compiler(baseline))
        self.assertIn("FROM scratch", dockerfile)
        self.assertIn("CGO_ENABLED=0", dockerfile)
        self.assertIn("GOWORK=off", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)


@unittest.skipUnless(HELM, "Set HELM_BIN or install Helm to run render/RBAC guards")
class HelmTests(unittest.TestCase):
    def helm(self, *extra, success=True):
        result = subprocess.run(
            [HELM, "template", "check", str(CHART), "--namespace", "apps", "--kube-version", "1.37.0", "--include-crds", "-f", str(EXAMPLE), *extra],
            capture_output=True, text=True, encoding="utf-8", check=False,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_render_security_and_wiring(self):
        resources = list(yaml.safe_load_all(self.helm().stdout))
        kinds = [resource["kind"] for resource in resources]
        self.assertNotIn("Secret", kinds)
        self.assertNotIn("ClusterRole", kinds)
        self.assertNotIn("ClusterRoleBinding", kinds)
        self.assertNotIn("Namespace", kinds)
        for resource in resources:
            if resource["kind"] != "CustomResourceDefinition":
                self.assertEqual(resource["metadata"]["namespace"], "apps")
        role = next(resource for resource in resources if resource["kind"] == "Role")
        for rule in role["rules"]:
            self.assertNotIn("*", rule["resources"] + rule["verbs"] + rule["apiGroups"])
            if rule["resources"] == ["secrets"]:
                self.assertEqual(rule["verbs"], ["get"])
                self.assertEqual(set(rule["resourceNames"]), {"operator-identity", "operator-trust", "operator-state"})
            elif rule["resources"] == ["leases"]:
                self.assertEqual(rule["resourceNames"], ["sekvyr-operator-leader"])
                self.assertEqual(set(rule["verbs"]), {"get", "update", "patch"})
            else:
                self.assertEqual(rule["apiGroups"], ["secrets.sekvyr.ru"])
        deployment = next(resource for resource in resources if resource["kind"] == "Deployment")
        pod = deployment["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["serviceAccountName"], "sekvyr-operator")
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertIn("@sha256:", container["image"])
        self.assertIn("--leader-elect=true", container["args"])
        self.assertIn("--namespace=apps", container["args"])
        self.assertIn("--metrics-bind-address=0", container["args"])
        self.assertIn("--enable-sync=false", container["args"])
        self.assertIn("--enable-rollout=false", container["args"])
        self.assertIn("--panel-token-file=/var/run/secrets/sekvyr-panel/token", container["args"])
        self.assertTrue(all(mount["readOnly"] for mount in container["volumeMounts"]))
        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        self.assertNotIn("state", volumes)
        panel_token = volumes["panel-api"]["projected"]["sources"][0]["serviceAccountToken"]
        self.assertEqual(panel_token, {"audience": "sekvyr", "expirationSeconds": 3600, "path": "token"})
        kube_token = volumes["kube-api"]["projected"]["sources"][0]["serviceAccountToken"]
        self.assertNotIn("audience", kube_token)
        config_map = next(resource for resource in resources if resource["kind"] == "ConfigMap")
        self.assertTrue(config_map["immutable"])
        config = json.loads(config_map["data"]["installation.json"])
        self.assertEqual(config["namespace"], "apps")
        self.assertFalse(config["rolloutEnabled"])
        self.assertEqual(config["allowedDeployments"], [])
        self.assertEqual(len(config["protectedSecretNames"]), 3)
        self.assertIn("sh.helm.release.v1.", config["protectedPrefixes"])

    def test_creation_defaults_and_optional_runtime_pins_preserve_base_config(self):
        resources = list(yaml.safe_load_all(self.helm().stdout))
        self.assertEqual(sum(value["kind"] == "ServiceAccount" for value in resources), 1)
        self.assertEqual(sum(value["kind"] == "Lease" for value in resources), 1)
        config = json.loads(next(value for value in resources if value["kind"] == "ConfigMap")["data"]["installation.json"])
        for field in ("serviceAccountUID", "leaderElectionLeaseUID", "leaderElectionLeaseName"):
            self.assertNotIn(field, config)

    def test_external_service_account_and_lease_are_not_claimed_by_helm(self):
        service_uid, lease_uid = "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777"
        override = "serviceAccount.create=false,serviceAccount.uid=" + service_uid + ",leaderElection.create=false,leaderElection.uid=" + lease_uid
        resources = list(yaml.safe_load_all(self.helm("--set", override).stdout))
        self.assertFalse(any(value["kind"] in ("ServiceAccount", "Lease") for value in resources))
        config = json.loads(next(value for value in resources if value["kind"] == "ConfigMap")["data"]["installation.json"])
        self.assertEqual(config["serviceAccountUID"], service_uid)
        self.assertEqual(config["leaderElectionLeaseUID"], lease_uid)
        self.assertEqual(config["leaderElectionLeaseName"], "sekvyr-operator-leader")
        role = next(value for value in resources if value["kind"] == "Role")
        self.assertEqual([rule for rule in role["rules"] if rule["resources"] == ["serviceaccounts"]], [{
            "apiGroups": [""], "resources": ["serviceaccounts"], "resourceNames": ["sekvyr-operator"], "verbs": ["get"]}])

    def test_external_resources_require_explicit_uid_and_ha_duplicate_pins_must_match(self):
        for override in ("serviceAccount.create=false", "leaderElection.create=false", "serviceAccount.uid=not-a-uid",
                         "leaderElection.uid=not-a-uid", "configuration.retain=string", "serviceAccount.lookup=true"):
            with self.subTest(override=override):
                self.helm("--set", override, success=False)
        for override in ("serviceAccount.uid=44444444-4444-4444-8444-444444444444",
                         "leaderElection.uid=44444444-4444-4444-8444-444444444444"):
            with self.subTest(override=override):
                self.ha("--set", override, success=False)

    def test_ha_external_bootstrap_refs_use_existing_uid_pins_without_lookup(self):
        resources = list(yaml.safe_load_all(self.ha("--set", "serviceAccount.create=false,leaderElection.create=false,ha.fencer.serviceAccount.create=false").stdout))
        self.assertFalse(any(value["kind"] in ("ServiceAccount", "Lease") for value in resources))
        config = json.loads(next(value for value in resources if value["kind"] == "ConfigMap" and "installation.json" in value["data"])["data"]["installation.json"])
        self.assertEqual(config["serviceAccountUID"], "66666666-6666-4666-8666-666666666666")
        self.assertEqual(config["leaderElectionLeaseUID"], "77777777-7777-4777-8777-777777777777")
        self.assertEqual(config["leaderElectionLeaseName"], "sekvyr-operator-leader")
        for path in (CHART / "templates").glob("*"):
            self.assertNotIn("lookup ", path.read_text(encoding="utf-8"))

    def test_immutable_config_revisions_are_kept_for_reviewed_lifecycle(self):
        resources = list(yaml.safe_load_all(self.ha().stdout))
        for value in resources:
            if value["kind"] == "ConfigMap":
                self.assertTrue(value["immutable"])
                self.assertEqual(value["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")
        without = list(yaml.safe_load_all(self.ha("--set", "configuration.retain=false").stdout))
        self.assertTrue(all("helm.sh/resource-policy" not in value["metadata"].get("annotations", {})
            for value in without if value["kind"] == "ConfigMap"))
        old = next(value for value in resources if value["kind"] == "ConfigMap" and "installation.json" in value["data"])
        changed = list(yaml.safe_load_all(self.ha("--set", "installation.protectedSecretNames[0]=reserved-fixture").stdout))
        new = next(value for value in changed if value["kind"] == "ConfigMap" and "installation.json" in value["data"])
        self.assertNotEqual(old["metadata"]["name"], new["metadata"]["name"])

    def test_chart_renders_both_target_minors_without_claiming_runtime_compatibility(self):
        for version in ("1.34.1", "1.37.0"):
            with self.subTest(version=version):
                resources = list(yaml.safe_load_all(self.ha("--kube-version", version).stdout))
                self.assertTrue(any(value["kind"] == "ValidatingWebhookConfiguration" for value in resources))
        self.helm("--kube-version", "1.33.9", success=False)

    def test_admin_projected_token_ttl_is_bounded_with_fixed_audiences(self):
        resources = list(yaml.safe_load_all(self.ha("--set", "auth.tokenExpirationSeconds=600").stdout))
        operator = next(value for value in resources if value["kind"] == "Deployment" and value["metadata"]["name"] == "check-operator")
        projections = {value["name"]: value["projected"]["sources"][0]["serviceAccountToken"]
            for value in operator["spec"]["template"]["spec"]["volumes"] if "projected" in value}
        self.assertEqual(projections["panel-api"], {"path": "token", "audience": "sekvyr", "expirationSeconds": 600})
        self.assertEqual(projections["fencer-api"], {"path": "token", "audience": "sekvyr-fence", "expirationSeconds": 600})
        self.assertEqual(projections["kube-api"]["expirationSeconds"], 3600)
        for ttl in (599, 3601, "invalid"):
            self.helm("--set", "auth.tokenExpirationSeconds=" + str(ttl), success=False)

    def test_missing_digest_unknown_fields_and_unsafe_overrides_rejected(self):
        for override in [
            "image.digest=", "image.tag=latest", "replicas=0", "rollout.enabled=true",
            "installation.namespace=other", "installation.namespace=",
            "installation.identityKeySecret.uid=", "installation.identityKeySecret.namespace=other",
            "installation.trustBundleSecret.name=operator-identity",
            "installation.trustBundleSecret.uid=11111111-1111-4111-8111-111111111111",
            "installation.nodePrivateKey=example-password-not-a-real-key",
            "sync.enabled=true",
            "sync.enabled=true,installation.allowedTargetSecrets[0]=billing-env,rollout.enabled=true",
            "rollout.enabled=true,rollout.allowedDeployments[0]=billing",
            "rollout.allowedDeployments[0]=*",
            "installation.rolloutEnabled=true",
            "installation.allowedDeployments[0]=billing",
            "installation.allowedTargetSecrets[0]=operator-state",
            "installation.allowedTargetSecrets[0]=sh.helm.release.v1.example",
            "installation.witnessCAConfigMapRef.name=unapproved-ca,installation.witnessCAConfigMapRef.key=ca.crt",
        ]:
            with self.subTest(override=override):
                self.helm("--set", override, success=False)

    def test_opt_in_sync_has_only_exact_state_and_target_writes(self):
        result = self.helm("--set", "sync.enabled=true,installation.allowedTargetSecrets[0]=billing-env")
        resources = list(yaml.safe_load_all(result.stdout))
        role = next(resource for resource in resources if resource["kind"] == "Role")
        secret_rules = [rule for rule in role["rules"] if rule["resources"] == ["secrets"]]
        self.assertEqual(len(secret_rules), 4)
        self.assertTrue(any(rule["verbs"] == ["create"] and "resourceNames" not in rule for rule in secret_rules))
        for rule in secret_rules:
            self.assertNotIn("list", rule["verbs"])
            self.assertNotIn("watch", rule["verbs"])
            self.assertNotIn("patch", rule["verbs"])
            self.assertNotIn("delete", rule["verbs"])
            if "update" in rule["verbs"]:
                self.assertIn(rule["resourceNames"], [["operator-state"], ["billing-env"]])
        self.assertFalse(any("deployments" in rule["resources"] or "apps" in rule["apiGroups"] for rule in role["rules"]))
        deployment = next(resource for resource in resources if resource["kind"] == "Deployment")
        self.assertIn("--enable-sync=true", deployment["spec"]["template"]["spec"]["containers"][0]["args"])

    def test_rollout_opt_in_grants_only_exact_deployment_get_patch(self):
        override = "sync.enabled=true,installation.allowedTargetSecrets[0]=billing-env,rollout.enabled=true,rollout.allowedDeployments[0]=billing,rollout.allowedDeployments[1]=worker"
        resources = list(yaml.safe_load_all(self.helm("--set", override).stdout))
        role = next(resource for resource in resources if resource["kind"] == "Role")
        deployment_rules = [rule for rule in role["rules"] if rule["apiGroups"] == ["apps"]]
        self.assertEqual(deployment_rules, [{"apiGroups": ["apps"], "resources": ["deployments"],
                                           "resourceNames": ["billing", "worker"], "verbs": ["get", "patch"]}])
        deployment = next(resource for resource in resources if resource["kind"] == "Deployment")
        self.assertIn("--enable-rollout=true", deployment["spec"]["template"]["spec"]["containers"][0]["args"])
        config_map = next(resource for resource in resources if resource["kind"] == "ConfigMap")
        config = json.loads(config_map["data"]["installation.json"])
        self.assertTrue(config["rolloutEnabled"])
        self.assertEqual(config["allowedDeployments"], ["billing", "worker"])

    def test_rollout_disabled_retains_no_deployment_rbac_with_admin_allowlist(self):
        resources = list(yaml.safe_load_all(self.helm("--set", "rollout.allowedDeployments[0]=billing").stdout))
        role = next(resource for resource in resources if resource["kind"] == "Role")
        self.assertFalse(any(rule["apiGroups"] == ["apps"] for rule in role["rules"]))

    def test_witness_ca_must_reference_a_pinned_config_map(self):
        override = ",".join([
            "installation.caConfigMaps[0].name=witness-ca",
            "installation.caConfigMaps[0].uid=44444444-4444-4444-8444-444444444444",
            "installation.caConfigMaps[0].key=ca.crt",
            "installation.caConfigMaps[0].derSetSHA256=" + "1" * 64,
            "installation.witnessCAConfigMapRef.name=witness-ca",
            "installation.witnessCAConfigMapRef.key=ca.crt",
        ])
        resources = list(yaml.safe_load_all(self.helm("--set-string", override).stdout))
        role = next(resource for resource in resources if resource["kind"] == "Role")
        ca_rules = [rule for rule in role["rules"] if rule["resources"] == ["configmaps"]]
        self.assertEqual(ca_rules, [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["witness-ca"], "verbs": ["get"]}])
        config_map = next(resource for resource in resources if resource["kind"] == "ConfigMap")
        self.assertEqual(json.loads(config_map["data"]["installation.json"])["witnessCAConfigMapRef"], {"name": "witness-ca", "key": "ca.crt"})

    def ha(self, *extra, success=True):
        return self.helm("-f", str(EXAMPLE.with_name("values.ha.public.example.yaml")), *extra, success=success)

    def test_ha_trial_scope_and_no_operator_secret_create_or_privilege_escalation(self):
        resources = list(yaml.safe_load_all(self.ha().stdout))
        roles = {resource["metadata"]["name"]: resource for resource in resources if resource["kind"] == "Role"}
        operator = roles["check-operator"]
        self.assertFalse(any("create" in rule["verbs"] for rule in operator["rules"]))
        readable = {name for rule in operator["rules"] if rule["resources"] == ["secrets"] for name in rule.get("resourceNames", [])}
        self.assertNotIn("fencer-signing", readable)
        self.assertNotIn("fencer-gateway", readable)
        self.assertNotIn("fencer-tls", readable)
        self.assertIn("operator-gateway", readable)
        deployments = [rule for rule in operator["rules"] if rule["resources"] == ["deployments"]]
        self.assertEqual(deployments[0]["resourceNames"], ["billing"])
        cluster = next(resource for resource in resources if resource["kind"] == "ClusterRole")
        self.assertEqual(cluster["rules"], [
            {"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]},
            {"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["apps"], "verbs": ["get"]},
        ])
        binding = next(resource for resource in resources if resource["kind"] == "ClusterRoleBinding")
        self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount", "name": "sekvyr-fencer", "namespace": "apps"}])
        for rule in roles["check-fencer"]["rules"]:
            self.assertFalse(set(rule["verbs"]) & {"list", "watch", "update", "delete"})
            if "patch" in rule["verbs"]:
                self.assertIn(rule["resources"], [["secrets"], ["deployments"]])
                self.assertIn("resourceNames", rule)
        self.assertNotIn("Secret", [resource["kind"] for resource in resources])

    def test_ha_config_mounts_and_exact_fail_closed_webhook(self):
        resources = list(yaml.safe_load_all(self.ha().stdout))
        fencer = next(resource for resource in resources if resource["kind"] == "Deployment" and resource["metadata"]["name"] == "check-fencer")
        pod = fencer["spec"]["template"]["spec"]
        self.assertEqual(fencer["spec"]["template"]["metadata"]["labels"]["secrets.sekvyr.ru/trial-role"], "fencer")
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["containers"][0]["command"], ["/sekvyr-fencer"])
        self.assertTrue(all(value["readOnly"] for value in pod["containers"][0]["volumeMounts"]))
        configmap = next(resource for resource in resources if resource["kind"] == "ConfigMap" and "config.json" in resource["data"])
        server = json.loads(configmap["data"]["config.json"])
        self.assertTrue(server["trial"])
        self.assertEqual(len(server["managed_objects"]), 3)
        self.assertEqual(len(server["material_pins"]), 3)
        self.assertEqual(server["namespace"], "apps")
        self.assertEqual(server["fencer_service_account"], "sekvyr-fencer")
        client_config = json.loads(configmap["data"]["client.json"])
        self.assertEqual(client_config["origin"], "https://gateway.example.com")
        self.assertNotIn("s3", json.dumps(client_config).lower())
        webhook = next(resource for resource in resources if resource["kind"] == "ValidatingWebhookConfiguration")["webhooks"][0]
        self.assertEqual(webhook["failurePolicy"], "Fail")
        self.assertEqual(webhook["sideEffects"], "None")
        self.assertEqual(webhook["matchPolicy"], "Exact")
        self.assertNotIn("objectSelector", webhook)
        expression = webhook["matchConditions"][0]["expression"]
        self.assertIn('request.namespace == "apps"', expression)
        self.assertIn('"operator-state"', expression)
        self.assertIn('"billing-env"', expression)
        self.assertNotIn("fencer-signing", expression)
        ordinary = next(resource for resource in resources if resource["kind"] == "Deployment" and resource["metadata"]["name"] == "check-operator")
        projected = next(value for value in ordinary["spec"]["template"]["spec"]["volumes"] if value["name"] == "fencer-api")
        self.assertEqual(projected["projected"]["sources"][0]["serviceAccountToken"]["audience"], "sekvyr-fence")

    def test_fencer_readiness_timeout_keeps_live_journal_probe_separate_from_process_liveness(self):
        resources = list(yaml.safe_load_all(self.ha().stdout))
        container = next(value for value in resources if value["kind"] == "Deployment" and value["metadata"]["name"] == "check-fencer")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["readinessProbe"], {"httpGet": {"scheme": "HTTPS", "path": "/readyz", "port": "https"},
            "timeoutSeconds": 10, "periodSeconds": 10, "failureThreshold": 3, "successThreshold": 1})
        self.assertEqual(container["livenessProbe"], {"httpGet": {"scheme": "HTTPS", "path": "/healthz", "port": "https"},
            "timeoutSeconds": 1, "periodSeconds": 10, "failureThreshold": 3, "successThreshold": 1})
        self.assertNotIn("startupProbe", container)
        self.assertEqual(self.ha().stdout, self.ha("--set", "ha.fencer.readinessTimeoutSeconds=10").stdout)

    def test_fencer_probe_override_changes_only_timeout_not_config_rbac_webhook_or_other_resources(self):
        default = list(yaml.safe_load_all(self.ha().stdout))
        old = list(yaml.safe_load_all(self.ha("--set", "ha.fencer.readinessTimeoutSeconds=1").stdout))
        fencer = next(value for value in old if value["kind"] == "Deployment" and value["metadata"]["name"] == "check-fencer")
        self.assertEqual(fencer["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["timeoutSeconds"], 1)
        fencer["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["timeoutSeconds"] = 10
        self.assertEqual(default, old)
        # The now-explicit legacy settings equal API defaults: default timeout1,
        # period10/failure3/success1. Only readiness timeout10 is intentional.
        for name in ("readinessProbe", "livenessProbe"):
            legacy = copy.deepcopy(fencer["spec"]["template"]["spec"]["containers"][0][name])
            legacy["timeoutSeconds"] = 1
            self.assertEqual({key: legacy[key] for key in ("timeoutSeconds", "periodSeconds", "failureThreshold", "successThreshold")},
                {"timeoutSeconds": 1, "periodSeconds": 10, "failureThreshold": 3, "successThreshold": 1})

    def test_fencer_probe_timeout_strict_bounds_hold_with_schema_bypassed(self):
        for value in (0, 31, -1, 1.5, True, False, "10", None):
            for bypass in ([], ["--skip-schema-validation"]):
                with self.subTest(value=value, bypass=bypass):
                    self.ha(*bypass, "--set-json", "ha.fencer.readinessTimeoutSeconds=" + json.dumps(value), success=False)
        self.ha("--set", "ha.fencer.readinessTimeoutSeconds=30")

    def test_ha_refuses_missing_pins_nontrial_or_self_escalation(self):
        for override in ["ha.trial=false", "ha.config.trial=false", "replicas=1", "sync.enabled=false",
                         "ha.namespaceUID=", "ha.managedObjects[0].namespace=other", "ha.fencer.serviceAccount.name=sekvyr-operator",
                         "ha.fencer.signingKeySecret.name=operator-state", "rollout.allowedDeployments[0]=check-fencer",
                         "ha.config.gatewayClientSecret.privateKey=public-test-placeholder"]:
            with self.subTest(override=override):
                self.ha("--set", override, success=False)

    def test_retired_state_default_does_not_change_render(self):
        self.assertEqual(self.ha().stdout, self.ha("--set-json", "ha.webhook.retiredStateSecrets=[]").stdout)
        self.assertEqual(self.ha().stdout, self.ha("--set", "ha.maintenance=false").stdout)

    def test_ha_maintenance_stops_only_operator_without_changing_runtime_wire(self):
        resources = list(yaml.safe_load_all(self.ha("--set", "replicas=0,ha.maintenance=true").stdout))
        deployments = {value["metadata"]["name"]: value for value in resources if value["kind"] == "Deployment"}
        self.assertEqual(deployments["check-operator"]["spec"]["replicas"], 0)
        self.assertEqual(deployments["check-fencer"]["spec"]["replicas"], 2)
        before = list(yaml.safe_load_all(self.ha().stdout))
        self.assertEqual([v for v in resources if v["kind"] == "ConfigMap"], [v for v in before if v["kind"] == "ConfigMap"])

    def test_maintenance_gates_hold_even_if_schema_is_skipped(self):
        for extra in ([], ["--skip-schema-validation"]):
            for override in ("replicas=0", "ha.maintenance=true", "replicas=1,ha.maintenance=true",
                    "replicas=0,ha.maintenance=true,ha.fencer.replicas=1"):
                with self.subTest(override=override, extra=extra):
                    self.ha(*extra, "--set", override, success=False)
            self.helm(*extra, "--set", "ha.maintenance=true,replicas=0", success=False)
            self.helm(*extra, "--set", "replicas=0", success=False)

    def test_retired_state_extends_only_admission_and_protection(self):
        pin = {"name": "operator-state-retired", "uid": "a1000000-0000-4000-8000-000000000001"}
        resources = list(yaml.safe_load_all(self.ha("--set-json", "ha.webhook.retiredStateSecrets=" + json.dumps([pin])).stdout))
        webhook = next(value for value in resources if value["kind"] == "ValidatingWebhookConfiguration")
        self.assertIn('"operator-state-retired"', webhook["webhooks"][0]["matchConditions"][0]["expression"])
        config = next(json.loads(value["data"]["installation.json"]) for value in resources
            if value["kind"] == "ConfigMap" and "installation.json" in value.get("data", {}))
        self.assertIn(pin["name"], config["protectedSecretNames"])
        self.assertIn(pin["uid"], config["protectedSecretUIDs"])
        for value in resources:
            if value["kind"] == "Role":
                self.assertNotIn(pin["name"], json.dumps(value["rules"]))
            if value["kind"] == "ConfigMap" and "config.json" in value.get("data", {}):
                self.assertNotIn(pin["name"], json.dumps(json.loads(value["data"]["config.json"])["managed_objects"]))

    def test_retired_state_requires_distinct_exact_administrative_pins(self):
        pin = {"name": "operator-state-retired", "uid": "a1000000-0000-4000-8000-000000000001"}
        invalid = [[pin, pin], [pin, {**pin, "uid": "a1000000-0000-4000-8000-000000000002"}],
            [pin, {**pin, "name": "another-retired"}], [{**pin, "name": "*"}], [{**pin, "uid": "not-a-uuid"}],
            [{**pin, "namespace": "other"}]]
        for name in ("operator-state", "operator-identity", "operator-trust", "billing-env", "fencer-signing", "billing"):
            invalid.append([{**pin, "name": name}])
        baseline = list(yaml.safe_load_all(self.ha().stdout))
        config = next(json.loads(value["data"]["installation.json"]) for value in baseline
            if value["kind"] == "ConfigMap" and "installation.json" in value.get("data", {}))
        invalid.append([{**pin, "uid": config["stateSecret"]["uid"]}])
        for value in invalid:
            with self.subTest(value=value):
                self.ha("--set-json", "ha.webhook.retiredStateSecrets=" + json.dumps(value), success=False)
                self.ha("--skip-schema-validation", "--set-json", "ha.webhook.retiredStateSecrets=" + json.dumps(value), success=False)
        self.helm("--set-json", "ha.webhook.retiredStateSecrets=" + json.dumps([pin]), success=False)


if __name__ == "__main__":
    unittest.main()
