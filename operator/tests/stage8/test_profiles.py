"""Offline Stage 8 profile/creator guards; no Docker, network or sudo."""

import ast
import copy
import inspect
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fixture import canonical
from stage8 import profiles, capability, prepare_kind, infrastructure, jwks
import remote_kind_capability as oldcap
import prepare_remote_kind as oldcreator
import remote_kind_jwks as oldjwks
import test_remote_kind as fixtures

SYNTHETIC = {
    "operator_image": "example.invalid/operator@sha256:" + "a" * 64,
    "backend_image": "example.invalid/backend@sha256:" + "b" * 64,
    "recovery_sha256": "c" * 64,
    "provision_sha256": "d" * 64,
}

class ProfileGuards(unittest.TestCase):
    def test_exact_two_profiles_and_reject_unlisted_minor_alias_or_custom_node(self):
        self.assertEqual(profiles.node_profile("kind-1.34.11").version, "v1.34.11")
        self.assertTrue(profiles.node_profile("kind-1.37.0").node.endswith("a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"))
        for bad in ("v1.37.0", "kind-1.34.1", "kind-1.37", "latest", {}, None):
            with self.subTest(profile=bad), self.assertRaises(RuntimeError):
                profiles.node_profile(bad)

    def test_unset_or_mutable_pins_abort_every_entry_before_file_or_action(self):
        for pins in (dict.fromkeys(SYNTHETIC), dict(SYNTHETIC, operator_image="example.invalid/operator:latest"),
                dict(SYNTHETIC, recovery_sha256="<PENDING>"), dict(SYNTHETIC, provision_sha256="0" * 64)):
            with self.subTest(pins=pins), patch.object(profiles, "REVIEWED_ARTIFACTS", pins), \
                    patch.object(oldcap, "paths", side_effect=AssertionError("No files")), \
                    patch.object(oldcap, "docker", side_effect=AssertionError("No Docker")):
                for operation in (
                        lambda: capability.Capability(None, profile="kind-1.37.0"),
                        lambda: prepare_kind.create("kind-1.37.0", *["unused"] * 9),
                        lambda: infrastructure.prepare("unused", profile="kind-1.37.0"),
                        lambda: jwks.RemoteKindJWKS(None, None, profile="kind-1.37.0")):
                    with self.assertRaises(RuntimeError): operation()

    def test_private_scope_cannot_add_arbitrary_override_or_mutate_old_globals(self):
        original = dict(oldcap.node_identity.__globals__)
        replacement = capability.fixed_function(oldcap.node_identity, NODE=profiles.node_profile("kind-1.34.11").node)
        self.assertIs(replacement.__code__, oldcap.node_identity.__code__)
        self.assertNotEqual(replacement.__globals__["NODE"], oldcap.NODE)
        self.assertEqual(oldcap.node_identity.__globals__, original)
        with self.assertRaises(RuntimeError):
            capability.fixed_function(oldcap.node_identity, arbitrary_plan_source="denied")

    def test_minimal_creator_and_infrastructure_copies_preserve_reviewed_algorithm(self):
        replacements = [
            (prepare_kind._create_template, oldcreator.create, "EXPECTED_VERSION", ast.Constant("v1.37.0")),
            (infrastructure._prepare_template, infrastructure.legacy.prepare, "EXPECTED_VERSIONS",
                ast.Tuple(elts=[ast.Constant("v1.37.0"), ast.Constant("v1.34.1+k0s")], ctx=ast.Load())),
        ]
        for new, original, identifier, old in replacements:
            class RestoreLiteral(ast.NodeTransformer):
                def visit_Name(self, node):
                    return copy.deepcopy(old) if node.id == identifier else node
                def visit_Dict(self, node):
                    positions = [i for i, key in enumerate(node.keys)
                        if isinstance(key, ast.Constant) and key.value == "stage8ProfileSHA256"]
                    if positions:
                        self_count[0] += len(positions)
                        index = positions[0]
                        self_assert(isinstance(node.values[index], ast.Name)
                            and node.values[index].id == "STAGE8_PROFILE_SHA256")
                        del node.keys[index]
                        del node.values[index]
                    return self.generic_visit(node)
            self_count, self_assert = [0], self.assertTrue
            updated = ast.parse(inspect.getsource(new))
            updated = RestoreLiteral().visit(updated)
            self.assertEqual(self_count[0], 1 if new is prepare_kind._create_template else 0)
            updated.body[0].name = original.__name__
            self.assertEqual(ast.dump(updated, include_attributes=False),
                ast.dump(ast.parse(inspect.getsource(original)), include_attributes=False))

    def test_creator_saves_classification_before_fixed_create_and_never_adopts_existing_receipt(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(profiles, "REVIEWED_ARTIFACTS", SYNTHETIC):
            root = Path(temporary) / "root"
            (root / "receipts").mkdir(parents=True)
            task, backup = root / "fresh-runtime", root / "private" / "creator"
            def operation(*args):
                value = json.loads((root / "receipts" / profiles.PROFILE_RECEIPT).read_bytes())
                self.assertEqual(value["nodeImage"], profiles.node_profile("kind-1.34.11").node)
                self.assertEqual(value["artifacts"], SYNTHETIC)
                self.assertEqual(value["rootCreationReceiptSHA256"], oldcap.digest(b"independent-root-create"))
                self.assertEqual(create_scope["STAGE8_PROFILE_SHA256"],
                    oldcap.digest((root / "receipts" / profiles.PROFILE_RECEIPT).read_bytes()))
                return task
            called = Mock(side_effect=operation)
            create_scope = {}
            def bind(code, scope):
                create_scope.update(scope)
                return called
            with patch.object(oldcreator.os, "geteuid", return_value=0, create=True), \
                    patch.object(oldcreator.os, "uname", return_value=SimpleNamespace(sysname="Linux", machine="x86_64"), create=True), \
                    patch.object(oldcreator, "runtime_capabilities"), patch.object(oldcap, "paths", return_value=(root, task, backup)), \
                    patch.object(oldcap, "directory"), patch.object(oldcap, "root_creation", return_value=(b"independent-root-create", {})), \
                    patch.object(prepare_kind, "FunctionType", side_effect=bind), \
                    patch.object(oldcap, "docker", side_effect=AssertionError("No Docker in this fixture")):
                self.assertEqual(prepare_kind.create("kind-1.34.11", root, task, *["explicit"] * 7), task)
                with self.assertRaises(FileExistsError):
                    prepare_kind.create("kind-1.34.11", root, task, *["explicit"] * 7)
            called.assert_called_once()

    def test_asset_map_is_pure_exact_and_has_no_importer(self):
        with patch.object(profiles, "REVIEWED_ARTIFACTS", SYNTHETIC):
            self.assertFalse(prepare_kind.verify_asset_map(dict(SYNTHETIC))["imported"])
            with self.assertRaises(RuntimeError):
                prepare_kind.verify_asset_map(dict(SYNTHETIC, backend_image="example.invalid/backend:latest"))
        self.assertFalse(hasattr(prepare_kind, "import_images"))

class CapabilityGuards(unittest.TestCase):
    docker = fixtures.CapabilityGuards.docker

    def setUp(self):
        fixtures.CapabilityGuards.setUp(self)
        replacement = patch.object(profiles, "REVIEWED_ARTIFACTS", SYNTHETIC)
        replacement.start()
        self.addCleanup(replacement.stop)
        (self.root / "receipts").mkdir()
        self.select("kind-1.37.0")

    def select(self, profile):
        selected = profiles.node_profile(profile)
        self.selected = selected
        self.node["Config"]["Image"] = selected.node
        self.preflight["nodeImage"] = selected.node
        profile_raw = canonical(profiles.receipt(selected, SYNTHETIC,
            self.root, self.task, self.preflight["rootCreationReceiptSHA256"]))
        self.preflight["stage8ProfileSHA256"] = oldcap.digest(profile_raw)
        self.created["node"]["image"] = selected.node
        self.created["configSHA256"] = oldcap.digest(canonical(self.node["Config"]))
        self.created["preflightSHA256"] = oldcap.digest(canonical(self.preflight))
        self.limits["creatorSHA256"] = oldcap.digest(canonical(self.created))
        self.image[0]["RepoDigests"] = [selected.node.split("@")[0].split(":")[0] + "@" + selected.node.split("@")[1]]
        original_docker = self.docker
        def docker(*args, **kwargs):
            if args == ("image", "inspect", selected.node):
                self.calls.append(args)
                return canonical(self.image)
            return original_docker(*args, **kwargs)
        # The base fixture patches oldcap.docker; install a narrower profile fake.
        replacement = patch.object(oldcap, "docker", side_effect=docker)
        replacement.start()
        self.addCleanup(replacement.stop)
        marker = {"format": oldcap.FORMAT, "rootTask": str(self.root), "runtimeTask": str(self.task),
            "preflightSHA256": oldcap.digest(canonical(self.preflight)),
            "creatorSHA256": oldcap.digest(canonical(self.created)), "capsSHA256": oldcap.digest(canonical(self.limits))}
        for path, value in ((self.task / "private" / oldcap.MARKER, marker),
                (self.task / "private" / "node-pin.json", self.created["node"]),
                (self.backup / "preflight.json", self.preflight), (self.backup / "creation.json", self.created),
                (self.backup / "caps.json", self.limits)):
            path.write_bytes(canonical(value))
        self.profile_file = self.root / "receipts" / profiles.PROFILE_RECEIPT
        self.profile_file.write_bytes(profile_raw)

    def owner(self):
        return capability.Capability(self.cluster, profile=self.selected.name)

    def test_each_closed_node_checks_exact_digest_labels_caps_and_creator_chain(self):
        for profile in ("kind-1.37.0", "kind-1.34.11"):
            with self.subTest(profile=profile):
                self.select(profile)
                owner = self.owner()
                self.assertEqual(owner.exec("true"), b"safe-result")
                self.assertEqual(owner.root_plan()["stage8ProfilePath"], str(self.profile_file))

    def test_old_creator_receipts_without_stage8_classification_never_reach_docker(self):
        self.profile_file.unlink()
        with self.assertRaises(FileNotFoundError): self.owner()
        self.assertFalse(self.calls)

    def test_late_profile_cannot_adopt_legacy_preflight_without_profile_hash(self):
        del self.preflight["stage8ProfileSHA256"]
        self.created["preflightSHA256"] = oldcap.digest(canonical(self.preflight))
        self.limits["creatorSHA256"] = oldcap.digest(canonical(self.created))
        marker = json.loads((self.task / "private" / oldcap.MARKER).read_bytes())
        marker.update(preflightSHA256=oldcap.digest(canonical(self.preflight)),
            creatorSHA256=oldcap.digest(canonical(self.created)), capsSHA256=oldcap.digest(canonical(self.limits)))
        for path, value in ((self.task / "private" / oldcap.MARKER, marker),
                (self.backup / "preflight.json", self.preflight), (self.backup / "creation.json", self.created),
                (self.backup / "caps.json", self.limits)):
            path.write_bytes(canonical(value))
        with self.assertRaises(RuntimeError): self.owner()
        self.assertFalse(self.calls)

    def test_wrong_profile_root_hash_or_build_pin_rejects_before_docker(self):
        original = self.profile_file.read_bytes()
        for field, value in (("profile", "kind-1.34.11"), ("rootCreationReceiptSHA256", "f" * 64),
                ("artifacts", dict(SYNTHETIC, recovery_sha256="e" * 64))):
            changed = json.loads(original);changed[field] = value
            self.profile_file.write_bytes(canonical(changed))
            with self.assertRaises(RuntimeError): self.owner()
            self.assertFalse(self.calls)
        self.profile_file.write_bytes(original)

    def test_caps_pid_network_or_alias_drift_denies_action_for_second_minor(self):
        self.select("kind-1.34.11")
        owner = self.owner()
        for mutate in (lambda: self.node["HostConfig"].update(Memory=1),
                lambda: self.process.update(starttime="reused"),
                lambda: self.network["Containers"].update({"f" * 64: {}}),
                lambda: self.image[0].update(RepoDigests=["example.invalid/foreign@sha256:" + "f" * 64])):
            snapshots = copy.deepcopy((self.node, self.process, self.network, self.image))
            mutate()
            with self.assertRaises(RuntimeError): owner.exec("true")
            self.assertNotEqual(self.calls[-1][0], "exec")
            self.node, self.process, self.network, self.image = snapshots

    def test_classification_mutation_after_construction_refuses_exec(self):
        owner = self.owner()
        self.profile_file.write_bytes(self.profile_file.read_bytes() + b" ")
        with self.assertRaises(RuntimeError): owner.exec("true")
        self.assertNotEqual(self.calls[-1][0], "exec")

    def test_jwks_uses_same_backup_and_requires_explicit_stage8_capability_path(self):
        signer = jwks.RemoteKindJWKS(self.cluster, self.task / "private" / oldcap.MARKER, profile=self.selected.name)
        self.assertEqual(signer.native, self.backup)
        self.assertIsInstance(signer.capability, capability.Capability)
        self.assertEqual(signer._exec("true"), b"safe-result")
        with self.assertRaises(RuntimeError):
            jwks.RemoteKindJWKS(self.cluster, self.task / "other-marker.json", profile=self.selected.name)

    def test_cleanup_retains_legacy_foreign_and_shared_network_guards(self):
        owner = self.owner()
        with patch.object(oldcreator, "foreign_unchanged"), patch.object(oldcreator, "docker", side_effect=AssertionError("No mutation")):
            self.assertFalse(prepare_kind.cleanup(owner)["deleteRequested"])
        self.network["Containers"]["f" * 64] = {}
        with patch.object(oldcreator, "docker") as actor, self.assertRaises(RuntimeError):
            prepare_kind.cleanup(owner, execute=True)
        actor.assert_not_called()
