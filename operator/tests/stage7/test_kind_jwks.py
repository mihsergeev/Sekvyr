"""No live actions: owned node, immutable backup and real JWT crypto guards."""

import base64
import copy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from kind_jwks import KindJWKS, MANIFEST, OLD_KEY, OLD_PUBLIC, SIGN, VERIFY, NODE, CLUSTER, WRITE_NEW, REPLACE_MANIFEST, changed_manifest, digest, native_path
from helm_lifecycle import canonical


def static_manifest():
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "kube-apiserver", "namespace": "kube-system"}, "spec": {
        "hostNetwork": True, "containers": [{"name": "kube-apiserver", "image": "registry.k8s.io/kube-apiserver:v1.37.0",
            "command": ["kube-apiserver", SIGN + OLD_KEY, VERIFY + OLD_PUBLIC, "--service-account-issuer=https://kubernetes.default.svc"],
            "volumeMounts": [{"name": "pki", "mountPath": "/etc/kubernetes/pki", "readOnly": True}]}],
        "volumes": [{"name": "pki", "hostPath": {"path": "/etc/kubernetes/pki", "type": "DirectoryOrCreate"}}]}}


class JWKSGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        obj = self.obj = KindJWKS.__new__(KindJWKS)
        obj.task, obj.root, obj.native = root / "task", root / "task" / "private" / "kind-jwks", root / "native"
        obj.root.mkdir(parents=True)
        obj.native.mkdir()
        obj.pin_file = obj.task / "private" / "node-pin.json"
        obj.pin = {"id": "1" * 64, "image": NODE, "volumes": []}
        obj.pin_raw = canonical(obj.pin)
        obj.pin_file.write_bytes(obj.pin_raw)
        obj.creation_receipt = obj.native / "creation.json"
        obj.creation_raw = canonical({"node": obj.pin})
        obj.creation_receipt.write_bytes(obj.creation_raw)
        obj.prepared = False
        self.old_key = ec.generate_private_key(ec.SECP256R1())
        self.public = self.old_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.files = {MANIFEST: yaml.safe_dump(static_manifest()).encode(), OLD_PUBLIC: self.public}
        self.key_hashes = {OLD_KEY: "e" * 64, OLD_PUBLIC: digest(self.public)}
        self.node = {"Id": obj.pin["id"], "Image": "sha256:" + "a" * 64, "Config": {"Image": NODE,
            "Labels": {"io.x-k8s.kind.cluster": CLUSTER, "io.x-k8s.kind.role": "control-plane"}}, "State": {"Running": True}}
        self.image = {"Id": self.node["Image"], "RepoDigests": [NODE.split("@", 1)[0].rsplit(":", 1)[0] + "@" + NODE.split("@", 1)[1]]}
        self.calls = []
        obj._docker = self.docker

    def docker(self, *args, data=None):
        self.calls.append((args, data))
        if args[0] == "inspect":
            return canonical([self.node])
        if args[:2] == ("image", "inspect"):
            return canonical([self.image])
        if args[0] != "exec":
            raise AssertionError("Unscoped fake Docker call")
        offset = 3 if args[1] == "-i" else 2
        command = args[offset:]
        if command[0] == "cat":
            self.assertNotEqual(command[1], OLD_KEY)
            return self.files[command[1]]
        if command[0] == "sha256sum":
            return "".join((self.key_hashes[path] if path in self.key_hashes else digest(self.files[path])) + "  " + path + "\n" for path in command[1:]).encode()
        if command[:3] == ("sh", "-c", WRITE_NEW):
            path, expected = command[-2:]
            self.assertNotIn(path, self.files)
            self.assertEqual(digest(data), expected)
            self.assertTrue((self.obj.root / "backup-complete.json").exists())
            self.files[path] = data
            return b""
        if command[:3] == ("sh", "-c", REPLACE_MANIFEST):
            before, after = command[-2:]
            self.assertEqual(digest(self.files[MANIFEST]), before)
            self.assertEqual(digest(data), after)
            self.files[MANIFEST] = data
            return b""
        raise AssertionError("Unexpected owned exec")

    def test_only_two_flags_change_and_original_key_files_are_unmodified(self):
        before = static_manifest()
        rotated = yaml.safe_load(changed_manifest(yaml.safe_dump(before), "/etc/kubernetes/pki/new.key", "/etc/kubernetes/pki/overlap.pub"))
        expected = copy.deepcopy(before)
        expected["spec"]["containers"][0]["command"][1:3] = [SIGN + "/etc/kubernetes/pki/new.key", VERIFY + "/etc/kubernetes/pki/overlap.pub"]
        self.assertEqual(rotated, expected)
        for mutate in (lambda value: value["spec"]["containers"][0]["command"].append(VERIFY + OLD_PUBLIC),
                lambda value: value["spec"]["containers"][0]["volumeMounts"][0].update(readOnly=False)):
            value = static_manifest()
            mutate(value)
            with self.assertRaises(RuntimeError):
                changed_manifest(yaml.safe_dump(value), "/new.key", "/new.pub")

    def test_each_exec_revalidates_exact_node_and_image(self):
        self.obj._exec("cat", MANIFEST)
        self.obj._exec("cat", OLD_PUBLIC)
        self.assertEqual(sum(call[0][0] == "inspect" for call in self.calls), 2)
        self.assertEqual(sum(call[0][:2] == ("image", "inspect") for call in self.calls), 2)
        self.node["Id"] = "2" * 64
        with self.assertRaisesRegex(RuntimeError, "CID/image/labels"):
            self.obj._exec("cat", MANIFEST)
        self.assertEqual(sum(call[0][0] == "exec" for call in self.calls), 2)

    def test_wrong_role_image_or_creation_receipt_blocks_exec(self):
        for field in ("role", "image", "receipt"):
            previous = copy.deepcopy(self.node)
            raw = self.obj.creation_receipt.read_bytes()
            if field == "role":
                self.node["Config"]["Labels"]["io.x-k8s.kind.role"] = "worker"
            elif field == "image":
                self.node["Image"] = "sha256:" + "b" * 64
            else:
                self.obj.creation_receipt.write_bytes(b"changed")
            with self.assertRaises(RuntimeError):
                self.obj._exec("cat", MANIFEST)
            self.node, self.obj.creation_raw = previous, raw
            self.obj.creation_receipt.write_bytes(raw)
        self.assertFalse(any(call[0][0] == "exec" for call in self.calls))

    def test_backup_precedes_all_mutation_no_private_key_native_copy(self):
        self.obj.prepare()
        self.assertFalse(any(call[0][0] == "exec" and "sh" in call[0] for call in self.calls))
        native_raw = b"".join(path.read_bytes() for path in self.obj.native.glob("*"))
        self.assertNotIn(b"PRIVATE KEY", native_raw)
        self.assertTrue((self.obj.root / "new-key.pem").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertFalse(self.obj.plan["exactOriginalManifestRestoreClaimed"])
        self.assertEqual(self.obj.plan["restoreMode"], "original-signer-temporary-overlap-verifiers")
        with self.assertRaises(RuntimeError):
            self.obj.prepare()

    def test_changed_native_backup_denies_rotation_before_mutation(self):
        self.obj.prepare()
        self.obj._bound_panel, self.obj._bound_meta = object(), {}
        (self.obj.native / (self.obj.task.name + "-jwks-original-manifest.yaml")).write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "backup changed"):
            self.obj.rotate()
        self.assertFalse(any(call[0][0] == "exec" and "sh" in call[0] for call in self.calls))

    def test_rotation_and_restore_original_signer_keep_overlap_no_extra_keys_in_argv(self):
        self.obj.prepare()
        self.obj._bound_panel, self.obj._bound_meta = object(), {}
        original_hashes = dict(self.key_hashes)
        with patch.object(self.obj, "_wait_ready", return_value={"keys": []}) as ready:
            self.obj.rotate()
            self.obj.restore()
        command = yaml.safe_load(self.files[MANIFEST])["spec"]["containers"][0]["command"]
        self.assertIn(SIGN + OLD_KEY, command)
        self.assertIn(VERIFY + self.obj.bundle_path, command)
        self.assertEqual(self.key_hashes, original_hashes)
        self.assertEqual(ready.call_args_list[-1].kwargs, {"new_signer": False})
        for args, data in self.calls:
            self.assertNotIn("PRIVATE KEY", " ".join(args))
            if data is not None:
                self.assertIn("-i", args)

    def test_restore_handles_staging_failure_without_touching_original_manifest(self):
        self.obj.prepare()
        before = self.files[MANIFEST]
        self.obj.restore()
        self.assertEqual(self.files[MANIFEST], before)
        self.assertTrue((self.obj.root / "unmodified.json").exists())
        self.assertFalse(any(call[0][0] == "exec" and "sh" in call[0] for call in self.calls))

    def test_unknown_manifest_denies_restore(self):
        self.obj.prepare()
        self.files[MANIFEST] = b"unreviewed"
        with self.assertRaisesRegex(RuntimeError, "restoration refused"):
            self.obj.restore()

    def test_no_host_or_watched_directory_backup_paths(self):
        for script in (WRITE_NEW, REPLACE_MANIFEST):
            self.assertNotIn("kill", script)
            self.assertNotIn("systemctl", script)
        self.assertIn("mktemp /etc/kubernetes/.sekvyr-stage7-api.", REPLACE_MANIFEST)
        self.assertNotIn("mktemp /etc/kubernetes/manifests/", REPLACE_MANIFEST)
        with self.assertRaises(RuntimeError):
            native_path(self.obj.root)

    def test_discovery_never_adds_unknown_or_substituted_public_material(self):
        self.obj.prepare()
        self.obj._previous_jwks = {"keys": [dict(self.obj.new_jwk, kid="old-public-test-kid")]}
        overlap = {"keys": self.obj._previous_jwks["keys"] + [self.obj.new_jwk]}
        self.obj._known_overlap(overlap)
        for changed in ({"keys": overlap["keys"] + [dict(self.obj.new_jwk, kid="unreviewed")]},
                {"keys": overlap["keys"][:-1] + [dict(self.obj.new_jwk, x="A" * 43)]}):
            with self.assertRaisesRegex(RuntimeError, "independently prepared"):
                self.obj._known_overlap(changed)

    def test_bound_token_is_real_signature_and_exact_owned_pod_context(self):
        self.obj.prepare()
        private = serialization.load_pem_private_key((self.obj.root / "new-key.pem").read_bytes(), None)
        meta = {"namespace": "trial-apps", "service_account": "reader", "service_account_uid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "issuer": "https://kubernetes.default.svc"}
        pod_ref = {"name": "consumer-pod", "uid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
        provider = object()
        self.obj._bound_panel, self.obj._bound_meta, self.obj._bound_pod = provider, meta, pod_ref
        encode = lambda value: base64.urlsafe_b64encode(canonical(value)).decode().rstrip("=")
        header = encode({"alg": "ES256", "kid": self.obj.plan["newKid"]})
        claims = {"aud": ["sekvyr"], "iss": meta["issuer"], "iat": 1, "exp": 601,
            "kubernetes.io": {"namespace": "trial-apps", "pod": pod_ref, "serviceaccount": {"name": "reader", "uid": meta["service_account_uid"]}}}
        claims["kubernetes.io"]["pod"] = {"name": pod_ref["name"], "uid": pod_ref["uid"]}
        body = encode(claims)
        r, s = decode_dss_signature(private.sign((header + "." + body).encode(), ec.ECDSA(hashes.SHA256())))
        signature = base64.urlsafe_b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode().rstrip("=")
        token = header + "." + body + "." + signature
        requests = []
        def kube(*args, **kwargs):
            requests.append((args, kwargs))
            if "pod" in args:
                value = {"metadata": {"uid": pod_ref["uid"], "ownerReferences": [{"kind": "ReplicaSet", "controller": True, "name": "replica", "uid": "replica-uid"}]}, "spec": {"serviceAccountName": "reader"}}
            elif "replicaset" in args:
                value = {"metadata": {"uid": "replica-uid", "ownerReferences": [{"kind": "Deployment", "controller": True, "name": "consumer", "uid": "deployment-uid"}]}}
            else:
                value = {"status": {"token": token}}
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(value), stderr="")
        self.obj.cluster = SimpleNamespace(kube=kube)
        owned = Mock()
        owned.get.side_effect = lambda kind, name: {"metadata": {"uid": meta["service_account_uid"] if kind == "ServiceAccount" else "deployment-uid"}}
        with patch("kind_jwks.OwnedNamespace", return_value=owned):
            self.assertEqual(self.obj.bound_token(provider, pod_ref), token)
            token = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
            with self.assertRaisesRegex(RuntimeError, "signature does not match"):
                self.obj.bound_token(provider, pod_ref)
        self.assertTrue(all("--request-timeout=5s" in args for args, kwargs in requests))
        post = next(kwargs for args, kwargs in requests if args[0] == "create")
        self.assertEqual(json.loads(post["data"])["spec"]["boundObjectRef"]["uid"], pod_ref["uid"])

    def run_fixture(self):
        events = []
        previous = {"keys": [{"kid": "old-public-test-key", "kty": "EC", "crv": "P-256", "x": "PUBLIC"}]}
        overlap = {"keys": previous["keys"] + [{"kid": "new-public-test-key", "kty": "EC", "crv": "P-256", "x": "PUBLIC_NEW"}]}
        meta = {"initial_jwks": previous, "namespace": "trial-apps", "service_account": "reader", "service_account_uid": "reader-uid"}
        pod = {"name": "reader-pod", "uid": "reader-pod-uid"}
        encode = lambda value: base64.urlsafe_b64encode(canonical(value)).decode().rstrip("=")
        old = encode({"kid": "old-public-test-key"}) + "." + encode({"iat": 100, "exp": 700,
            "kubernetes.io": {"namespace": "trial-apps", "pod": pod, "serviceaccount": {"name": "reader", "uid": "reader-uid"}}}) + ".PUBLIC"
        current = {"keys": previous}
        self.obj.cluster = SimpleNamespace(kube=Mock(side_effect=lambda *args: SimpleNamespace(stdout=json.dumps(current["keys"]))))
        def prepare():
            events.append("prepare")
            self.obj.plan = {"oldKid": "old-public-test-key", "newKid": "new-public-test-key", "originalManifestSHA256": digest(b"PUBLIC_ORIGINAL")}
        def rotate():
            events.append("rotated-ready")
            current["keys"] = overlap
            return overlap
        def known(value):
            self.assertEqual(value, overlap)
            events.append("known-overlap")
        def bound(*args):
            events.append("bound-new-token-verified")
            return "PUBLIC_NEW_TOKEN_VERIFIED_BY_SEPARATE_CRYPTO_GUARDS"
        self.obj.prepare = Mock(side_effect=prepare)
        self.obj.rotate = Mock(side_effect=rotate)
        self.obj._known_overlap = Mock(side_effect=known)
        self.obj.bound_token = Mock(side_effect=bound)
        self.obj.restore = Mock(side_effect=lambda: events.append("restored-ready"))
        self.obj._exec = Mock(return_value=b"PUBLIC_RESTORED_OVERLAP")
        provider = SimpleNamespace(exchange=Mock(side_effect=lambda value: events.append("authenticate-old")), ready=Mock(return_value=meta),
            assert_manual_jwks_rollover=Mock(side_effect=lambda *args: events.append("owner-retirement") or {"sourceTimingOnly": True}),
            update_jwks=Mock(side_effect=lambda value: events.append("owner-restore-jwks")))
        return provider, old, pod, events

    def test_ready_callbacks_run_after_verified_tokens_and_before_owner_changes_in_both_phases(self):
        provider, old, pod, events = self.run_fixture()
        result = self.obj.run(provider, old, pod, after_control_plane_ready=lambda phase: events.append("callback-" + phase))
        self.assertEqual(events, ["authenticate-old", "prepare", "rotated-ready", "known-overlap", "bound-new-token-verified",
            "callback-rotated", "owner-retirement", "restored-ready", "known-overlap", "callback-restored", "owner-restore-jwks"])
        self.assertTrue(result["originalSignerRestored"])
        self.obj.restore.assert_called_once()

    def test_rotated_callback_failure_still_restores_signer_and_propagates_exact_exception(self):
        provider, old, pod, events = self.run_fixture()
        failure = ValueError("PUBLIC synthetic rotated reconnect failure")
        def callback(phase):
            events.append("callback-" + phase)
            if phase == "rotated":
                raise failure
        with self.assertRaises(ValueError) as caught:
            self.obj.run(provider, old, pod, after_control_plane_ready=callback)
        self.assertIs(caught.exception, failure)
        self.obj.restore.assert_called_once()
        provider.assert_manual_jwks_rollover.assert_not_called()
        provider.update_jwks.assert_called_once()
        self.assertLess(events.index("restored-ready"), events.index("callback-restored"))
        self.assertLess(events.index("callback-restored"), events.index("owner-restore-jwks"))

    def test_restored_callback_failure_occurs_after_signer_restore_without_owner_update_or_pass(self):
        provider, old, pod, events = self.run_fixture()
        failure = RuntimeError("PUBLIC synthetic restored reconnect failure")
        def callback(phase):
            events.append("callback-" + phase)
            if phase == "restored":
                raise failure
        with self.assertRaises(RuntimeError) as caught:
            self.obj.run(provider, old, pod, after_control_plane_ready=callback)
        self.assertIs(caught.exception, failure)
        self.obj.restore.assert_called_once()
        provider.assert_manual_jwks_rollover.assert_called_once()
        provider.update_jwks.assert_not_called()
        self.assertLess(events.index("known-overlap", events.index("restored-ready")), events.index("callback-restored"))

    def test_invalid_ready_callback_is_rejected_before_auth_prepare_or_any_action(self):
        provider, old, pod, events = self.run_fixture()
        for invalid in ("reconnect", {}, 1):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(RuntimeError, "must be callable"):
                self.obj.run(provider, old, pod, after_control_plane_ready=invalid)
        self.assertEqual(events, [])
        provider.exchange.assert_not_called()
        self.obj.cluster.kube.assert_not_called()
        self.obj.prepare.assert_not_called()
        self.obj.rotate.assert_not_called()
        self.obj.restore.assert_not_called()

    def test_default_no_callback_keeps_prior_sequence(self):
        provider, old, pod, events = self.run_fixture()
        result = self.obj.run(provider, old, pod)
        self.assertTrue(result["originalSignerRestored"])
        self.assertEqual(events, ["authenticate-old", "prepare", "rotated-ready", "known-overlap", "bound-new-token-verified",
            "owner-retirement", "restored-ready", "known-overlap", "owner-restore-jwks"])


if __name__ == "__main__":
    unittest.main()
