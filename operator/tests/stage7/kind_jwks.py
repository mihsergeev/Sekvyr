"""One explicitly owned kind API-server signer rollover, coordinator only.

Original sa.key/sa.pub are never copied or modified. Restore means original
signer plus temporary old/new verification overlap, not exact manifest restore.
The whole creation-pinned trial cluster is deleted after acceptance.

Primary references:
https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/
https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/serviceaccount/jwt.go
"""

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app_modes import OwnedNamespace, require
from fixture import safe_task
from helm_lifecycle import canonical, private_exact
from panel_cases import observe_jwt, public_jwks
from prepare import CLUSTER, NODE, SOCKET

MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
OLD_KEY, OLD_PUBLIC = "/etc/kubernetes/pki/sa.key", "/etc/kubernetes/pki/sa.pub"
SIGN, VERIFY = "--service-account-signing-key-file=", "--service-account-key-file="


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class _DeadlineCluster:
    def __init__(self, cluster):
        self.cluster = cluster

    def __getattr__(self, name):
        return getattr(self.cluster, name)

    def kube(self, *args, **kwargs):
        return self.cluster.kube(*args, "--request-timeout=5s", **kwargs)


def native_path(value):
    path = Path(value).absolute()
    require(path.resolve() == path and not path.is_symlink() and path.is_dir()
        and len(path.parts) >= 4 and path.parts[1] == "mnt" and re.fullmatch(r"[a-z]", path.parts[2]),
        "Explicit existing native backup directory outside WSL filesystem required")
    return path


def changed_manifest(original, signer, verifier):
    value = yaml.safe_load(original)
    require(value.get("apiVersion") == "v1" and value.get("kind") == "Pod" and value["metadata"]["name"] == "kube-apiserver",
        "Unexpected kind API-server static manifest")
    containers = value["spec"]["containers"]
    require(len(containers) == 1 and containers[0]["name"] == "kube-apiserver", "Unexpected API-server containers")
    command = containers[0]["command"]
    require(command[0] == "kube-apiserver" and command.count(SIGN + OLD_KEY) == 1 and command.count(VERIFY + OLD_PUBLIC) == 1
        and sum(item.startswith(SIGN) for item in command) == 1 and sum(item.startswith(VERIFY) for item in command) == 1
        and not any(item.startswith("--service-account-signing-endpoint") for item in command), "Unexpected service-account signer flags")
    mounts = [item for item in containers[0].get("volumeMounts", []) if item.get("mountPath") == "/etc/kubernetes/pki"]
    require(len(mounts) == 1 and mounts[0].get("readOnly") is True
        and any(item.get("name") == mounts[0]["name"] and item.get("hostPath", {}).get("path") == "/etc/kubernetes/pki"
            for item in value["spec"].get("volumes", [])), "API-server signing files lack the expected read-only mount")
    result = copy.deepcopy(value)
    result["spec"]["containers"][0]["command"] = [SIGN + signer if item == SIGN + OLD_KEY else VERIFY + verifier if item == VERIFY + OLD_PUBLIC else item for item in command]
    # Only the two flags differ semantically. No additional watched file is used.
    return yaml.safe_dump(result, sort_keys=False).encode("utf-8")


WRITE_NEW = r'''set -eu
path=$1; expected=$2
test ! -e "$path"; test ! -L "$path"
umask 077
temp=$(mktemp /etc/kubernetes/pki/.sekvyr-stage7.XXXXXX)
trap 'rm -f -- "$temp"' EXIT
cat > "$temp"
test "$(sha256sum "$temp" | cut -d ' ' -f1)" = "$expected"
chmod 0600 "$temp"; sync -f "$temp"
ln -- "$temp" "$path"
sync -f /etc/kubernetes/pki
'''

REPLACE_MANIFEST = r'''set -eu
path=/etc/kubernetes/manifests/kube-apiserver.yaml
before=$1; after=$2
test -f "$path"; test ! -L "$path"
test "$(sha256sum "$path" | cut -d ' ' -f1)" = "$before"
umask 077
temp=$(mktemp /etc/kubernetes/.sekvyr-stage7-api.XXXXXX)
trap 'rm -f -- "$temp"' EXIT
cat > "$temp"
test "$(sha256sum "$temp" | cut -d ' ' -f1)" = "$after"
chmod 0600 "$temp"; sync -f "$temp"
test "$(sha256sum "$path" | cut -d ' ' -f1)" = "$before"
mv -f -- "$temp" "$path"
sync -f /etc/kubernetes/manifests
'''


class KindJWKS:
    def __init__(self, cluster, native_creation_receipt, native_backup_dir):
        self.cluster, self.task = cluster, safe_task(cluster.task)
        require(self.task.parent == Path("/var/tmp"), "Signer rollover is local owned kind only")
        self.pin_file = self.task / "private" / "node-pin.json"
        self.pin_raw = self.pin_file.read_bytes()
        self.pin = json.loads(self.pin_raw)
        require(re.fullmatch(r"[0-9a-f]{64}", self.pin.get("id", "")) and self.pin.get("image") == NODE, "Exact creator node CID and image required")
        self.native = native_path(native_backup_dir)
        self.creation_receipt = Path(native_creation_receipt).absolute()
        require(self.creation_receipt.resolve() == self.creation_receipt and not self.creation_receipt.is_symlink()
            and self.creation_receipt.parent == self.native, "Exact native creation receipt required")
        self.creation_raw = self.creation_receipt.read_bytes()
        creation = json.loads(self.creation_raw)
        require(creation["taskDirectory"] == str(self.task) and creation["node"] == self.pin
            and creation["fixture"]["namespaces"] == cluster.fixture["namespaces"], "Native creation receipt does not identify this cluster")
        self.root = self.task / "private" / "kind-jwks"
        self.root.mkdir(mode=0o700, exist_ok=True)
        require(not self.root.is_symlink(), "Unsafe signer rollover context")
        self.prepared = False

    def __repr__(self):
        return "<owned kind JWKS rollover [redacted]>"

    def _docker(self, *args, data=None):
        try:
            value = subprocess.run(["sudo", "-n", "docker", "--host=" + SOCKET, *args], input=data,
                capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("Owned kind operation unavailable") from None
        require(value.returncode == 0, "Owned kind operation failed")
        return value.stdout

    def guard(self):
        require(not self.pin_file.is_symlink() and self.pin_file.read_bytes() == self.pin_raw
            and not self.creation_receipt.is_symlink() and self.creation_receipt.read_bytes() == self.creation_raw, "Creation receipts changed")
        objects = json.loads(self._docker("inspect", self.pin["id"]))
        require(len(objects) == 1, "Pinned kind node missing or ambiguous")
        value = objects[0]
        labels = value["Config"].get("Labels", {})
        require(value["Id"] == self.pin["id"] and value["Config"]["Image"] == NODE
            and labels.get("io.x-k8s.kind.cluster") == CLUSTER and labels.get("io.x-k8s.kind.role") == "control-plane"
            and value["State"].get("Running") is True, "Owned kind CID/image/labels changed")
        image = json.loads(self._docker("image", "inspect", NODE))
        repository = NODE.split("@", 1)[0].rsplit(":", 1)[0]
        immutable = repository + "@" + NODE.split("@", 1)[1]
        require(len(image) == 1 and image[0]["Id"] == value["Image"]
            and any(item in (immutable, "docker.io/" + immutable) for item in image[0].get("RepoDigests", [])), "Pinned kind OCI image changed")

    def _exec(self, *args, data=None):
        self.guard()  # before EACH exec, not only before the first mutation
        return self._docker("exec", *( ["-i"] if data is not None else []), self.pin["id"], *args, data=data)

    def _old_hashes(self):
        raw = self._exec("sha256sum", OLD_KEY, OLD_PUBLIC).decode("ascii")
        result = {}
        for line in raw.splitlines():
            hash_value, path = line.split(None, 1)
            require(path in (OLD_KEY, OLD_PUBLIC) and re.fullmatch(r"[0-9a-f]{64}", hash_value), "Unexpected original key hash response")
            result[path] = hash_value
        require(set(result) == {OLD_KEY, OLD_PUBLIC}, "Original signing key hashes unavailable")
        return result

    def _original_unchanged(self):
        require(self._old_hashes() == self.plan["originalKeyHashes"], "Original signing keys changed")

    def prepare(self):
        require(not (self.root / "plan.json").exists(), "Existing signer plan requires explicit coordinator resume/recovery review")
        original = self._exec("cat", MANIFEST)
        require(len(original) <= 256 << 10, "API-server manifest exceeds bounds")
        # No original private key contents ever leave the node.
        hashes_before = self._old_hashes()
        old_public = self._exec("cat", OLD_PUBLIC)
        require(digest(old_public) == hashes_before[OLD_PUBLIC], "Original public key changed during preparation")
        self.old_public = serialization.load_pem_public_key(old_public)
        old_der = self.old_public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        old_kid = base64.urlsafe_b64encode(hashlib.sha256(old_der).digest()).decode().rstrip("=")
        key = ec.generate_private_key(ec.SECP256R1())
        self.new_public = key.public_key()
        public_der = self.new_public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        kid = base64.urlsafe_b64encode(hashlib.sha256(public_der).digest()).decode().rstrip("=")
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        public = self.new_public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        numbers = self.new_public.public_numbers()
        b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.new_jwk = {"alg": "ES256", "crv": "P-256", "kid": kid, "kty": "EC", "use": "sig",
            "x": b64(numbers.x.to_bytes(32, "big")), "y": b64(numbers.y.to_bytes(32, "big"))}
        suffix = digest(public)[:12]
        new_key, bundle_path = "/etc/kubernetes/pki/sekvyr-stage7-sa-" + suffix + ".key", "/etc/kubernetes/pki/sekvyr-stage7-sa-" + suffix + ".pub"
        bundle = old_public.rstrip() + b"\n" + public
        rotated = changed_manifest(original, new_key, bundle_path)
        restored = changed_manifest(original, OLD_KEY, bundle_path)
        self.plan = {"format": "sekvyr-stage7-kind-jwks-v1", "nodeCID": self.pin["id"], "nodeImage": NODE,
            "originalManifestSHA256": digest(original), "rotatedManifestSHA256": digest(rotated), "restoredManifestSHA256": digest(restored),
            "originalKeyHashes": hashes_before, "oldKid": old_kid, "newKid": kid, "newPublicJWK": self.new_jwk,
            "files": {new_key: digest(private), bundle_path: digest(bundle)},
            "restoreMode": "original-signer-temporary-overlap-verifiers", "exactOriginalManifestRestoreClaimed": False}
        self.key_path, self.bundle_path = new_key, bundle_path
        for name, raw in (("original-manifest.yaml", original), ("rotated-manifest.yaml", rotated), ("restored-overlap-manifest.yaml", restored),
                ("new-key.pem", private), ("public-bundle.pem", bundle), ("plan.json", canonical(self.plan))):
            private_exact(self.root / name, raw)
        # Native backups contain manifest/receipts, NEVER original/new private keys.
        for name, raw in (("original-manifest.yaml", original), ("restored-overlap-manifest.yaml", restored), ("plan.json", canonical(self.plan))):
            private_exact(self.native / (self.task.name + "-jwks-" + name), raw)
        private_exact(self.root / "backup-complete.json", canonical({"nativeCreationReceiptSHA256": digest(self.creation_raw), "planSHA256": digest(canonical(self.plan)), "nativeBackupComplete": True}))
        self.prepared = True
        return {"backupsComplete": True, "originalKeyContentCopied": False, "production": False}

    def _backup_guard(self):
        require(self.prepared and (self.root / "backup-complete.json").is_file(), "Verified backups required before signer mutation")
        require((self.root / "plan.json").read_bytes() == canonical(self.plan), "Signer plan changed")
        for name in ("original-manifest.yaml", "restored-overlap-manifest.yaml", "plan.json"):
            native = self.native / (self.task.name + "-jwks-" + name)
            require(not native.is_symlink() and native.read_bytes() == (self.root / name).read_bytes(), "Independent signer backup changed")
        require(digest((self.root / "original-manifest.yaml").read_bytes()) == self.plan["originalManifestSHA256"]
            and digest((self.root / "restored-overlap-manifest.yaml").read_bytes()) == self.plan["restoredManifestSHA256"], "Signer backup hashes differ")
        self._original_unchanged()

    def _new_files_guard(self):
        raw = self._exec("sha256sum", self.key_path, self.bundle_path).decode("ascii")
        found = {line.split(None, 1)[1]: line.split(None, 1)[0] for line in raw.splitlines()}
        require(found == self.plan["files"], "Created signer material changed")

    def rotate(self):
        require(hasattr(self, "_bound_panel") and hasattr(self, "_bound_meta"), "Authenticated bound-token probe required before rotation")
        self._backup_guard()
        for path, name in ((self.key_path, "new-key.pem"), (self.bundle_path, "public-bundle.pem")):
            self._backup_guard()
            raw = (self.root / name).read_bytes()
            require(digest(raw) == self.plan["files"][path], "Saved signer material changed")
            self._exec("sh", "-c", WRITE_NEW, "stage7-write-new", path, digest(raw), data=raw)
        self._new_files_guard()
        self._replace(self.plan["originalManifestSHA256"], "rotated-manifest.yaml", self.plan["rotatedManifestSHA256"])
        private_exact(self.root / "rotated.json", canonical({"manifestSHA256": self.plan["rotatedManifestSHA256"], "temporaryOverlap": True}))
        return self._wait_ready(new_signer=True)

    def _replace(self, before, name, after):
        self._backup_guard()
        raw = (self.root / name).read_bytes()
        require(digest(raw) == after, "Reviewed signer manifest changed")
        self._exec("sh", "-c", REPLACE_MANIFEST, "stage7-replace-api", before, after, data=raw)
        require(digest(self._exec("cat", MANIFEST)) == after, "API-server manifest replacement unconfirmed")

    def _wait_ready(self, new_signer):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            ready = self.cluster.kube("get", "--raw", "/readyz", "--request-timeout=5s", check=False)
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                response = self.cluster.kube("get", "--raw", "/openid/v1/jwks", "--request-timeout=5s", check=False)
                if response.returncode == 0:
                    jwks = json.loads(response.stdout)
                    if self.plan["newKid"] in public_jwks(jwks):
                        self._known_overlap(jwks)
                        try:
                            self.bound_token(self._bound_panel, self._bound_pod, self.plan["newKid"] if new_signer else self.plan["oldKid"])
                        except RuntimeError:
                            time.sleep(1)
                            continue
                        self._original_unchanged()
                        return jwks
            time.sleep(1)
        raise RuntimeError("Owned API-server signer readiness deadline exceeded")

    def _known_overlap(self, jwks):
        public_jwks(jwks)
        expected = {key["kid"]: key for key in self._previous_jwks["keys"]}
        expected[self.plan["newKid"]] = self.plan["newPublicJWK"]
        require({key["kid"]: key for key in jwks["keys"]} == expected, "Discovery keys differ from independently prepared overlap")

    def bound_token(self, panel_cases, pod_ref, expected_kid=None):
        require(panel_cases is self._bound_panel and pod_ref == self._bound_pod, "Bound token probe context differs")
        meta = self._bound_meta
        cluster = _DeadlineCluster(self.cluster)
        namespace, account = meta["namespace"], meta["service_account"]
        owned = OwnedNamespace(cluster, namespace)
        require(owned.get("ServiceAccount", account)["metadata"]["uid"] == meta["service_account_uid"], "Bound token ServiceAccount replaced")
        require(set(pod_ref) == {"name", "uid"} and isinstance(pod_ref["name"], str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", pod_ref["name"]), "Exact owned Pod name and UID required")
        pod = json.loads(cluster.kube("get", "pod", pod_ref["name"], "-n", namespace, "-o", "json").stdout)
        require(pod["metadata"]["uid"] == pod_ref["uid"] and not pod["metadata"].get("deletionTimestamp")
            and pod["spec"].get("serviceAccountName") == account, "TokenRequest Pod binding changed")
        refs = [ref for ref in pod["metadata"].get("ownerReferences", []) if ref.get("controller") is True and ref.get("kind") == "ReplicaSet"]
        require(len(refs) == 1, "Bound Pod needs one owned Deployment chain")
        replica = json.loads(cluster.kube("get", "replicaset", refs[0]["name"], "-n", namespace, "-o", "json").stdout)
        require(replica["metadata"]["uid"] == refs[0]["uid"], "Bound Pod ReplicaSet replaced")
        refs = [ref for ref in replica["metadata"].get("ownerReferences", []) if ref.get("controller") is True and ref.get("kind") == "Deployment"]
        require(len(refs) == 1 and owned.get("Deployment", refs[0]["name"])["metadata"]["uid"] == refs[0]["uid"], "Bound Pod Deployment is not creation-pinned")
        request = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"audiences": ["sekvyr"], "expirationSeconds": 600,
            "boundObjectRef": {"apiVersion": "v1", "kind": "Pod", "name": pod_ref["name"], "uid": pod_ref["uid"]}}}
        self.guard()
        response = json.loads(cluster.kube("create", "--raw", "/api/v1/namespaces/" + namespace + "/serviceaccounts/" + account + "/token",
            "-f", "-", data=json.dumps(request)).stdout)
        token = response["status"]["token"]
        observed = observe_jwt(token)
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)))
        require(claims.get("aud") == ["sekvyr"] and claims.get("iss") == meta["issuer"], "TokenRequest issuer or audience differs")
        expected_kid = expected_kid or self.plan["newKid"]
        require(expected_kid in (self.plan["newKid"], self.plan["oldKid"]), "Unreviewed signer expectation")
        require(observed["kid"] == expected_kid and observed["pod_uid"] == pod_ref["uid"]
            and observed["namespace"] == namespace and observed["service_account"] == account and observed["service_account_uid"] == meta["service_account_uid"], "Real new-signer TokenRequest binding differs")
        parts = token.split(".")
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        public = self.new_public if expected_kid == self.plan["newKid"] else self.old_public
        message = (parts[0] + "." + parts[1]).encode("ascii")
        try:
            if isinstance(public, ec.EllipticCurvePublicKey):
                require(isinstance(public.curve, ec.SECP256R1) and len(signature) == 64, "Unexpected EC JWT signature")
                public.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")), message, ec.ECDSA(hashes.SHA256()))
            else:
                require(isinstance(public, rsa.RSAPublicKey), "Unsupported original signing key")
                public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise RuntimeError("New TokenRequest signature does not match prepared signer") from None
        return token

    def restore(self):
        self._backup_guard()
        current = digest(self._exec("cat", MANIFEST))
        require(current in (self.plan["originalManifestSHA256"], self.plan["rotatedManifestSHA256"], self.plan["restoredManifestSHA256"]), "Unreviewed API-server manifest; restoration refused")
        if current == self.plan["originalManifestSHA256"]:
            # A failed staging write has not changed the API server. Never
            # require a missing/partially staged unused key to recover it.
            private_exact(self.root / "unmodified.json", canonical({"originalManifestUnchanged": True, "originalKeyHashesUnchanged": True}))
            return
        self._new_files_guard()
        if current != self.plan["restoredManifestSHA256"]:
            self._replace(current, "restored-overlap-manifest.yaml", self.plan["restoredManifestSHA256"])
        self._wait_ready(new_signer=False)
        private_exact(self.root / "restored.json", canonical({"originalSignerRestored": True, "temporaryOverlapVerification": True,
            "exactOriginalManifestRestoreClaimed": False, "originalKeyHashesUnchanged": True, "cleanupByWholeOwnedClusterDeletion": True}))

    def run(self, panel_cases, old_projected_jwt, pod_ref, *, after_control_plane_ready=None):
        """Optionally reconnect a reviewed owned panel transport after restart.

        The callback receives only 'rotated' or 'restored'. It grants no new
        identity/trust, performs no implicit retry and does not waive token or
        cryptographic checks. Callback exceptions retain normal finally rules.
        """
        require(after_control_plane_ready is None or callable(after_control_plane_ready),
            "Explicit control-plane-ready callback must be callable")
        panel_cases.exchange(old_projected_jwt)  # Authenticate before observing claims.
        old = observe_jwt(old_projected_jwt)
        meta = panel_cases.ready()
        require(old["pod_uid"] == pod_ref["uid"] and old["namespace"] == meta["namespace"] and old["service_account"] == meta["service_account"]
            and old["service_account_uid"] == meta["service_account_uid"], "Old projected token is not from the pinned Pod")
        previous = copy.deepcopy(meta["initial_jwks"])
        current_keys = json.loads(self.cluster.kube("get", "--raw", "/openid/v1/jwks", "--request-timeout=5s").stdout)
        require(current_keys == previous, "API-server initial keys differ from the reviewed panel source")
        self.prepare()
        require(old["kid"] == self.plan["oldKid"], "Original projected JWT does not match original key")
        self._bound_panel, self._bound_pod, self._bound_meta = panel_cases, copy.deepcopy(pod_ref), copy.deepcopy(meta)
        self._previous_jwks = previous
        result = None
        try:
            overlap = self.rotate()
            self._known_overlap(overlap)
            new_token = self.bound_token(panel_cases, pod_ref)
            new_only = {"keys": [key for key in overlap["keys"] if key["kid"] == self.plan["newKid"]]}
            if after_control_plane_ready is not None:
                after_control_plane_ready("rotated")
            result = panel_cases.assert_manual_jwks_rollover(old_projected_jwt, new_token, overlap, new_only)
        finally:
            # Keep BOTH verifiers while restoring the original signer. New
            # kubelet-cached tokens remain valid until the owned cluster goes.
            self.restore()
            restore_keys = self.cluster.kube("get", "--raw", "/openid/v1/jwks", "--request-timeout=5s")
            overlap = json.loads(restore_keys.stdout)
            # A staging failure can leave the original manifest untouched.
            if digest(self._exec("cat", MANIFEST)) == self.plan["originalManifestSHA256"]:
                require({key["kid"]: key for key in overlap["keys"]} == {key["kid"]: key for key in previous["keys"]}, "Original discovery keys changed")
            else:
                self._known_overlap(overlap)
            if after_control_plane_ready is not None:
                after_control_plane_ready("restored")
            panel_cases.update_jwks(overlap)
        return dict(result, originalSignerRestored=True, temporaryOverlapVerification=True, originalKeyContentCopied=False,
            exactOriginalManifestRestoreClaimed=False, projectedFileRotationClaimed=False)
