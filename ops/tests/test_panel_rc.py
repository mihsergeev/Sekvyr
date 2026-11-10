"""Regression tests for the reviewed panel RC inputs."""

import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ops import panel_rc as oci, panel_rc_release as release


VERSION = "1.2.3-rc.4"
REVISION = "a" * 40
BRANCH = f"rc/panel-v{VERSION}"


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def native_image(root, *, component="backend", layout="1.0.0", platform="amd64", wrong_diff=False, wrong_sbom=False):
    blobs = {}

    def blob(data, media):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        identifier = sha256(data)
        blobs[identifier] = data
        return {"digest": identifier, "size": len(data), "mediaType": media}

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w"):
        pass
    raw_layer = layer.getvalue()
    diff_id = sha256(raw_layer)
    config = blob({
        "architecture": "amd64",
        "os": "linux",
        "config": {"Labels": {"org.opencontainers.image.title": f"Sekvyr {component}",
                              "org.opencontainers.image.version": VERSION,
                              "org.opencontainers.image.revision": REVISION}},
        "rootfs": {"type": "layers", "diff_ids": [sha256(b"other") if wrong_diff else diff_id]},
    }, oci.CONFIG)
    image = blob({
        "schemaVersion": 2, "mediaType": oci.MANIFEST, "config": config,
        "layers": [blob(gzip.compress(raw_layer), oci.LAYER + "+gzip")],
    }, oci.MANIFEST)
    image["platform"] = {"os": "linux", "architecture": platform}
    files = {
        "index.json": json.dumps({"schemaVersion": 2, "mediaType": oci.INDEX,
                                  "manifests": [image]}).encode(),
        "oci-layout": json.dumps({"imageLayoutVersion": layout}).encode(),
        **{f"blobs/sha256/{name.split(':')[1]}": data for name, data in blobs.items()},
    }
    archive = root / "candidate.oci.tar"
    with tarfile.open(archive, "w") as tar:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    sbom = root / "sbom.cdx.json"
    sbom.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": [{"name": "demo"}],
        "metadata": {"component": {"type": "container", "properties": [
            {"name": "aquasecurity:trivy:ImageID", "value": sha256(b"other") if wrong_sbom else config["digest"]},
            {"name": "aquasecurity:trivy:DiffID", "value": diff_id},
        ]}},
    }), encoding="utf-8")
    (root / "SHA256SUMS").write_text(
        "\n".join(f"{oci.digest(path)}  {path.name}" for path in (archive, sbom)) + "\n", encoding="utf-8",
    )


class NativeArchiveTest(unittest.TestCase):
    def read(self, expected_component="backend", **changes):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            native_image(root, **changes)
            return oci.read_image(root, root / "layout", expected_component, "amd64", VERSION, REVISION)

    def test_accepts_matching_inventory_and_uncompressed_layers(self):
        descriptor, paths, _ = self.read()
        self.assertEqual(descriptor["platform"], {"os": "linux", "architecture": "amd64"})
        self.assertEqual(len(paths), 3)

    def test_rejects_inconsistent_metadata_even_with_matching_archive_checksums(self):
        for changes, error in (
            ({"layout": "2.0.0"}, "layout version"),
            ({"platform": "arm64"}, "descriptor platform"),
            ({"wrong_diff": True}, "uncompressed layer digest"),
            ({"wrong_sbom": True}, "inventory does not match"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, error):
                self.read(**changes)

    def test_rejects_a_valid_image_in_the_other_component_slot(self):
        self.read(expected_component="frontend", component="frontend")
        for expected, actual in (("backend", "frontend"), ("frontend", "backend")):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "wrong image component"):
                self.read(expected_component=expected, component=actual)


class ReleaseInputsTest(unittest.TestCase):
    def test_operator_manifest_binds_chart_and_both_offline_binaries(self):
        repo, version = "example/sekvyr", "0.1.0-rc.2"
        assets = release.operator_files(version)
        self.assertIn(f"sekvyr-operator-{version}.tgz", assets)
        self.assertIn("sekvyr-provision-linux-amd64", assets)
        self.assertIn("sekvyr-provision-linux-arm64", assets)
        manifest = {
            "format": release.OPERATOR_FORMAT, "repository": repo, "version": version, "revision": REVISION,
            "assets": {name: sha256(name.encode()) for name in assets},
            "images": {"operator": release.image_ref(repo, "operator", sha256(b"operator"))},
        }
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / release.MANIFEST
            path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(release.checked_manifest(root, repo, version, REVISION, operator=True), manifest)
            with self.assertRaisesRegex(ValueError, "another release"):
                release.checked_manifest(root, repo, version, REVISION)
            del manifest["assets"]["sekvyr-provision-linux-arm64"]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid signed asset manifest"):
                release.checked_manifest(root, repo, version, REVISION, operator=True)

    def test_candidate_artifacts_from_one_attempt(self):
        names = ["backend-amd64", "backend-arm64", "frontend-amd64"]
        items = [
            {"name": f"{name}-attempt-{attempt}", "id": i, "digest": sha256(str(i).encode()),
             "expired": False, "workflow_run": {"id": 12, "head_branch": BRANCH, "head_sha": REVISION}}
            for i, (name, attempt) in enumerate(((n, a) for a in (1, 2) for n in names), 1)
        ]

        def select(artifacts):
            return release.candidate_artifacts([{"artifacts": artifacts}], BRANCH, REVISION, 12, 2)

        self.assertEqual({a["id"] for a in select(items).values()}, {4, 5, 6})
        with self.assertRaisesRegex(ValueError, "exactly one"):
            select(items[:-1])
        with self.assertRaisesRegex(ValueError, "exactly one"):
            select([*items, items[-1]])
        wrong_run = copy.deepcopy(items)
        wrong_run[-1]["workflow_run"]["id"] = 999
        with self.assertRaisesRegex(ValueError, "invalid artifact metadata"):
            select(wrong_run)

    def test_reviewed_draft_is_a_retry_source_and_rejects_replacements(self):
        repo = "example/sekvyr"
        payloads = {name: name.encode() for name in release.FILES}
        payloads[release.MANIFEST] = json.dumps({
            "format": release.FORMAT, "repository": repo, "version": VERSION, "revision": REVISION,
            "assets": {name: sha256(data) for name, data in payloads.items()},
            "images": {name: release.image_ref(repo, name, sha256(name.encode())) for name in oci.PLATFORMS},
        }).encode()
        payloads[release.BUNDLE] = b"demo bundle"
        ids = dict(enumerate(sorted(payloads), 1))
        draft = {
            "id": 11, "tag_name": f"v{VERSION}", "prerelease": True, "draft": True,
            "assets": [{"id": asset_id, "state": "uploaded", "name": name} for asset_id, name in ids.items()],
        }
        manifest_hash = sha256(payloads[release.MANIFEST]).split(":")[1]

        def download(_repo, endpoint, path):
            path.write_bytes(payloads[ids[int(endpoint.rsplit("/", 1)[1])]])

        with TemporaryDirectory() as directory, patch.object(release, "api", return_value=draft) as api, \
                patch.object(release, "download", side_effect=download), patch.object(release.subprocess, "run") as verify:
            root = Path(directory)
            for attempt in range(2):
                output = root / str(attempt)
                release.reviewed(repo, VERSION, REVISION, 11, manifest_hash, output)
                self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, payloads)
            self.assertTrue(all(call.args == (repo, "releases/11") for call in api.call_args_list))
            self.assertEqual(verify.call_count, 2)
            self.assertIn("--source-ref", verify.call_args.args[0])

            with self.assertRaisesRegex(ValueError, "reviewed copy"):
                release.reviewed(repo, VERSION, REVISION, 11, "f" * 64, root / "replaced-manifest")
            payloads["frontend-image.oci.tar"] = b"substituted"
            with self.assertRaisesRegex(ValueError, "asset digest mismatch"):
                release.reviewed(repo, VERSION, REVISION, 11, manifest_hash, root / "replaced-image")


if __name__ == "__main__":
    unittest.main()
