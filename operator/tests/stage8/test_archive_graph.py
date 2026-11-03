"""OCI archives generated in memory; no registry or container runtime calls."""

import gzip
import io
import json
import tarfile
import unittest

from stage8 import archive_graph as g


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def blob(files, media, raw, **extra):
    digest = g.sha(raw)
    files["blobs/sha256/" + digest[7:]] = raw
    return {"mediaType": media, "digest": digest, "size": len(raw), **extra}


def fixture_image(files, architecture):
    layer_raw = b"\0" * 1024  # Empty tar layer.
    layer = blob(files, "application/vnd.oci.image.layer.v1.tar+gzip", gzip.compress(layer_raw, mtime=0))
    config = blob(files, g.CONFIG, encode({"os": "linux", "architecture": architecture,
        "rootfs": {"type": "layers", "diff_ids": [g.sha(layer_raw)]}}))
    image = blob(files, g.MANIFEST, encode({"schemaVersion": 2, "mediaType": g.MANIFEST,
        "config": config, "layers": [layer]}), platform={"os": "linux", "architecture": architecture})
    return image, config, layer


def discovery(files, *roots):
    files["index.json"] = encode({"schemaVersion": 2, "mediaType": g.INDEX, "manifests": roots})


def tar_bytes(files, special=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        for member in special:
            archive.addfile(member)
    return buffer.getvalue()


def fixture_archive(*, nested=False, partial=False, legacy_manifest=False):
    files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}'}
    amd, config, layer = fixture_image(files, "amd64")
    arm = None
    root = amd
    if nested:
        arm, _, _ = fixture_image({} if partial else files, "arm64")
        root = blob(files, g.INDEX, encode({"schemaVersion": 2, "mediaType": g.INDEX,
            "manifests": [amd, arm]}))
    discovery(files, dict(root, annotations={"org.opencontainers.image.ref.name": "reviewed:trial"}))
    if legacy_manifest:
        files["manifest.json"] = encode([{"Config": "blobs/sha256/" + config["digest"][7:],
            "RepoTags": ["example.invalid/public:trial", "example.invalid/public:another-tag"],
            "Layers": ["blobs/sha256/" + layer["digest"][7:]]}])
    return files, root, amd, arm


class ArchiveGraphTests(unittest.TestCase):
    def validate(self, files, root, amd, **options):
        return g.validate(tar_bytes(files), root["digest"], amd["digest"], **options)

    def test_direct_and_nested_rc_images(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                files, root, amd, _ = fixture_archive(nested=nested)
                self.assertEqual(self.validate(files, root, amd), g.sha(files["index.json"]))

    def test_legacy_partial_index_and_same_image_multiple_tags(self):
        files, root, amd, _ = fixture_archive(nested=True, partial=True, legacy_manifest=True)
        self.assertEqual(self.validate(files, root, amd, allow_legacy=True), g.sha(files["index.json"]))
        with self.assertRaisesRegex(RuntimeError, "Required OCI blob is missing"):
            self.validate(files, root, amd)
        files.pop("blobs/sha256/" + amd["digest"][7:])
        with self.assertRaisesRegex(RuntimeError, "Required OCI blob is missing"):
            self.validate(files, root, amd, allow_legacy=True)

    def test_legacy_cannot_infer_missing_platform(self):
        files, _, amd, arm = fixture_archive(nested=True, partial=True)
        del arm["platform"]
        root = blob(files, g.INDEX, encode({"schemaVersion": 2, "manifests": [amd, arm]}))
        discovery(files, root)
        with self.assertRaisesRegex(RuntimeError, "Required OCI blob is missing"):
            self.validate(files, root, amd, allow_legacy=True)

    def test_containerd_legacy_digest_alias_is_bound_to_discovery_root(self):
        files, root, amd, _ = fixture_archive(nested=True)
        short, full = "org.opencontainers.image.ref.name", "io.containerd.image.name"
        names = {short: "@" + root["digest"], full: "example.invalid/public@" + root["digest"]}
        discovery(files, dict(root, annotations=names))
        self.validate(files, root, amd, allow_legacy=True)
        with self.assertRaisesRegex(RuntimeError, "named OCI reference"):
            self.validate(files, root, amd)
        for invalid in ({short: names[short]}, dict(names, **{short: "@" + amd["digest"]}),
                dict(names, **{full: "example.invalid/public@" + amd["digest"]})):
            discovery(files, dict(root, annotations=invalid))
            with self.assertRaisesRegex(RuntimeError, "named OCI reference"):
                self.validate(files, root, amd, allow_legacy=True)

    def test_wrong_receipt_and_wrong_discovery_pin(self):
        files, root, amd, arm = fixture_archive(nested=True)
        with self.assertRaisesRegex(RuntimeError, "linux/amd64 OCI manifest differs"):
            self.validate(files, root, arm)
        with self.assertRaisesRegex(RuntimeError, "discovery root differs"):
            self.validate(files, arm, amd)

    def test_extra_outer_root_even_with_valid_digest_is_denied(self):
        files, root, amd, arm = fixture_archive(nested=True)
        discovery(files, root, dict(arm, annotations={"io.containerd.image.name": "unreviewed:trial"}))
        with self.assertRaisesRegex(RuntimeError, "Exactly one OCI discovery root"):
            self.validate(files, root, amd)

    def test_named_nested_root_is_denied(self):
        files, _, amd, _ = fixture_archive()
        root = blob(files, g.INDEX, encode({"schemaVersion": 2, "manifests": [
            dict(amd, annotations={"io.containerd.image.name": "unreviewed:trial"})]}))
        discovery(files, root)
        for allow_legacy in (False, True):
            with self.assertRaisesRegex(RuntimeError, "nested named"):
                self.validate(files, root, amd, allow_legacy=allow_legacy)

    def test_two_amd_descriptors_are_ambiguous_even_if_identical(self):
        files, _, amd, _ = fixture_archive()
        root = blob(files, g.INDEX, encode({"schemaVersion": 2, "manifests": [amd, amd]}))
        discovery(files, root)
        with self.assertRaisesRegex(RuntimeError, "Repeated OCI image or index descriptor"):
            self.validate(files, root, amd)

    def test_all_blobs_are_hashed_and_reachable_including_unselected(self):
        files, root, amd, arm = fixture_archive(nested=True)
        arm_path = "blobs/sha256/" + arm["digest"][7:]
        files[arm_path] += b" "
        with self.assertRaisesRegex(RuntimeError, "blob checksum differs"):
            self.validate(files, root, amd, allow_legacy=True)
        files, root, amd, _ = fixture_archive(nested=True)
        blob(files, g.CONFIG, b"orphan")
        with self.assertRaisesRegex(RuntimeError, "Unreferenced OCI archive member"):
            self.validate(files, root, amd)

    def test_descriptor_size_type_and_platform_must_match(self):
        for field, value, reason in (("size", 1, "size differs"), ("size", True, "Invalid OCI descriptor"),
                ("platform", {"os": "linux", "architecture": "arm64"}, "config platform differs"),
                ("platform", {"os": "linux", "architecture": "x86_64"}, "Invalid OCI platform"),
                ("platform", {"os": "linux", "architecture": "amd64", "variant": "v3"}, "Unsupported linux/amd64 variant"),
                ("urls", ["https://example.invalid/untrusted"], "Invalid OCI descriptor")):
            files, root, amd, _ = fixture_archive()
            discovery(files, dict(root, **{field: value}))
            with self.subTest(field=field, value=value), self.assertRaisesRegex(RuntimeError, reason):
                self.validate(files, root, amd)

    def test_legacy_manifest_must_match_single_selected_config_and_layers(self):
        for edit, reason in ((lambda rows: rows.append(rows[0]), "describe one image"),
                (lambda rows: rows[0].update(Config=rows[0]["Layers"][0]), "differs from selected OCI image"),
                (lambda rows: rows[0].update(Layers=[]), "differs from selected OCI image"),
                (lambda rows: rows[0].update(Layers=["../layer"]), "differs from selected OCI image")):
            files, root, amd, _ = fixture_archive(legacy_manifest=True)
            value = json.loads(files["manifest.json"])
            edit(value)
            files["manifest.json"] = encode(value)
            with self.assertRaisesRegex(RuntimeError, reason):
                self.validate(files, root, amd, allow_legacy=True)

    def test_special_paths_and_hidden_concatenation_are_denied(self):
        files, root, amd, _ = fixture_archive()
        for name in ("../escape", "/absolute", "blobs//double", "blobs\\alternate"):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "OCI archive path"):
                self.validate(dict(files, **{name: b"data"}), root, amd)
        link = tarfile.TarInfo("link")
        link.type, link.linkname = tarfile.SYMTYPE, "index.json"
        with self.assertRaisesRegex(RuntimeError, "Unsupported OCI tar entry"):
            g.validate(tar_bytes(files, (link,)), root["digest"], amd["digest"])
        duplicate = tarfile.TarInfo("index.json")
        with self.assertRaisesRegex(RuntimeError, "OCI archive path"):
            g.validate(tar_bytes(files, (duplicate,)), root["digest"], amd["digest"])
        with self.assertRaisesRegex(RuntimeError, "OCI tar trailer"):
            g.validate(tar_bytes(files) * 2, root["digest"], amd["digest"])

    def test_strict_metadata_and_no_path_in_errors(self):
        files, root, amd, _ = fixture_archive()
        files["index.json"] = b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}'
        with self.assertRaisesRegex(RuntimeError, "Duplicate OCI metadata field"):
            self.validate(files, root, amd)
        files["index.json"] = b"untrusted-secret-like-marker"
        with self.assertRaisesRegex(RuntimeError, "^Malformed OCI archive$"):
            self.validate(files, root, amd)


if __name__ == "__main__":
    unittest.main()
