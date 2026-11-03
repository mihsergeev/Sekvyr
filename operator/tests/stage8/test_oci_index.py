"""Security guards for local OCI assembly and one-pointer SBOM normalization."""
import hashlib
import io
import json
from pathlib import Path
import os
import tarfile
import tempfile
import unittest
from unittest import mock

from stage8 import oci_index as subject


VERSION = "1.2.3-rc.1"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def member(tar, name, data, kind=tarfile.REGTYPE):
    item = tarfile.TarInfo(name)
    item.type = kind
    item.mode = 0o644
    if kind == tarfile.REGTYPE:
        item.size = len(data)
        tar.addfile(item, io.BytesIO(data))
    else:
        item.linkname = "../../outside"
        tar.addfile(item)


def fixture(parent, architecture, *, config_arch=None, version=VERSION,
            revision="", mutate=None):
    directory = parent / architecture
    directory.mkdir()
    layer_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_stream, mode="w") as tar:
        member(tar, "public.txt", architecture.encode())
    layer = layer_stream.getvalue()
    config = subject.canonical({"os": "linux", "architecture": config_arch or architecture,
        "config": {"Labels": {"org.opencontainers.image.version": version,
                               "org.opencontainers.image.revision": revision}}})
    blobs = {digest(config): config, digest(layer): layer}
    manifest = subject.canonical({"schemaVersion": 2, "mediaType": subject.MANIFEST,
        "config": {"mediaType": subject.CONFIG, "digest": digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": digest(layer), "size": len(layer)}]})
    blobs[digest(manifest)] = manifest
    descriptor = {"mediaType": subject.MANIFEST, "digest": digest(manifest),
                  "size": len(manifest), "platform": {"os": "linux", "architecture": architecture}}
    discovery = {"schemaVersion": 2, "mediaType": subject.INDEX, "manifests": [descriptor]}
    entries = {"oci-layout": subject.canonical({"imageLayoutVersion": "1.0.0"}),
               "index.json": subject.canonical(discovery)}
    entries.update({"blobs/sha256/" + key.split(":")[1]: value for key, value in blobs.items()})
    if mutate:
        mutate(entries, discovery, descriptor, blobs)
    archive = directory / "image.tar"
    with tarfile.open(archive, "w") as tar:
        for name, data in entries.items():
            member(tar, name, data)
    config_digest = digest(config)
    private_name = "/private-build/run/" + architecture + ".oci"
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"bom-ref": "image-" + architecture, "type": "container",
             "name": private_name, "properties": [{"name": "aquasecurity:trivy:ImageID",
                                                     "value": config_digest}]}},
        "components": [{"bom-ref": "package", "type": "library", "name": "public-fixture"}],
        "dependencies": [{"ref": "image-" + architecture, "dependsOn": ["package"]},
                         {"ref": "package", "dependsOn": []}]}
    sbom_path = directory / "raw.cdx.json"
    sbom_path.write_bytes(subject.canonical(sbom))
    return {"path": archive, "archive_sha256": subject.file_sha(archive),
            "manifest_digest": digest(manifest)}, {
                "path": sbom_path, "sha256": subject.file_sha(sbom_path),
                "private_name": private_name, "private_root_prefix": "/private-build/run"}


class OCIIndexGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oci-guard-")
        self.root = Path(self.temporary.name).resolve()
        self.images = {}
        self.sboms = {}
        for architecture in ("amd64", "arm64"):
            self.images[architecture], self.sboms[architecture] = fixture(self.root, architecture)

    def tearDown(self):
        self.temporary.cleanup()

    def arguments(self, output="assembled"):
        validation = {architecture: {"scanJSONSHA256": "1" * 64, "databaseSHA256": "2" * 64,
            "runtimeReceiptSHA256": "3" * 64, "privacyReceiptSHA256": "4" * 64,
            "severityCounts": dict.fromkeys(("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"), 0),
            "includeUnfixed": True, "ignoredFindings": False} for architecture in self.images}
        return {"images": self.images, "sboms": self.sboms, "component": "operator",
            "version": VERSION, "source_content_sha256": "a" * 64,
            "dockerfile_sha256": "b" * 64, "toolchain_versions": {"go": "1.27.3", "buildkit": "0.34.1"},
            "official_base_digests": ["sha256:" + "c" * 64], "validation": validation,
            "reference_name": "example/operator:" + VERSION, "output": self.root / output}

    def rejected(self, arguments):
        with self.assertRaises(ValueError):
            subject.assemble(**arguments)
        self.assertFalse(Path(arguments["output"]).exists())

    def rewrite_archive(self, architecture, change):
        path = self.images[architecture]["path"]
        with tarfile.open(path) as tar:
            entries = [(item.name, tar.extractfile(item).read()) for item in tar]
        entries = change(entries)
        with tarfile.open(path, "w") as tar:
            for item in entries:
                member(tar, *item)
        self.images[architecture]["archive_sha256"] = subject.file_sha(path)

    def test_exact_two_children_and_deterministic_unsigned_bundle(self):
        first = subject.assemble(**self.arguments())
        second = subject.assemble(**self.arguments("again"))
        self.assertEqual(first, second)
        self.assertFalse(first["signed"])
        self.assertFalse(first["SLSAClaim"])
        self.assertFalse(first["registryWrites"])
        self.assertFalse(first["nativeARMHardwareClaim"])
        layout = self.root / "assembled/layout"
        discovery = json.loads((layout / "index.json").read_bytes())
        self.assertEqual(len(discovery["manifests"]), 1)
        self.assertEqual(discovery["manifests"][0]["digest"], first["imageIndexDigest"])
        index = json.loads((layout / "blobs/sha256" / first["imageIndexDigest"].split(":")[1]).read_bytes())
        self.assertEqual([item["platform"]["architecture"] for item in index["manifests"]], ["amd64", "arm64"])
        self.assertEqual([item["digest"] for item in index["manifests"]],
                         [self.images[key]["manifest_digest"] for key in ("amd64", "arm64")])
        for architecture in ("amd64", "arm64"):
            old = json.loads(self.sboms[architecture]["path"].read_bytes())
            new = json.loads((self.root / ("assembled/sbom-linux-" + architecture + ".cdx.json")).read_bytes())
            self.assertEqual(subject.semantic_changes(old, new), ["/metadata/component/name"])
            self.assertEqual(old["dependencies"], new["dependencies"])
        self.assertNotIn(b"/private-build", (self.root / "assembled/provenance.json").read_bytes())

    def test_wrong_archive_sha(self):
        self.images["amd64"]["archive_sha256"] = "0" * 64
        self.rejected(self.arguments())

    def test_wrong_measured_manifest(self):
        self.images["amd64"]["manifest_digest"] = "sha256:" + "0" * 64
        self.rejected(self.arguments())

    def test_wrong_actual_platform(self):
        extra = self.root / "different"
        extra.mkdir()
        self.images["arm64"], self.sboms["arm64"] = fixture(extra, "arm64", config_arch="amd64")
        self.rejected(self.arguments())

    def test_external_descriptor_url(self):
        def change(entries):
            root = json.loads(dict(entries)["index.json"])
            root["manifests"][0]["urls"] = ["https://registry.example.invalid/blob"]
            return [(name, subject.canonical(root) if name == "index.json" else data) for name, data in entries]
        self.rewrite_archive("amd64", change)
        self.rejected(self.arguments())

    def test_extra_named_reference(self):
        def change(entries):
            root = json.loads(dict(entries)["index.json"])
            root["manifests"].append(dict(root["manifests"][0], annotations={"org.opencontainers.image.ref.name": "other/image:tag"}))
            return [(name, subject.canonical(root) if name == "index.json" else data) for name, data in entries]
        self.rewrite_archive("amd64", change)
        self.rejected(self.arguments())

    def test_tampered_blob_after_whole_archive_pin_updated(self):
        def change(entries):
            key = next(name for name, _ in entries if name.startswith("blobs/sha256/"))
            return [(name, b"tampered" if name == key else data) for name, data in entries]
        self.rewrite_archive("amd64", change)
        self.rejected(self.arguments())

    def test_unreachable_blob(self):
        self.rewrite_archive("amd64", lambda entries: entries + [("blobs/sha256/" + hashlib.sha256(b"extra").hexdigest(), b"extra")])
        self.rejected(self.arguments())

    def test_path_traversal(self):
        self.rewrite_archive("amd64", lambda entries: entries + [("../../outside", b"data")])
        self.rejected(self.arguments())

    def test_link_entry(self):
        self.rewrite_archive("amd64", lambda entries: entries + [("blobs/sha256/" + "0" * 64, b"", tarfile.SYMTYPE)])
        self.rejected(self.arguments())

    def test_duplicate_archive_entry(self):
        self.rewrite_archive("amd64", lambda entries: entries + [entries[0]])
        self.rejected(self.arguments())

    def test_wrong_version_and_revision(self):
        for version, revision in (("9.9.9-rc.1", ""), (VERSION, "unreviewed")):
            extra = self.root / ("case" + str(len(list(self.root.iterdir()))))
            extra.mkdir()
            self.images["arm64"], self.sboms["arm64"] = fixture(extra, "arm64", version=version, revision=revision)
            self.rejected(self.arguments())

    def test_high_findings_and_ignored_unfixed_block_assembly(self):
        for key, value in (("ignoredFindings", True), ("includeUnfixed", False)):
            args = self.arguments()
            args["validation"]["amd64"][key] = value
            self.rejected(args)
        args = self.arguments()
        args["validation"]["amd64"]["severityCounts"]["HIGH"] = 1
        self.rejected(args)

    def test_private_path_elsewhere_in_graph_blocks_normalization(self):
        path = self.sboms["amd64"]["path"]
        value = json.loads(path.read_bytes())
        value["components"][0]["name"] = "/private-build/run/hidden"
        path.write_bytes(subject.canonical(value))
        self.sboms["amd64"]["sha256"] = subject.file_sha(path)
        self.rejected(self.arguments())

    def test_sbom_config_binding(self):
        path = self.sboms["amd64"]["path"]
        value = json.loads(path.read_bytes())
        value["metadata"]["component"]["properties"][0]["value"] = "sha256:" + "0" * 64
        path.write_bytes(subject.canonical(value))
        self.sboms["amd64"]["sha256"] = subject.file_sha(path)
        self.rejected(self.arguments())

    def test_existing_output_is_never_adopted(self):
        output = self.root / "assembled"
        output.mkdir()
        marker = output / "marker"
        marker.write_bytes(b"preserve")
        with self.assertRaises(ValueError):
            subject.assemble(**self.arguments())
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_exact_architecture_set(self):
        args = self.arguments()
        args["images"] = {"amd64": self.images["amd64"]}
        self.rejected(args)

    def test_duplicate_json_keys(self):
        with self.assertRaises(ValueError):
            subject.strict_json(b'{"same":1,"same":2}')

    def test_fd_identity_detects_in_place_mutation(self):
        path = self.sboms["amd64"]["path"]
        stream, identity = subject.open_bounded(path, 8 << 20)
        try:
            path.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                subject.assert_unchanged(path, stream, identity)
        finally:
            stream.close()

    def test_hardlinked_input_is_rejected(self):
        path = self.sboms["amd64"]["path"]
        os.link(path, self.root / "extra-link")
        with self.assertRaises(ValueError):
            subject.read_verified_file(path, self.sboms["amd64"]["sha256"], 8 << 20)

    def test_size_limit_precedes_sbom_read(self):
        path = self.sboms["amd64"]["path"]
        path.write_bytes(b" " * ((8 << 20) + 1))
        self.sboms["amd64"]["sha256"] = subject.file_sha(path)
        self.rejected(self.arguments())

    def test_excess_archive_entries_are_rejected(self):
        extras = [("blobs/sha256/" + f"{i:064x}", b"") for i in range(1024)]
        self.rewrite_archive("amd64", lambda entries: entries + extras)
        self.rejected(self.arguments())

    def test_raced_open_rejects_replaced_inode_before_read(self):
        path = self.sboms["amd64"]["path"]
        original_open = os.open

        def replace_then_open(target, flags):
            self.assertEqual(Path(target), path)
            path.unlink()
            if hasattr(os, "mkfifo"):
                self.assertTrue(flags & os.O_NONBLOCK)
                os.mkfifo(path)
            else:
                path.write_bytes(b"replacement")
            return original_open(target, flags)

        with mock.patch.object(subject.os, "open", side_effect=replace_then_open):
            with self.assertRaises(ValueError):
                subject.open_bounded(path, 8 << 20)


if __name__ == "__main__":
    unittest.main()
