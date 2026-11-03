"""Assemble two already verified OCI image manifests without rebuilding them.

This module performs no network, registry, Docker or Kubernetes operations.
Callers supply measured archive/manifest hashes and reviewed source provenance.
The output directory must not exist. A discovery index points to one image index;
that image index contains exactly the unchanged linux/amd64 and linux/arm64 images.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import NamedTuple


INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYERS = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
}
SHA = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_BLOB = 1 << 30
MAX_ARCHIVE = 4 << 30


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def strict_json(data):
    require(len(data) <= 8 << 20, "OCI JSON exceeds limit")

    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "Duplicate OCI JSON field")
            out[key] = value
        return out

    def constant(_):
        raise ValueError("Non-finite OCI JSON value")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def regular(path):
    path = Path(path)
    require(path.is_absolute(), "Input path must be absolute")
    require(path.is_file() and not path.is_symlink(), "Input must be a regular file")
    require(path.resolve() == path.absolute(), "Input path traverses a symlink")
    return path


def file_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class ReadIdentity(NamedTuple):
    path_stat: os.stat_result
    fd_stat: os.stat_result

    @property
    def st_size(self):
        return self.path_stat.st_size


def open_bounded(path, limit):
    """Open one owned regular inode; do not follow links or read before bounds."""
    require(type(limit) is int and limit > 0, "Invalid file read limit")
    path = regular(path)
    before = path.lstat()
    uid = os.geteuid() if hasattr(os, "geteuid") else 0
    require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, uid),
            "Input is not an owned regular file")
    require(before.st_nlink == 1, "Hardlinked input is forbidden")
    require(0 <= before.st_size <= limit, "Input file exceeds limit")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        current = os.fstat(fd)
        # Windows Python versions expose different ctime semantics through
        # pathname and FD APIs. Anchor each clock separately; retain exact
        # cross-API ctime equality on POSIX and all other inode fields everywhere.
        left, right = file_identity(current), file_identity(before)
        require(left[:-1] == right[:-1] if os.name == "nt" else left == right,
                "Input inode changed while opening")
        require(file_identity(path.lstat()) == file_identity(before), "Input path changed while opening")
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    return stream, ReadIdentity(before, current)


def assert_unchanged(path, stream, identity):
    require(file_identity(os.fstat(stream.fileno())) == file_identity(identity.fd_stat),
            "Input inode changed while reading")
    require(file_identity(Path(path).lstat()) == file_identity(identity.path_stat),
            "Input path changed while reading")


def read_verified_file(path, expected_sha256, limit):
    """Bounded FD read with owner, inode, ctime, nlink and exact SHA checks."""
    require(SHA.fullmatch(expected_sha256 or ""), "Expected file SHA is required")
    stream, identity = open_bounded(path, limit)
    with stream:
        data = stream.read(identity.st_size + 1)
        require(len(data) == identity.st_size, "Input file size changed while reading")
        assert_unchanged(path, stream, identity)
        require(hashlib.sha256(data).hexdigest() == expected_sha256, "Input file SHA differs")
        return data


def file_sha(path):
    digest = hashlib.sha256()
    stream, identity = open_bounded(path, MAX_ARCHIVE)
    with stream:
        remaining = identity.st_size
        while remaining:
            block = stream.read(min(1 << 20, remaining))
            require(bool(block), "Input file became truncated")
            digest.update(block)
            remaining -= len(block)
        require(stream.read(1) == b"", "Input file grew while hashing")
        assert_unchanged(path, stream, identity)
    return digest.hexdigest()


def validate_descriptor(descriptor, media_type):
    require(isinstance(descriptor, dict), "Invalid OCI descriptor")
    require(descriptor.get("mediaType") == media_type, "Unexpected OCI media type")
    require(DIGEST.fullmatch(descriptor.get("digest", "")), "Invalid OCI digest")
    size = descriptor.get("size")
    require(type(size) is int and 0 < size <= MAX_BLOB, "Invalid OCI blob size")
    require(not any(key in descriptor for key in ("urls", "data")),
            "External or inline OCI content is forbidden")


class VerifiedImage:
    """Hold the exact input archive open while its verified blobs are copied."""

    def __init__(self, path, archive_sha256, manifest_digest, architecture, version):
        self.stream = self.tar = None
        try:
            self._initialize(path, archive_sha256, manifest_digest, architecture, version)
        except BaseException:
            self.close()
            raise

    def _initialize(self, path, archive_sha256, manifest_digest, architecture, version):
        require(SHA.fullmatch(archive_sha256 or ""), "Expected archive SHA is required")
        require(DIGEST.fullmatch(manifest_digest or ""), "Expected manifest digest is required")
        require(architecture in ("amd64", "arm64"), "Architecture is not allowed")
        self.path = regular(path)
        require(self.path.stat().st_size <= MAX_ARCHIVE, "OCI archive exceeds limit")
        self.stream, self.identity = open_bounded(self.path, MAX_ARCHIVE)
        digest = hashlib.sha256()
        remaining = self.identity.st_size
        while remaining:
            block = self.stream.read(min(1 << 20, remaining))
            require(bool(block), "Input archive became truncated")
            digest.update(block)
            remaining -= len(block)
        require(self.stream.read(1) == b"", "Input archive grew while hashing")
        self.unchanged()
        require(digest.hexdigest() == archive_sha256, "Input archive SHA differs")
        self.stream.seek(0)
        self.tar = tarfile.open(fileobj=self.stream, mode="r:")
        self.architecture = architecture
        self.archive_sha256 = archive_sha256
        members = []
        for member in self.tar:
            require(len(members) < 1024, "Too many OCI archive entries")
            members.append(member)
        require(len({item.name for item in members}) == len(members), "Duplicate OCI archive entry")
        require(sum(item.size for item in members) <= MAX_ARCHIVE, "OCI content exceeds limit")
        self.files = {}
        for member in members:
            name = member.name
            require(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
                    "Unsafe OCI archive path")
            allowed = name in ("oci-layout", "index.json", "blobs", "blobs/sha256")
            allowed = allowed or bool(re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name))
            require(allowed, "Unexpected OCI archive path")
            require(member.isdir() or member.isfile(), "OCI links and special entries are forbidden")
            require(member.isdir() == (name in ("blobs", "blobs/sha256")),
                    "Unexpected OCI entry type")
            if member.isfile():
                require(member.size <= MAX_BLOB, "OCI blob exceeds limit")
                self.files[name] = member
        require(strict_json(self.read("oci-layout")) == {"imageLayoutVersion": "1.0.0"},
                "Unexpected OCI layout version")
        discovery = strict_json(self.read("index.json"))
        require(isinstance(discovery, dict), "Invalid discovery index")
        require(discovery.get("schemaVersion") == 2 and discovery.get("mediaType") == INDEX,
                "Invalid discovery index schema")
        children = discovery.get("manifests")
        require(isinstance(children, list) and len(children) == 1,
                "Each input must contain exactly one image manifest")
        descriptor = children[0]
        validate_descriptor(descriptor, MANIFEST)
        require(descriptor["digest"] == manifest_digest, "Input manifest differs from measured pin")
        platform = descriptor.get("platform")
        if platform is not None:
            require(platform.get("os") == "linux" and platform.get("architecture") == architecture,
                    "Input descriptor platform differs")
            require(not platform.get("variant") or architecture == "arm64" and platform["variant"] == "v8",
                    "Unexpected platform variant")
        manifest = strict_json(self.blob(descriptor))
        require(isinstance(manifest, dict), "Invalid image manifest")
        require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") == MANIFEST,
                "Input is not a direct OCI image manifest")
        require("subject" not in manifest and "artifactType" not in manifest,
                "Input must be an image, not a referrer")
        validate_descriptor(manifest.get("config"), CONFIG)
        config = strict_json(self.blob(manifest["config"]))
        require(isinstance(config, dict), "Invalid image config")
        require(config.get("architecture") == architecture and config.get("os") == "linux",
                "Actual image config platform differs")
        require(not config.get("variant") or architecture == "arm64" and config["variant"] == "v8",
                "Actual image config variant differs")
        labels = config.get("config", {}).get("Labels", {})
        require(labels.get("org.opencontainers.image.version") == version, "Actual version label differs")
        require(labels.get("org.opencontainers.image.revision", "") == "", "Dirty candidate must not claim a revision")
        layers = manifest.get("layers")
        require(isinstance(layers, list) and len(layers) <= 256, "Invalid image layer list")
        descriptors = [descriptor, manifest["config"]]
        for layer in layers:
            require(isinstance(layer, dict) and layer.get("mediaType") in LAYERS, "Unsupported image layer")
            validate_descriptor(layer, layer["mediaType"])
            self.blob(layer)
            descriptors.append(layer)
        self.descriptors = {item["digest"]: item for item in descriptors}
        actual_names = {name for name in self.files if name.startswith("blobs/sha256/")}
        require(actual_names == {"blobs/sha256/" + key.split(":")[1] for key in self.descriptors},
                "Unreachable OCI blob is forbidden")
        self.manifest_digest = manifest_digest
        self.config_digest = manifest["config"]["digest"]
        self.layer_digests = [item["digest"] for item in layers]
        self.output_descriptor = {
            "mediaType": MANIFEST, "digest": manifest_digest, "size": descriptor["size"],
            "platform": {"os": "linux", "architecture": architecture},
        }
        if config.get("variant"):
            self.output_descriptor["platform"]["variant"] = config["variant"]

    def read(self, name, limit=MAX_BLOB):
        require(name in self.files, "Referenced OCI file is missing")
        require(self.files[name].size <= limit, "Referenced OCI file exceeds limit")
        with self.tar.extractfile(self.files[name]) as stream:
            data = stream.read(self.files[name].size + 1)
        require(len(data) == self.files[name].size, "Referenced OCI file became truncated")
        return data

    def blob(self, descriptor):
        limit = 8 << 20 if descriptor["mediaType"] in (MANIFEST, CONFIG) else MAX_BLOB
        data = self.read("blobs/sha256/" + descriptor["digest"].split(":")[1], limit)
        require(len(data) == descriptor["size"], "OCI blob size differs")
        require(hashlib.sha256(data).hexdigest() == descriptor["digest"].split(":")[1],
                "OCI blob SHA differs")
        return data

    def unchanged(self):
        assert_unchanged(self.path, self.stream, self.identity)

    def close(self):
        if self.tar is not None:
            self.tar.close()
        if self.stream is not None:
            self.stream.close()


def write_once(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def semantic_changes(before, after, pointer=""):
    """Return exact JSON pointers; preserve graph identifiers and all values."""
    if type(before) is not type(after):
        return [pointer]
    if isinstance(before, dict):
        if before.keys() != after.keys():
            return [pointer]
        return [change for key in before for change in semantic_changes(
            before[key], after[key], pointer + "/" + key.replace("~", "~0").replace("/", "~1"))]
    if isinstance(before, list):
        if len(before) != len(after):
            return [pointer]
        return [change for index, item in enumerate(before) for change in semantic_changes(
            item, after[index], pointer + "/" + str(index))]
    return [] if before == after else [pointer]


def normalize_sbom(*, path, sha256, private_name, private_root_prefix,
                   public_child_reference, expected_config_digest):
    """Change one explicitly reviewed artifact-name field; never scrub a graph.

    Returns public bytes and a receipt containing no previous private name/path.
    The caller must still privacy-audit the whole output before publication.
    """
    require(SHA.fullmatch(sha256 or ""), "Expected SBOM SHA is required")
    require(DIGEST.fullmatch(expected_config_digest or ""), "Expected image config pin is required")
    require(bool(re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}",
                             public_child_reference)), "Public child reference is required")
    require(isinstance(private_root_prefix, str) and private_root_prefix.startswith("/") and
            private_root_prefix.isascii() and len(private_root_prefix) > 8 and
            isinstance(private_name, str) and private_name.startswith(private_root_prefix + "/"),
            "Exact private source identity is required")
    source = read_verified_file(path, sha256, 8 << 20)
    before = strict_json(source)
    require(before.get("bomFormat") == "CycloneDX", "Expected CycloneDX SBOM")
    component = before.get("metadata", {}).get("component", {})
    require(component.get("name") == private_name, "SBOM source component name differs")
    properties = component.get("properties", [])
    require(isinstance(properties, list), "Invalid SBOM properties")
    image_ids = [item.get("value") for item in properties
                 if isinstance(item, dict) and item.get("name") == "aquasecurity:trivy:ImageID"]
    require(image_ids == [expected_config_digest], "SBOM is not bound to this image config")
    after = strict_json(source)
    after["metadata"]["component"]["name"] = public_child_reference
    require(semantic_changes(before, after) == ["/metadata/component/name"],
            "SBOM normalization changed more than its artifact name")
    output = canonical(after)
    require(private_root_prefix.casefold().encode() not in output.lower(),
            "Private source path remains elsewhere in SBOM")
    receipt = {"inputSHA256": sha256, "changedJSONPointer": "/metadata/component/name",
               "outputSHA256": hashlib.sha256(output).hexdigest(),
               "publicChildReference": public_child_reference,
               "expectedImageConfigDigest": expected_config_digest,
               "graphAndPackageSemanticsUnchanged": True}
    return output, receipt


def assemble(*, images, component, version, source_content_sha256,
             dockerfile_sha256, toolchain_versions, official_base_digests,
             validation, sboms, reference_name, output):
    """Create a new layout/archive; never mutate or publish its tested children.

    images is exactly {"amd64": {path, archive_sha256, manifest_digest}, "arm64": ...}.
    The returned imageIndexDigest identifies the nested index blob. discoverySHA256
    identifies index.json, whose sole descriptor points to that image index.
    """
    require(component in ("backend", "operator"), "Component is not allowed")
    require(set(images) == {"amd64", "arm64"}, "Exactly amd64 and arm64 are required")
    require(bool(re.fullmatch(r"\d+\.\d+\.\d+-rc\.[1-9]\d*", version)), "An explicit RC version is required")
    require(SHA.fullmatch(source_content_sha256 or ""), "Source content SHA is required")
    require(SHA.fullmatch(dockerfile_sha256 or ""), "Dockerfile SHA is required")
    require(isinstance(toolchain_versions, dict) and toolchain_versions and
            set(toolchain_versions) <= {"buildkit", "go", "python", "sqlite", "gcc", "node", "alpine"},
            "Reviewed toolchain versions are required")
    require(all(isinstance(value, str) and re.fullmatch(r"v?[0-9][0-9A-Za-z._+-]{0,79}", value)
                for value in toolchain_versions.values()), "Invalid public toolchain version")
    require(set(validation) == set(sboms) == {"amd64", "arm64"},
            "Both measured validation and SBOM pins are required")
    require(isinstance(official_base_digests, list) and 1 <= len(official_base_digests) <= 8,
            "Reviewed official base digests are required")
    require(len(set(official_base_digests)) == len(official_base_digests) and
            all(DIGEST.fullmatch(item) for item in official_base_digests), "Invalid official base pins")
    require(bool(re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+", reference_name)),
            "A plain local OCI reference name is required")
    target = Path(output)
    require(target.is_absolute(), "Output path must be absolute")
    require(not target.exists() and not target.is_symlink(), "Output directory already exists")
    require(target.parent.is_dir() and target.parent.resolve() == target.parent.absolute(),
            "Output parent is not an existing direct directory")
    opened = []
    try:
        for architecture in ("amd64", "arm64"):
            item = images[architecture]
            require(set(item) == {"path", "archive_sha256", "manifest_digest"}, "Unexpected input pin field")
            opened.append(VerifiedImage(architecture=architecture, version=version, **item))
        require(opened[0].manifest_digest != opened[1].manifest_digest, "Architecture manifests must differ")
        normalized = {}
        for image in opened:
            checked = validation[image.architecture]
            require(set(checked) == {"scanJSONSHA256", "databaseSHA256", "severityCounts",
                                     "includeUnfixed", "ignoredFindings", "runtimeReceiptSHA256",
                                     "privacyReceiptSHA256"}, "Unexpected validation field")
            require(all(SHA.fullmatch(checked[key] or "") for key in
                        ("scanJSONSHA256", "databaseSHA256", "runtimeReceiptSHA256", "privacyReceiptSHA256")),
                    "Measured validation receipt hashes are required")
            severity = checked["severityCounts"]
            require(isinstance(severity, dict) and set(severity) ==
                    {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"} and
                    all(type(count) is int and count >= 0 for count in severity.values()) and
                    severity["HIGH"] == severity["CRITICAL"] == 0,
                    "HIGH or CRITICAL findings block assembly")
            require(checked["includeUnfixed"] is True and checked["ignoredFindings"] is False,
                    "Validation must include unfixed findings without ignores")
            pin = sboms[image.architecture]
            require(set(pin) == {"path", "sha256", "private_name", "private_root_prefix"},
                    "Unexpected SBOM input pin field")
            normalized[image.architecture] = normalize_sbom(
                public_child_reference=reference_name + "@" + image.manifest_digest,
                expected_config_digest=image.config_digest, **pin)
        target.mkdir(mode=0o700)
        layout = target / "layout"
        (layout / "blobs" / "sha256").mkdir(mode=0o700, parents=True)
        copied = set()
        for image in opened:
            for digest, descriptor in sorted(image.descriptors.items()):
                if digest in copied:
                    continue
                data = image.blob(descriptor)
                write_once(layout / "blobs" / "sha256" / digest.split(":")[1], data)
                copied.add(digest)
            image.unchanged()
        image_index = {"schemaVersion": 2, "mediaType": INDEX,
                       "manifests": [image.output_descriptor for image in opened],
                       "annotations": {"org.opencontainers.image.version": version,
                                       "io.sekvyr.source-content-sha256": source_content_sha256}}
        index_bytes = canonical(image_index)
        index_digest = "sha256:" + hashlib.sha256(index_bytes).hexdigest()
        require(index_digest not in copied, "Index content unexpectedly aliases an input blob")
        write_once(layout / "blobs" / "sha256" / index_digest.split(":")[1], index_bytes)
        discovery = {"schemaVersion": 2, "mediaType": INDEX, "manifests": [{
            "mediaType": INDEX, "digest": index_digest, "size": len(index_bytes),
            "annotations": {"org.opencontainers.image.ref.name": reference_name}}]}
        discovery_bytes = canonical(discovery)
        write_once(layout / "index.json", discovery_bytes)
        write_once(layout / "oci-layout", canonical({"imageLayoutVersion": "1.0.0"}))
        archive = target / "image.oci.tar"
        with archive.open("xb") as stream:
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for path in sorted(layout.rglob("*"), key=lambda item: item.relative_to(layout).as_posix()):
                    require(path.is_dir() or path.is_file() and not path.is_symlink(), "Unexpected output entry")
                    name = path.relative_to(layout).as_posix()
                    entry = tarfile.TarInfo(name)
                    entry.uid = entry.gid = entry.mtime = 0
                    entry.uname = entry.gname = ""
                    entry.mode = 0o755 if path.is_dir() else 0o644
                    if path.is_dir():
                        entry.type = tarfile.DIRTYPE
                        tar.addfile(entry)
                    else:
                        entry.size = path.stat().st_size
                        with path.open("rb") as source:
                            tar.addfile(entry, source)
            stream.flush()
            os.fsync(stream.fileno())
        provenance = {"format": "sekvyr-stage8-tested-oci-index-v1", "component": component,
                      "version": version, "sourceContentSHA256": source_content_sha256,
                      "dockerfileSHA256": dockerfile_sha256,
                      "reviewedToolchainVersions": toolchain_versions,
                      "reviewedOfficialBaseDigests": official_base_digests,
                      "imageIndexDigest": index_digest,
                      "discoverySHA256": hashlib.sha256(discovery_bytes).hexdigest(),
                      "archiveSHA256": file_sha(archive), "archiveBytes": archive.stat().st_size,
                      "children": [{"architecture": image.architecture, "os": "linux",
                                    "manifestDigest": image.manifest_digest,
                                    "configDigest": image.config_digest,
                                    "layerDigests": image.layer_digests,
                                    "inputArchiveSHA256": image.archive_sha256}
                                   for image in opened],
                      "childManifestsUnchanged": True, "rebuilt": False,
                      "registryWrites": False, "hostDockerLoad": False,
                      "nativeARMHardwareClaim": False,
                      "recordType": "unsigned-local-build-manifest", "signed": False,
                      "SLSAClaim": False, "validationReceipts": validation, "SBOMs": {}}
        provenance["validationScope"] = "image-build-inspection-scan-privacy"
        provenance["liveKubernetesAcceptance"] = "recorded-separately"
        for architecture in ("amd64", "arm64"):
            data, receipt = normalized[architecture]
            filename = "sbom-linux-" + architecture + ".cdx.json"
            write_once(target / filename, data)
            provenance["SBOMs"][architecture] = dict(receipt, filename=filename)
        for image in opened:
            image.unchanged()
        write_once(target / "provenance.json", canonical(provenance))
        sums = [provenance["archiveSHA256"] + "  image.oci.tar",
                hashlib.sha256(canonical(provenance)).hexdigest() + "  provenance.json"]
        sums.extend(item["outputSHA256"] + "  " + item["filename"]
                    for item in provenance["SBOMs"].values())
        write_once(target / "SHA256SUMS", ("\n".join(sums) + "\n").encode())
        return provenance
    finally:
        for image in opened:
            image.close()
