"""Verify the exact OCI tar bytes before passing them to containerd."""

import hashlib
import io
import json
import math
import re
import tarfile


MAX_ARCHIVE = 256 << 20
MAX_JSON = 4 << 20
MAX_MEMBERS = 4096
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOB = re.compile(r"blobs/sha256/([0-9a-f]{64})\Z")
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
INDEX_TYPES = {INDEX, "application/vnd.docker.distribution.manifest.list.v2+json"}
IMAGE_TYPES = {MANIFEST, "application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES = {CONFIG, "application/vnd.docker.container.image.v1+json"}
LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
NAMES = {"io.containerd.image.name", "org.opencontainers.image.ref.name"}
IMAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9./:_@-]{0,511}\Z")
ARCHITECTURES = {"386", "amd64", "arm", "arm64", "loong64", "mips", "mipsle", "mips64", "mips64le",
    "ppc64", "ppc64le", "riscv64", "s390x", "wasm", "unknown"}
AMD64 = ("linux", "amd64")


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def is_digest(value):
    return type(value) is str and DIGEST.fullmatch(value) is not None


def strict_json(data):
    require(0 < len(data) <= MAX_JSON, "OCI metadata exceeds bounds")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate OCI metadata field")
            result[key] = value
        return result

    def invalid(_):
        raise RuntimeError("Invalid OCI metadata number")

    def finite_float(value):
        result = float(value)
        require(math.isfinite(result), "Invalid OCI metadata number")
        return result

    result = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid,
        parse_float=finite_float)

    def inspect(value, depth):
        require(depth <= 48, "OCI metadata nesting exceeds bounds")
        if type(value) is dict:
            for key, member in value.items():
                inspect(key, depth + 1)
                inspect(member, depth + 1)
        elif type(value) is list:
            for member in value:
                inspect(member, depth + 1)
        elif type(value) is str:
            value.encode("utf-8")  # Reject unpaired escaped surrogates.
    inspect(result, 0)
    return result


def safe_path(name):
    return (type(name) is str and 0 < len(name) <= 512 and "\\" not in name
        and all(part not in ("", ".", "..") for part in name.split("/"))
        and all(32 < ord(char) < 127 for char in name))


def annotations(value, *, named=False, legacy_root_digest=None):
    reason = "Invalid or nested named OCI reference"
    require(type(value) is dict and all(type(k) is str and type(v) is str for k, v in value.items()), reason)
    for key in NAMES.intersection(value):
        name = value[key]
        if named and IMAGE_NAME.fullmatch(name):
            continue
        full_name = value.get("io.containerd.image.name", "")
        require(named and legacy_root_digest is not None and key == "org.opencontainers.image.ref.name"
            and name == "@" + legacy_root_digest and IMAGE_NAME.fullmatch(full_name)
            and full_name.partition("@")[2] == legacy_root_digest, reason)


def platform(value):
    require(type(value) is dict and set(value) <= {"os", "architecture", "variant", "os.version", "os.features", "features"}
        and type(value.get("os")) is str and re.fullmatch(r"[a-z][a-z0-9]{0,31}", value["os"])
        and type(value.get("architecture")) is str and value["architecture"] in ARCHITECTURES,
        "Invalid OCI platform")
    for key in ("variant", "os.version"):
        require(key not in value or type(value[key]) is str, "Invalid OCI platform")
    for key in ("os.features", "features"):
        require(key not in value or type(value[key]) is list and all(type(v) is str for v in value[key]),
            "Invalid OCI platform")
    identity = value["os"], value["architecture"]
    require(identity != AMD64 or value.get("variant", "") in ("", "v1"), "Unsupported linux/amd64 variant")
    return identity


def descriptor(value, types, *, named=False, with_platform=False, legacy_root=False):
    fields = {"mediaType", "digest", "size", "annotations"}
    if with_platform:
        fields.add("platform")
    require(type(value) is dict and set(value) <= fields and value.get("mediaType") in types
        and is_digest(value.get("digest")) and type(value.get("size")) is int
        and 0 < value["size"] <= (MAX_ARCHIVE if value["mediaType"] in LAYER_TYPES else MAX_JSON),
        "Invalid OCI descriptor")
    if "annotations" in value:
        annotations(value["annotations"], named=named, legacy_root_digest=value["digest"] if legacy_root else None)
    if "platform" in value:
        platform(value["platform"])
    return value


def index(value, types=INDEX_TYPES):
    require(type(value) is dict and set(value) <= {"schemaVersion", "mediaType", "manifests", "annotations"}
        and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 2
        and ("mediaType" not in value or value["mediaType"] in types)
        and type(value.get("manifests")) is list and 0 < len(value["manifests"]) <= 256, "Invalid OCI index")
    if "annotations" in value:
        annotations(value["annotations"])
    return value["manifests"]


def members(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE and len(raw) % 512 == 0,
        "OCI archive exceeds bounds")
    view = memoryview(raw)
    files, directories, seen = {}, set(), set()
    end = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name
            require(len(seen) < MAX_MEMBERS and safe_path(name) and name not in seen,
                "Unsafe, duplicate or excessive OCI archive path")
            seen.add(name)
            # Reject tar extensions/hidden headers, including PAX and GNU long names.
            require(member.offset == end and member.offset_data == end + 512 and not member.pax_headers
                and not member.sparse and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
                "Unsupported OCI tar entry")
            offset, size = member.offset_data, member.size
            require(0 <= size <= MAX_ARCHIVE and offset + size <= len(raw), "Invalid OCI tar member bounds")
            end = offset + ((size + 511) // 512) * 512
            require(end <= len(raw) and not any(view[offset + size:end]), "Invalid OCI tar padding")
            if member.isdir():
                require(size == 0, "Invalid OCI directory")
                directories.add(name)
            else:
                files[name] = view[offset:offset + size]
    require(len(raw) - end >= 1024 and not any(view[end:]), "Invalid OCI tar trailer")
    return files, directories


class Graph:
    def __init__(self, files, directories, *, allow_legacy):
        self.files, self.directories = files, directories
        self.allow_legacy = allow_legacy
        self.used = {"index.json", "oci-layout"}
        self.blobs, self.descriptors, self.selected = {}, {}, []
        self.visited = set()
        self.visits = 0
        for name, data in files.items():
            match = BLOB.fullmatch(name)
            if match:
                digest = "sha256:" + match[1]
                require(sha(data) == digest, "OCI blob checksum differs")
                self.blobs[digest] = name

    def blob(self, desc, optional):
        digest = desc["digest"]
        identity = desc["mediaType"], desc["size"]
        require(self.descriptors.setdefault(digest, identity) == identity,
            "Conflicting OCI descriptors for one blob")
        name = self.blobs.get(digest)
        if name is None:
            require(optional, "Required OCI blob is missing")
            return None
        self.used.add(name)
        data = self.files[name]
        require(len(data) == desc["size"], "OCI descriptor size differs")
        return data

    def visit(self, desc, inherited=None, depth=0):
        self.visits += 1
        require(depth <= 8 and self.visits <= MAX_MEMBERS, "OCI graph exceeds bounds")
        descriptor(desc, INDEX_TYPES | IMAGE_TYPES, named=depth == 0, with_platform=True,
            legacy_root=self.allow_legacy and depth == 0)
        require(desc["digest"] not in self.visited, "Repeated OCI image or index descriptor")
        self.visited.add(desc["digest"])
        declared = platform(desc["platform"]) if "platform" in desc else inherited
        require(inherited is None or declared == inherited, "Conflicting OCI platform descriptors")
        # Only a legacy platform-filtered export can omit explicitly unselected content.
        optional = self.allow_legacy and depth > 0 and declared is not None and declared != AMD64
        data = self.blob(desc, optional)
        if data is None:
            return
        value = strict_json(data)
        media = desc["mediaType"]
        if media in INDEX_TYPES:
            for child in index(value, {media}):
                self.visit(child, declared, depth + 1)
            return
        require(type(value) is dict and set(value) <= {"schemaVersion", "mediaType", "config", "layers", "annotations"}
            and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 2
            and ("mediaType" not in value or value["mediaType"] == media)
            and type(value.get("layers")) is list and len(value["layers"]) <= 256, "Invalid OCI image manifest")
        if "annotations" in value:
            annotations(value["annotations"])
        conf = descriptor(value.get("config"), CONFIG_TYPES)
        conf_data = self.blob(conf, optional)
        layers = [descriptor(item, LAYER_TYPES) for item in value["layers"]]
        for item in layers:
            self.blob(item, optional)
        if conf_data is None:
            return
        config = strict_json(conf_data)
        require(type(config) is dict and type(config.get("rootfs")) is dict,
            "Invalid OCI image config")
        actual = platform({k: config[k] for k in ("os", "architecture", "variant") if k in config})
        require(declared is None or actual == declared, "OCI config platform differs from descriptor")
        rootfs = config["rootfs"]
        diff_ids = rootfs.get("diff_ids")
        require(rootfs.get("type") == "layers" and type(diff_ids) is list and len(diff_ids) == len(layers)
            and all(is_digest(item) for item in diff_ids), "Invalid OCI rootfs descriptor")
        if actual == AMD64:
            self.selected.append((desc["digest"], conf, layers))

    def finish(self, expected):
        require(len(self.selected) == 1 and self.selected[0][0] == expected,
            "Unique linux/amd64 OCI manifest differs from receipt")
        if "manifest.json" in self.files:
            require(self.allow_legacy, "Docker compatibility manifest is not allowed for RC images")
            value = strict_json(self.files["manifest.json"])
            require(type(value) is list and len(value) == 1 and type(value[0]) is dict
                and set(value[0]) == {"Config", "RepoTags", "Layers"}, "Docker manifest must describe one image")
            row = value[0]
            require(row["RepoTags"] is None or type(row["RepoTags"]) is list and len(row["RepoTags"]) <= 256
                and all(type(tag) is str and IMAGE_NAME.fullmatch(tag) for tag in row["RepoTags"]),
                "Invalid Docker image tags")
            _, conf, layers = self.selected[0]
            # containerd's OCI exporter points the compatibility manifest at
            # the very same content-addressed files. It adds no extra blobs.
            require(row["Config"] == self.blobs[conf["digest"]]
                and row["Layers"] == [self.blobs[layer["digest"]] for layer in layers],
                "Docker manifest differs from selected OCI image")
            self.used.add("manifest.json")
        require(set(self.files) == self.used, "Unreferenced OCI archive member")
        parents = {"blobs", "blobs/sha256"}
        for path in self.used:
            parts = path.split("/")
            parents.update("/".join(parts[:i]) for i in range(1, len(parts)))
        require(self.directories <= parents, "Unreferenced OCI archive directory")


def validate(raw, expected_root, expected_amd64, *, allow_legacy=False):
    """Return the exact discovery digest after validating the complete graph."""
    require(is_digest(expected_root) and is_digest(expected_amd64), "Invalid OCI image pins")
    try:
        files, directories = members(raw)
        require(strict_json(files["oci-layout"]) == {"imageLayoutVersion": "1.0.0"}, "Invalid OCI layout")
        discovery = files["index.json"]
        roots = index(strict_json(discovery), {INDEX})
        require(len(roots) == 1, "Exactly one OCI discovery root is required")
        root = descriptor(roots[0], INDEX_TYPES | IMAGE_TYPES, named=True, with_platform=True, legacy_root=allow_legacy)
        require(root["digest"] == expected_root, "OCI discovery root differs from reviewed digest")
        graph = Graph(files, directories, allow_legacy=allow_legacy)
        graph.visit(root)
        graph.finish(expected_amd64)
        return sha(discovery)
    except (KeyError, TypeError, ValueError, UnicodeError, tarfile.TarError, OSError, RecursionError):
        raise RuntimeError("Malformed OCI archive") from None
