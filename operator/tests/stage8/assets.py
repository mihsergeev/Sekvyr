"""Import only reviewed RC/public dependencies into a creation-pinned own node."""
import hashlib
import os
from pathlib import Path
import re
import stat
import struct

from app_modes import require
from fixture import canonical, write_private
from . import archive_graph
from .capability import Capability
from .profiles import reviewed
import remote_assets_import as legacy

# Filled only after Root reviews the final verification-image export.
REVIEWED_BACKEND_TEST_IMAGE = "docker.io/library/sekvyr-backend-stage8-tests@sha256:6d7d15f799b6f255599788c22f25f22b66aa3ddf5a8986f1811636a63d7e511a"
LEGACY_ROLES = {"postgres", "seaweed", "python", "agent"}
CLIS = (("checkpoint-recovery", "recovery_sha256"), ("provision", "provision_sha256"))


def references(profile):
    _, pins = reviewed(profile)
    require(type(REVIEWED_BACKEND_TEST_IMAGE) is str and re.fullmatch(
        r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", REVIEWED_BACKEND_TEST_IMAGE),
        "Reviewed backend test image required")
    result = {role: value for role, value in legacy.REFERENCES.items() if role not in ("operator", "backend")}
    result.update(operator=pins["operator_image"], backend=pins["backend_image"], tests=REVIEWED_BACKEND_TEST_IMAGE)
    require(set(result) == {"operator", "backend", "postgres", "seaweed", "python", "agent", "tests"},
        "Exact Stage 8 image roles required")
    return result


def owned_file(path, maximum):
    path = Path(path)
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)

    try:
        require(path.is_absolute() and path.resolve(strict=True) == path,
            "Public artifact path traverses a link")
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            and before.st_mode & 0o022 == 0 and 0 < before.st_size <= maximum,
            "Bounded root-owned public artifact required")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= os.O_BINARY if os.name == "nt" else os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            opened = identity(os.fstat(fd))
            expected = identity(before)
            # Windows fd/path ctime can differ. Anchor both independently there.
            require((opened[:-1] == expected[:-1] if os.name == "nt" else opened == expected)
                and identity(path.lstat()) == expected, "Public artifact identity changed while opening")
            raw = bytearray()
            while len(raw) <= before.st_size:
                block = os.read(fd, min(1 << 20, before.st_size + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            require(len(raw) == before.st_size and identity(os.fstat(fd)) == opened
                and identity(path.lstat()) == expected and path.resolve(strict=True) == path,
                "Public artifact identity changed while reading")
        finally:
            os.close(fd)
        return bytes(raw)
    except (OSError, ValueError):
        raise RuntimeError("Cannot read bounded root-owned public artifact") from None


def verify_archive(owner, role, reference, entry):
    path = owner.root / "assets" / (role + ".tar")
    target = reference.split("@", 1)[1]
    require(type(entry) is dict and entry.get("path") == str(path) and entry.get("rootDigest") == target
        and type(entry.get("archiveBytes")) is int and 0 < entry["archiveBytes"] <= archive_graph.MAX_ARCHIVE
        and type(entry.get("archiveSHA256")) is str and re.fullmatch(r"[0-9a-f]{64}", entry["archiveSHA256"])
        and archive_graph.is_digest(entry.get("linuxAMD64ManifestDigest")),
        "Public archive receipt differs from reviewed image")
    raw = owned_file(path, entry["archiveBytes"])
    require(len(raw) == entry["archiveBytes"] and hashlib.sha256(raw).hexdigest() == entry["archiveSHA256"],
        "Public archive bytes differ from independent receipt")
    discovery = archive_graph.validate(raw, target, entry["linuxAMD64ManifestDigest"],
        allow_legacy=role in LEGACY_ROLES)
    return raw, discovery


def verify_static_cli(raw, expected):
    require(64 <= len(raw) <= 128 << 20 and hashlib.sha256(raw).hexdigest() == expected
        and raw[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", raw, 18)[0] == 62,
        "Reviewed static amd64 executable required")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<H", raw, 54)[0], struct.unpack_from("<H", raw, 56)[0]
    require(0 < count <= 128 and size >= 56 and offset + count * size <= len(raw)
        and all(struct.unpack_from("<I", raw, offset + index * size)[0] not in (2, 3) for index in range(count)),
        "Artifact cannot require a dynamic loader")


def verified_cli(owner, name, expected):
    binary = owner.root / "tools" / ("sekvyr-" + name)
    raw = owned_file(binary, 128 << 20)
    verify_static_cli(raw, expected)
    return raw


def verify_import_wrapper(payload, expected, allowed):
    require(archive_graph.sha(payload) == expected, "Archive wrapper checksum differs")
    try:
        roots = archive_graph.index(archive_graph.strict_json(payload))
        require(len(roots) == 1, "Archive wrapper must describe one image")
        root = archive_graph.descriptor(roots[0], archive_graph.INDEX_TYPES | archive_graph.IMAGE_TYPES,
            named=True, with_platform=True)
        require(root["digest"] in allowed, "Archive wrapper references another image")
    except (KeyError, TypeError, UnicodeError, ValueError, RecursionError):
        raise RuntimeError("Malformed archive wrapper") from None


def run(cluster, *, profile):
    refs = references(profile)  # No file/Docker access with unset pins.
    _, pins = reviewed(profile)
    owner = Capability(cluster, profile=profile)
    metadata = owner.root / "receipts" / "public-assets.json"
    raw = owned_file(metadata, 128 << 10)
    try:
        manifest = archive_graph.strict_json(raw)
    except (UnicodeError, ValueError, RecursionError):
        raise RuntimeError("Malformed Stage 8 public asset receipt") from None
    require(type(manifest) is dict and raw == canonical(manifest)
        and manifest.get("format") == "sekvyr-stage8-public-assets-v1"
        and manifest.get("rootTask") == str(owner.root) and type(manifest.get("archives")) is dict
        and set(manifest["archives"]) == set(refs),
        "Exclusive Stage 8 public asset receipt required")
    # Validate the complete set before the first mutation. Reread each artifact
    # against the same receipt at use time so no unverified bytes reach ctr.
    for role, reference in refs.items():
        verify_archive(owner, role, reference, manifest["archives"][role])
    for name, pin in CLIS:
        verified_cli(owner, name, pins[pin])
    directory = owner.task / "private" / "image-imports"
    directory.mkdir(mode=0o700)  # A partial import is retained, never adopted.
    for role, reference in refs.items():
        entry = manifest["archives"][role]
        data, discovery = verify_archive(owner, role, reference, entry)
        target = reference.split("@", 1)[1]
        before = legacy.rows(owner)
        previous = {value[0]: value[2] for value in before}
        write_private(directory / (role + "-intent.json"), canonical({"reference": reference,
            "archiveSHA256": entry["archiveSHA256"], "bytes": len(data)}))
        owner.exec("ctr", "-n", "k8s.io", "images", "import", "--digests", "--platform", "linux/amd64", "-", data=data)
        del data
        content = owner.exec("ctr", "-n", "k8s.io", "content", "get", target)
        require("sha256:" + hashlib.sha256(content).hexdigest() == target, "Imported immutable root checksum differs")
        values = legacy.rows(owner)
        current = {value[0]: value[2] for value in values}
        require(all(current.get(name) == digest for name, digest in previous.items()),
            "Import changed an existing image reference")
        allowed = {target, entry["linuxAMD64ManifestDigest"], discovery}
        for value in values:
            name = value[0]
            if name in previous:
                continue
            generated = re.fullmatch(r"import-[0-9]{4}-[0-9]{2}-[0-9]{2}@sha256:[0-9a-f]{64}", name)
            if value[2] not in allowed:
                require(generated, "Import exposed another image root")
                payload = owner.exec("ctr", "-n", "k8s.io", "content", "get", value[2])
                verify_import_wrapper(payload, value[2], allowed)
            if generated:
                require(name.split("@")[1] == value[2], "Bare import alias target differs")
                legacy.exact_alias(owner, legacy.rows(owner), "docker.io/library/" + name, value[2])
        legacy.exact_alias(owner, legacy.rows(owner), reference, target)
        matches = [value for value in legacy.rows(owner) if value[0] == reference]
        require(len(matches) == 1 and matches[0][2] == target, "Canonical CRI image reference differs")
        write_private(directory / (role + "-complete.json"), canonical({"rootAndArchiveSHA256Verified": True,
            "canonicalCRIReferenceVerified": True, "hostDockerImageLoaded": False}))
    for name, pin in CLIS:
        data = verified_cli(owner, name, pins[pin])
        target = owner.task / "tools" / ("sekvyr-" + name)
        write_private(target, data)
        target.chmod(0o555)
        if name == "checkpoint-recovery":
            write_private(owner.task / "private" / "recovery-binary.json",
                canonical({"image": pins["operator_image"], "sha256": pins[pin]}))
    result = {"sourceStage": 8, "publicImagesImportedInsideCreationPinnedKind": len(refs),
        "hostDockerImageImports": 0, "newRCBinaryHashesVerified": True, "production": False}
    write_private(owner.task / "public-images-ready.json", canonical(result))
    return result
