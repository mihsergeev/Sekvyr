"""Assemble the scanned native builds without rebuilding or changing image blobs."""

import argparse
import hashlib
import json
import re
import shutil
import tarfile
from pathlib import Path

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
PLATFORMS = {"backend": ("amd64", "arm64"), "frontend": ("amd64",)}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def blob(layout, descriptor):
    match = re.fullmatch(r"sha256:([0-9a-f]{64})", descriptor["digest"])
    check(match and not descriptor.keys() & {"urls", "data"}, "invalid OCI descriptor")
    file = layout / "blobs" / "sha256" / match[1]
    check(file.stat().st_size == descriptor["size"] and digest(file) == match[1],
          "OCI blob does not match descriptor")
    return file


def read_image(artifact, layout, arch, version, revision):
    archive = artifact / "candidate.oci.tar"
    sbom = artifact / "sbom.cdx.json"
    sums = (artifact / "SHA256SUMS").read_text().splitlines()
    check(sums == [f"{digest(path)}  {path.name}" for path in (archive, sbom)],
          f"artifact checksums do not match: {artifact.name}")
    with tarfile.open(archive, "r:") as tar:
        seen = set()
        for member in tar:
            name = member.name
            check(name not in seen, f"duplicate tar entry: {name}")
            seen.add(name)
            directory = member.isdir() and name in {"blobs", "blobs/sha256"}
            file = member.isfile() and (name in {"oci-layout", "index.json"}
                                        or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name))
            check(directory or file, f"unexpected tar entry: {name}")
        tar.extractall(layout, filter="data")

    index = json.loads((layout / "index.json").read_bytes())
    check(index["schemaVersion"] == 2 and index["mediaType"] == INDEX, "invalid OCI index")
    descriptor, = index["manifests"]
    check(descriptor["mediaType"] == MANIFEST, "expected one OCI image manifest")
    manifest_path = blob(layout, descriptor)
    manifest = json.loads(manifest_path.read_bytes())
    config_path = blob(layout, manifest["config"])
    config = json.loads(config_path.read_bytes())
    labels = config["config"]["Labels"]
    check(config["os"] == "linux" and config["architecture"] == arch, "wrong image platform")
    check(labels["org.opencontainers.image.version"] == version, "wrong image version")
    check(labels["org.opencontainers.image.revision"] == revision, "wrong image revision")
    paths = [manifest_path, config_path, *(blob(layout, layer) for layer in manifest["layers"])]
    descriptor = {key: descriptor[key] for key in ("mediaType", "digest", "size")}
    descriptor["platform"] = {"os": "linux", "architecture": arch}
    return descriptor, paths, sbom


def write_index(layout, manifests):
    index = {"schemaVersion": 2, "mediaType": INDEX, "manifests": manifests}
    encoded = (json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (layout / "index.json").write_bytes(encoded)
    return encoded


def assemble(candidate, output, version, revision):
    output.mkdir()
    for component, architectures in PLATFORMS.items():
        bundle = output / component
        blob_dir = bundle / "blobs" / "sha256"
        blob_dir.mkdir(parents=True)
        descriptors = []
        for arch in architectures:
            name = f"{component}-{arch}"
            extracted = output / name
            descriptor, paths, sbom = read_image(candidate / name, extracted, arch, version, revision)
            descriptors.append(descriptor)
            for path in paths:
                target = blob_dir / path.name
                if not target.exists():
                    path.replace(target)
            shutil.copyfile(sbom, output / f"{component}-sbom-linux-{arch}.cdx.json")
            shutil.rmtree(extracted)
        (bundle / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8")
        if len(descriptors) > 1:
            encoded = write_index(bundle, descriptors)
            identifier = hashlib.sha256(encoded).hexdigest()
            (blob_dir / identifier).write_bytes(encoded)
            descriptors = [{"mediaType": INDEX, "digest": f"sha256:{identifier}", "size": len(encoded)}]
        write_index(bundle, descriptors)
        with tarfile.open(output / f"{component}-image.oci.tar", "w:") as tar:
            for path in sorted(bundle.rglob("*")):
                tar.add(path, arcname=path.relative_to(bundle).as_posix(), recursive=False)
        shutil.rmtree(bundle)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("version")
    parser.add_argument("revision")
    args = parser.parse_args()
    assemble(args.candidate, args.output, args.version, args.revision)
