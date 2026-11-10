"""Assemble the scanned native builds without rebuilding or changing image blobs."""

import argparse
import gzip
import hashlib
import json
import re
import shutil
import tarfile
from pathlib import Path

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"
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


def read_image(artifact, layout, component, arch, version, revision):
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

    check(json.loads((layout / "oci-layout").read_bytes()) == {"imageLayoutVersion": "1.0.0"},
          "invalid OCI layout version")
    index = json.loads((layout / "index.json").read_bytes())
    check(index["schemaVersion"] == 2 and index["mediaType"] == INDEX, "invalid OCI index")
    descriptor, = index["manifests"]
    check(descriptor["mediaType"] == MANIFEST, "expected one OCI image manifest")
    platform = {"os": "linux", "architecture": arch}
    declared = descriptor.get("platform", platform)
    check(all(declared.get(key) == value for key, value in platform.items())
          and declared.get("variant") in ({None, "v8"} if arch == "arm64" else {None}),
          "wrong descriptor platform")
    manifest_path = blob(layout, descriptor)
    manifest = json.loads(manifest_path.read_bytes())
    check(manifest["schemaVersion"] == 2 and manifest["mediaType"] == MANIFEST,
          "invalid OCI image manifest")
    check(manifest["config"]["mediaType"] == CONFIG, "invalid OCI image config media type")
    config_path = blob(layout, manifest["config"])
    config = json.loads(config_path.read_bytes())
    labels = config["config"]["Labels"]
    check(config["os"] == "linux" and config["architecture"] == arch, "wrong image platform")
    check(labels.get("org.opencontainers.image.title") == f"Sekvyr {component}", "wrong image component")
    check(labels["org.opencontainers.image.version"] == version, "wrong image version")
    check(labels["org.opencontainers.image.revision"] == revision, "wrong image revision")
    rootfs = config["rootfs"]
    layers = manifest["layers"]
    diff_ids = rootfs["diff_ids"]
    check(rootfs["type"] == "layers" and isinstance(diff_ids, list) and isinstance(layers, list)
          and len(diff_ids) == len(layers) > 0, "invalid OCI rootfs")
    paths = [manifest_path, config_path]
    for layer, diff_id in zip(layers, diff_ids, strict=True):
        path = blob(layout, layer)
        media_type = layer["mediaType"]
        check(media_type in {LAYER, LAYER + "+gzip"}, "unsupported OCI layer media type")
        if media_type == LAYER + "+gzip":
            with gzip.open(path, "rb") as stream:
                actual = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        else:
            actual = layer["digest"]
        check(actual == diff_id, "OCI uncompressed layer digest mismatch")
        paths.append(path)
    check_sbom(sbom, manifest["config"]["digest"], diff_ids)
    descriptor = {key: descriptor[key] for key in ("mediaType", "digest", "size")}
    descriptor["platform"] = platform
    return descriptor, paths, sbom


def check_sbom(path, config_digest, diff_ids):
    bom = json.loads(path.read_bytes())
    check(bom["bomFormat"] == "CycloneDX" and bom["specVersion"] in {"1.6", "1.7"}
          and type(bom["version"]) is int and bom["version"] >= 1
          and isinstance(bom["components"], list) and bom["components"],
          "invalid CycloneDX inventory")
    component = bom["metadata"]["component"]
    check(component["type"] == "container", "inventory does not describe a container")
    properties = component["properties"]
    image_ids = [p["value"] for p in properties if p["name"] == "aquasecurity:trivy:ImageID"]
    layer_ids = {p["value"] for p in properties if p["name"] == "aquasecurity:trivy:DiffID"}
    check(image_ids == [config_digest] and layer_ids == set(diff_ids),
          "inventory does not match the image config and layers")


def write_index(layout, manifests):
    index = {"schemaVersion": 2, "mediaType": INDEX, "manifests": manifests}
    encoded = (json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (layout / "index.json").write_bytes(encoded)
    return encoded


def assemble(candidate, output, version, revision, platforms=PLATFORMS):
    output.mkdir()
    images = {}
    for component, architectures in platforms.items():
        bundle = output / component
        blob_dir = bundle / "blobs" / "sha256"
        blob_dir.mkdir(parents=True)
        descriptors = []
        for arch in architectures:
            name = f"{component}-{arch}"
            extracted = output / name
            descriptor, paths, sbom = read_image(candidate / name, extracted, component, arch, version, revision)
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
        images[component] = descriptors[0]["digest"]
        write_index(bundle, descriptors)
        with tarfile.open(output / f"{component}-image.oci.tar", "w:") as tar:
            for path in sorted(bundle.rglob("*")):
                tar.add(path, arcname=path.relative_to(bundle).as_posix(), recursive=False)
        shutil.rmtree(bundle)
    return images


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("version")
    parser.add_argument("revision")
    args = parser.parse_args()
    assemble(args.candidate, args.output, args.version, args.revision)
