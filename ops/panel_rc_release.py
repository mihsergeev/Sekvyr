"""Pin scanned candidate artifacts and load a reviewed RC from a GitHub release."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
import zipfile

from ops.panel_rc import PLATFORMS, assemble, check, digest

WORKFLOW = ".github/workflows/panel-rc.yml"
FORMAT = "sekvyr-panel-rc-v1"
OPERATOR_FORMAT = "sekvyr-operator-rc-v1"
OPERATOR_PLATFORMS = {"operator": ("amd64", "arm64")}
MANIFEST = "release-manifest.json"
BUNDLE = "release-manifest.sigstore.json"
NATIVE_FILES = {"candidate.oci.tar", "sbom.cdx.json", "SHA256SUMS"}


def asset_files(platforms):
    return {
        *(f"{component}-image.oci.tar" for component in platforms),
        *(f"{component}-sbom-linux-{arch}.cdx.json" for component, arches in platforms.items() for arch in arches),
    }


FILES = asset_files(PLATFORMS)


def operator_files(version):
    return asset_files(OPERATOR_PLATFORMS) | {
        *(f"sekvyr-provision-linux-{arch}" for arch in OPERATOR_PLATFORMS["operator"]),
        f"sekvyr-operator-{version}.tgz",
        "SHA256SUMS",
    }


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value)


def valid_id(value):
    return type(value) is int and value > 0


def api(repo, endpoint, *args):
    return json.loads(subprocess.check_output(["gh", "api", f"repos/{repo}/{endpoint}", *args]))


def download(repo, endpoint, path):
    command = ["gh", "api", f"repos/{repo}/{endpoint}"]
    if endpoint.startswith("releases/assets/"):
        command.extend(["-H", "Accept: application/octet-stream"])
    with path.open("xb") as output:
        subprocess.run(command, check=True, stdout=output)


def candidate_artifacts(pages, branch, revision, run_id, attempt, platforms=PLATFORMS):
    artifacts = [item for page in pages for item in page["artifacts"]]
    selected = {}
    for component, arches in platforms.items():
        for arch in arches:
            name = f"{component}-{arch}"
            matches = [item for item in artifacts if item["name"] == f"{name}-attempt-{attempt}"]
            check(len(matches) == 1, f"expected exactly one artifact for {name} in attempt {attempt}")
            item, = matches
            run = item["workflow_run"]
            check(item["expired"] is False and valid_id(item["id"]) and valid_digest(item["digest"])
                  and run["id"] == run_id and run["head_branch"] == branch and run["head_sha"] == revision,
                  f"invalid artifact metadata for {name}")
            selected[name] = {"id": item["id"], "sha256": item["digest"]}
    return selected


def unpack_native(archive, destination, expected=NATIVE_FILES):
    with zipfile.ZipFile(archive) as source:
        check(len(source.infolist()) == len(expected) and set(source.namelist()) == expected,
              "unexpected candidate ZIP members")
        destination.mkdir()
        for name in expected:
            with source.open(name) as member, (destination / name).open("xb") as target:
                shutil.copyfileobj(member, target)


def image_ref(repo, component, identifier):
    check(valid_digest(identifier), "invalid image digest")
    return f"ghcr.io/{repo.split('/')[0].lower()}/sekvyr-{component}@{identifier}"


def passed_ci(repo, workflow, revision, branch):
    runs = api(repo, f"actions/workflows/{workflow}/runs", "-X", "GET", "-f", f"head_sha={revision}",
               "-f", f"branch={branch}", "-f", "event=push", "-f", "status=success")["workflow_runs"]
    passed = next((run for run in runs if run["head_sha"] == revision and run["head_branch"] == branch
                   and run["event"] == "push" and run["conclusion"] == "success"), None)
    check(passed is not None, f"{workflow} did not pass for this revision and branch")
    return {"run_id": passed["id"], "attempt": passed["run_attempt"]}


def prepare(repo, version, revision, run_id, attempt, output, *, operator=False):
    panel_version = json.loads(Path("frontend/package.json").read_bytes())["version"] if operator else version
    branch = f"rc/panel-v{panel_version}"
    platforms = OPERATOR_PLATFORMS if operator else PLATFORMS
    files = operator_files(version) if operator else FILES
    candidate = api(repo, f"actions/runs/{run_id}/attempts/{attempt}")
    check(candidate["id"] == run_id and candidate["run_attempt"] == attempt
          and candidate["path"] == WORKFLOW and candidate["event"] == "push"
          and candidate["conclusion"] == "success" and candidate["head_branch"] == branch
          and candidate["head_sha"] == revision, "candidate attempt did not scan this release")
    ci = passed_ci(repo, "ci.yml", revision, branch)
    operator_ci = passed_ci(repo, "operator.yml", revision, branch) if operator else None
    selected = candidate_artifacts(
        api(repo, f"actions/runs/{run_id}/artifacts?per_page=100", "--paginate", "--slurp"),
        branch, revision, run_id, attempt, platforms,
    )
    with TemporaryDirectory() as scratch:
        root = Path(scratch)
        for name, artifact in selected.items():
            archive = root / f"{name}.zip"
            download(repo, f"actions/artifacts/{artifact['id']}/zip", archive)
            check(f"sha256:{digest(archive)}" == artifact["sha256"], f"artifact digest mismatch: {name}")
            expected = NATIVE_FILES | {"sekvyr-provision"} if operator else NATIVE_FILES
            unpack_native(archive, root / name, expected)
            archive.unlink()
        images = assemble(root, output, version, revision, platforms)
        if operator:
            for arch in platforms["operator"]:
                shutil.copyfile(root / f"operator-{arch}" / "sekvyr-provision", output / f"sekvyr-provision-linux-{arch}")
            subprocess.run(["helm", "package", "operator/charts/sekvyr-operator", "--destination", str(output)],
                           check=True)
            checksums = "".join(f"{digest(output / name)}  {name}\n" for name in sorted(files - {"SHA256SUMS"}))
            (output / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    manifest = {
        "format": OPERATOR_FORMAT if operator else FORMAT, "repository": repo, "version": version, "revision": revision,
        "candidate": {"run_id": run_id, "attempt": attempt, "artifacts": selected},
        "ci": ci,
        "images": {name: image_ref(repo, name, identifier) for name, identifier in images.items()},
        "assets": {name: "sha256:" + digest(output / name) for name in sorted(files)},
    }
    if operator_ci:
        manifest["operator_ci"] = operator_ci
    (output / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def checked_manifest(output, repo, version, revision, *, operator=False):
    files = operator_files(version) if operator else FILES
    platforms = OPERATOR_PLATFORMS if operator else PLATFORMS
    release_format = OPERATOR_FORMAT if operator else FORMAT
    manifest = json.loads((output / MANIFEST).read_bytes())
    check((manifest["format"], manifest["repository"], manifest["version"], manifest["revision"])
          == (release_format, repo, version, revision), "signed manifest is for another release")
    check(set(manifest["assets"]) == files and all(map(valid_digest, manifest["assets"].values())),
          "invalid signed asset manifest")
    check(set(manifest["images"]) == set(platforms), "incomplete signed image set")
    for component, ref in manifest["images"].items():
        check(ref == image_ref(repo, component, ref.rsplit("@", 1)[-1]), "unexpected image reference")
    return manifest


def reviewed(repo, version, revision, release_id, reviewed_sha256, output, *, operator=False):
    tag = f"{'sekvyr-operator-' if operator else ''}v{version}"
    release = api(repo, f"releases/{release_id}")
    check(release["id"] == release_id and release["tag_name"] == tag and release["prerelease"]
          and (release["draft"] or release["immutable"]), "expected a draft or immutable release for this tag")
    assets = release["assets"]
    expected = (operator_files(version) if operator else FILES) | {MANIFEST, BUNDLE}
    check(len(assets) == len(expected) and {item["name"] for item in assets} == expected
          and all(item["state"] == "uploaded" and valid_id(item["id"]) for item in assets),
          "missing or unexpected release assets")
    by_name = {item["name"]: item["id"] for item in assets}
    output.mkdir()
    for name in (MANIFEST, BUNDLE):
        download(repo, f"releases/assets/{by_name[name]}", output / name)
    check(digest(output / MANIFEST) == reviewed_sha256, "release manifest differs from the reviewed copy")
    subprocess.run(
        ["gh", "attestation", "verify", str(output / MANIFEST), "--repo", repo,
         "--bundle", str(output / BUNDLE), "--signer-workflow", f"{repo}/{WORKFLOW}",
         "--signer-digest", revision, "--source-digest", revision, "--source-ref", f"refs/tags/{tag}",
         "--deny-self-hosted-runners"],
        check=True,
    )
    manifest = checked_manifest(output, repo, version, revision, operator=operator)
    for name, identifier in manifest["assets"].items():
        path = output / name
        download(repo, f"releases/assets/{by_name[name]}", path)
        check("sha256:" + digest(path) == identifier, f"release asset digest mismatch: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "reviewed"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--candidate-run", type=int)
    parser.add_argument("--candidate-attempt", type=int)
    parser.add_argument("--release-id", type=int)
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    repo, revision = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    match = re.fullmatch(r"refs/tags/(sekvyr-operator-)?v([0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+)", os.environ["GITHUB_REF"])
    check(match, "dispatch from the exact RC tag")
    operator, version = bool(match[1]), match[2]
    declared = (Path("operator/VERSION").read_text().strip() if operator
                else json.loads(Path("frontend/package.json").read_bytes())["version"])
    check(version == declared, "tag does not match the source version")
    if args.phase == "prepare":
        check(valid_id(args.candidate_run) and valid_id(args.candidate_attempt), "specify candidate run and attempt")
        prepare(repo, version, revision, args.candidate_run, args.candidate_attempt, args.output, operator=operator)
    else:
        check(valid_id(args.release_id), "specify the reviewed release ID")
        check(re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256 or ""), "specify the reviewed manifest SHA-256")
        reviewed(repo, version, revision, args.release_id, args.manifest_sha256, args.output, operator=operator)


if __name__ == "__main__":
    main()
