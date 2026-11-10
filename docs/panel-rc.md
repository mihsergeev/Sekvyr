# Publishing a reviewed panel RC

Use the signed backend/frontend digest pair from the immutable GitHub release.

## Prepare and review

1. Push the exact RC commit to `rc/panel-v<version>`. Wait for CI and the
   backend, frontend and operator native builds and scans to pass. Record the
   candidate run ID and attempt. If a rebuild is needed, rerun **all** candidate
   jobs so their artifacts belong to one attempt.
2. Tag that commit as `v<version>`. Run **Build and promote reviewed RC images**
   with `--ref v<version> -f phase=prepare -f candidate_run=<id> -f candidate_attempt=<n>`.
   The workflow verifies the candidate and CI, assembles the image archives,
   and signs `release-manifest.json`. The manifest records the source revision,
   candidate attempt, artifact IDs and hashes, image digests, and asset hashes.
3. Download `panel-release-assets-attempt-<n>` from the prepare run into a clean
   directory. Review the source and final assets for secrets and private data.
   Keep the manifest and its Sigstore bundle with the OCI archives and SBOMs.
   Confirm immutable releases are enabled in the repository settings. Create a
   draft for the existing tag with exactly those seven assets and the reviewed
   release notes.

   ```sh
   gh release create "$tag" reviewed/* --draft --prerelease --verify-tag \
     --title "$tag" --notes-file notes.md
   gh release view "$tag" --json databaseId --jq .databaseId
   sha256sum reviewed/release-manifest.json
   ```

## Promote and publish

Run the same workflow with `--ref "$tag" -f phase=promote`,
`-f release_id=<draft-id>` and `-f manifest_sha256=<reviewed-sha256>`.
It fetches the exact draft assets, verifies the signature and hashes, and
copies and checks both images by digest before attesting them. If a push fails,
dispatch the same inputs again. The draft has the reviewed bytes needed for the
retry even after the candidate and prepare artifacts expire. An immutable
published RC also works as a source for restoring its image digests.

After a successful promotion, compare the release ID and manifest hash in the
workflow summary with the approved draft. Check the draft still has the exact
reviewed assets, then publish it as a prerelease. Verify the release and the
published manifest with `gh release verify "$tag"` and
`gh release verify-asset "$tag" reviewed/release-manifest.json`.

## Install from a reviewed RC

Check out the RC source tag and verify the downloaded release manifest with
`gh release verify-asset "$tag" release-manifest.json`. Verify its workflow
signature and the attestations for both image digests before deploying. In the
following example, `repo` is the GitHub repository, `tag` the published tag,
and `revision` its checked-out commit SHA.

```sh
set -e
workflow="$repo/.github/workflows/panel-rc.yml"
gh attestation verify release-manifest.json --repo "$repo" \
  --bundle release-manifest.sigstore.json --signer-workflow "$workflow" \
  --signer-digest "$revision" --source-digest "$revision" \
  --source-ref "refs/tags/$tag" --deny-self-hosted-runners
for component in backend frontend; do
  ref=$(jq -er --arg component "$component" '.images[$component]' release-manifest.json)
  gh attestation verify "oci://$ref" --repo "$repo" --signer-workflow "$workflow" \
    --signer-digest "$revision" --source-digest "$revision" \
    --source-ref "refs/tags/$tag" --deny-self-hosted-runners
done
jq '{services: (.images | map_values({image: .}))}' release-manifest.json > compose.panel-rc.json
```

Append `compose.panel-rc.json` after `compose.ghcr.yml` and the installation's
other overlays in `COMPOSE_FILE`. Check both pins with
`docker compose config --images` and use the usual backup and deploy procedure.

## Upgrade a digest-pinned installation

For the next RC, verify its manifest and image attestations as above and write
the resulting override to a new file. Back up the running installation with
`ops/backup.sh` using its current configuration. Check out the new RC source tag,
replace the active override with the new file and check both pins with
`docker compose config --images`. Pull both images with
`docker compose pull backend frontend`, then apply the configuration with
`docker compose up -d` and check the running version.

`ops/update.sh` requires both panel images to use the requested tag. To move
from a digest-pinned RC to a compatible newer stable release, back up the
running RC before changing `COMPOSE_FILE`. Then remove the digest override
from `COMPOSE_FILE` and run `ops/update.sh <stable-tag>`.

## Publish the matching operator RC

Use the same candidate run and attempt. Dispatch `prepare` from
`sekvyr-operator-v<operator-version>` on the same commit. Preparation also
requires a successful Operator verification run, then signs the operator image,
SBOMs, Helm package and both offline provision binaries into a separate
manifest. Review those assets and attach them with their verification bundle to
the operator draft. Dispatch `promote` from the operator tag using that draft's
ID and reviewed manifest hash. Verify the published release, chart checksum and
operator image attestation before changing a deployment's digest.
