"""Offline storage-admin bootstrap/conformance using the official Python SDK.

The direct storage admin intentionally has broader privileges than runtime.
Successful fault injection is evidence that the separate gateway is required.
"""

import argparse
import base64
import concurrent.futures
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import uuid
from urllib.parse import urlsplit

from fixture import canonical, safe_task, write_private
from manifests import fsync_command


def client(endpoint, private, role="admin"):
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Fixed HTTPS S3 origin required")
    import boto3
    from botocore.config import Config
    credentials = json.loads((private / "storage-credentials.json").read_text(encoding="utf-8"))[role]
    return boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1", verify=str(private / "storage-ca.crt"),
        aws_access_key_id=credentials["access_key"], aws_secret_access_key=credentials["secret_key"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, proxies={},
            connect_timeout=5, read_timeout=30, retries={"total_max_attempts": 1},
            request_checksum_calculation="when_required", response_checksum_validation="when_required"))


def storage_bootstrap(cluster, endpoint):
    private = cluster.task / "private"
    fixture = cluster.fixture
    bucket, namespace = fixture["bucket"], fixture["namespaces"]["storage"]
    marker = private / "storage-ready.json"
    if marker.exists():
        raise RuntimeError("Bootstrap must not reset an initialized trial")
    # Apply fsync BEFORE the bucket/genesis. The command contains a validated,
    # fixed bucket name; no shell interpolation or command substitution.
    output = cluster.kube("exec", "-i", "deployment/storage", "-n", namespace, "-c", "storage", "--", "/usr/bin/weed", "shell",
        "-master=storage." + namespace + ".svc.cluster.local:9333", "-filer=storage." + namespace + ".svc.cluster.local:8888",
        data=fsync_command(bucket) + "fs.configure\n").stdout
    import re
    if not re.search(r'[\"\s]fsync[\"\s]*:\s*true', output):
        raise RuntimeError("Effective fsync rule was not confirmed")
    s3 = client(endpoint, private)
    s3.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object_lock_configuration(Bucket=bucket, ObjectLockConfiguration={"ObjectLockEnabled": "Enabled", "Rule": {
        "DefaultRetention": {"Mode": "COMPLIANCE", "Days": 1}}})
    if s3.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
        raise RuntimeError("Versioning not enabled")
    retention = s3.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
    if retention.get("ObjectLockEnabled") != "Enabled" or retention["Rule"]["DefaultRetention"]["Mode"] != "COMPLIANCE":
        raise RuntimeError("Compliance retention not enabled")
    write_private(marker, canonical({"format": "sekvyr-stage6-storage-ready-v1", "fsync": True, "ttl": False,
        "versioning": "Enabled", "retentionMode": "COMPLIANCE", "production": False, "bucket": bucket}))
    return {"fsyncBeforeGenesis": True, "versioning": True, "complianceRetention": True, "production": False}


def conformance(task, endpoint_a, endpoint_b):
    task = safe_task(task)
    private = task / "private"
    ready = json.loads((private / "storage-ready.json").read_text(encoding="utf-8"))
    if not ready["fsync"] or ready["ttl"] or ready["production"]:
        raise RuntimeError("Storage bootstrap guard failed")
    from botocore.exceptions import ClientError
    bucket = ready["bucket"]
    clients = [client(endpoint_a, private), client(endpoint_b, private)]
    key = "conformance/" + str(uuid.uuid4()) + "/slot"
    retain = datetime.now(timezone.utc) + timedelta(days=1)

    def put(index):
        body = canonical({"trial": True, "candidate": index, "nonce": str(uuid.uuid4())})
        try:
            response = clients[index].put_object(Bucket=bucket, Key=key, Body=body, IfNoneMatch="*",
                ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=retain,
                ChecksumSHA256=base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"))
            return {"status": "accepted", "version": response["VersionId"], "body": body}
        except ClientError as error:
            code = str(error.response.get("Error", {}).get("Code"))
            if code not in ("PreconditionFailed", "ConditionalRequestConflict", "412", "409"):
                raise RuntimeError("Unexpected conditional-write failure") from None
            return {"status": "conflict"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(put, (0, 1)))
    winners = [result for result in results if result["status"] == "accepted"]
    if len(winners) != 1:
        raise RuntimeError("Same-key conditional CAS did not produce exactly one winner")
    winner = winners[0]
    current = clients[0].get_object(Bucket=bucket, Key=key)
    if current["Body"].read(1 << 20) != winner["body"] or current["VersionId"] != winner["version"]:
        raise RuntimeError("Acknowledged canonical bytes/version changed")
    versions = clients[0].list_object_versions(Bucket=bucket, Prefix=key)
    if len(versions.get("Versions", [])) != 1 or versions.get("DeleteMarkers"):
        raise RuntimeError("Conditional race created duplicate versions or a marker")
    retention = clients[0].get_object_retention(Bucket=bucket, Key=key, VersionId=winner["version"])["Retention"]
    if retention["Mode"] != "COMPLIANCE":
        raise RuntimeError("Stored version lost COMPLIANCE retention")
    try:
        clients[0].delete_object(Bucket=bucket, Key=key, VersionId=winner["version"])
    except ClientError as error:
        if error.response["ResponseMetadata"]["HTTPStatusCode"] != 403:
            raise RuntimeError("Unexpected retention delete error") from None
    else:
        raise RuntimeError("Storage admin deleted a retained version")
    # Hold a safe opaque identity for a separate post-restart durability phase.
    write_private(private / "storage-probe.json", canonical({"bucket": bucket, "key": key,
        "version": winner["version"], "sha256": hashlib.sha256(winner["body"]).hexdigest()}))
    return {"crossGatewayConditionalWinners": 1, "versionsAfterRace": 1, "lockedVersionDeleteDenied": True,
        "requiresSeparateJournalGateway": True, "production": False}


def verify_after_restart(task, endpoint):
    task = safe_task(task)
    probe = json.loads((task / "private" / "storage-probe.json").read_text(encoding="utf-8"))
    s3 = client(endpoint, task / "private")
    value = s3.get_object(Bucket=probe["bucket"], Key=probe["key"], VersionId=probe["version"])
    raw = value["Body"].read(1 << 20)
    if hashlib.sha256(raw).hexdigest() != probe["sha256"]:
        raise RuntimeError("Acknowledged bytes did not survive component restart")
    return {"acknowledgedVersionSurvivedComponentRestart": True, "powerLossOrIndependentDomainProven": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("bootstrap", "conformance", "after-restart"))
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--secondary-endpoint")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        raise RuntimeError("Storage-admin phase requires explicit --execute")
    if args.phase == "bootstrap":
        from cluster import Cluster
        result = storage_bootstrap(Cluster(args.task_dir), args.endpoint)
    elif args.phase == "conformance":
        if not args.secondary_endpoint:
            raise ValueError("Two gateway endpoints required")
        result = conformance(args.task_dir, args.endpoint, args.secondary_endpoint)
    else:
        result = verify_after_restart(args.task_dir, args.endpoint)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # SDK exceptions may include URLs, signed headers or credential material.
        print("FAIL stage6 storage phase: " + type(error).__name__)
        raise SystemExit(1)
