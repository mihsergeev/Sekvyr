#!/usr/bin/env python3
"""Explicit safe transport diagnostics; prints status codes, never bodies."""

import argparse
import base64
import json
from pathlib import Path

from authority import Authority
import common
import infrastructure
import run as harness


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--driver", choices=("kind", "k0s"), required=True)
    args = parser.parse_args()
    task = Authority.safe_task(args.task_dir)
    common.configure(args.driver, task)
    if args.driver == "k0s":
        infrastructure.configure(task.name)
        harness.PANEL_NS = infrastructure.PANEL_NS
        harness.WITNESS_NS = infrastructure.WITNESS_NS
        harness.APP_NS = infrastructure.APP_NS
    authority = Authority.load(task)
    metadata = json.loads((task / "private" / "bootstrap.json").read_text())
    session = harness.Session(task, authority)
    try:
        session.login()
        _, vault = session.owner_request("GET", "/api/vault/status")
        for field in ("initialized", "sealed", "unsealed"):
            if field in vault and isinstance(vault[field], bool):
                print("vault_" + field + "=" + str(vault[field]).lower(), flush=True)
        pod = json.loads(common.kube("get", "pods", "-n", infrastructure.APP_NS,
                                    "-l", "app.kubernetes.io/instance=stage4", "-o", "json").stdout)["items"][0]
        token = common.kube("create", "token", infrastructure.SA, "-n", infrastructure.APP_NS,
                            "--audience=sekvyr", "--duration=10m", "--bound-object-kind=Pod",
                            "--bound-object-name=" + pod["metadata"]["name"],
                            "--bound-object-uid=" + pod["metadata"]["uid"]).stdout.strip()
        code, reply = session.panel.request("POST", "/api/v1/machine/token", {"kubernetes_token": token},
                                            expected=(200, 400, 401, 403, 422, 429, 500))
        print("token_status=" + str(code), flush=True)
        if code != 200:
            return
        print("session_schema=" + ",".join(sorted(reply)), flush=True)
        print("session_ttl=" + str(reply.get("expires_in")), flush=True)
        bearer = reply["access_token"]
        code, _ = session.panel.request("GET", "/api/v1/machine/capabilities", token=bearer,
                                        expected=(200, 401, 403, 404, 500))
        print("capabilities_status=" + str(code), flush=True)
        code, _ = session.panel.request("POST", "/api/v1/machine/report",
                                        {"public_key": base64.b64encode(authority.node_public).decode(),
                                         "agent_version": "sekvyr-operator-stage4"}, bearer,
                                        expected=(200, 400, 401, 403, 404, 422, 500))
        print("public_key_report_status=" + str(code), flush=True)
        path = "/api/v1/machine/e2e2/views/" + authority.scope["view_id"]
        for label, suffix in (("envelope", "/envelopes/" + metadata["initial_hash"]),
                              ("reader_wrap", "/reader-wrap?envelope_hash=" + metadata["initial_hash"])):
            code, _ = session.panel.request("GET", path + suffix, token=bearer,
                                            expected=(200, 400, 401, 403, 404, 409, 422, 500, 503))
            print(label + "_status=" + str(code), flush=True)
    finally:
        session.close()


if __name__ == "__main__":
    main()
