"""Reproduce the boot collision and verify both safe startup orders in Docker."""

import json
import ipaddress
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import uuid


ROOT = Path(__file__).resolve().parents[2]


def main():
    image = next(line.split()[1] for line in (ROOT / "frontend/Dockerfile").read_text().splitlines()
                 if line.startswith("FROM ghcr.io/nginx/nginx-unprivileged:"))
    with TemporaryDirectory(prefix="sekvyr-network-e2e-") as directory:
        file = Path(directory) / "compose.json"
        project = "sekvyr-network-e2e-" + uuid.uuid4().hex[:12]
        compose = ["docker", "compose", "--project-name", project, "--file", str(file)]

        def run(*args, success=True):
            result = subprocess.run(args, capture_output=True, text=True, timeout=60)
            if success and result.returncode:
                raise RuntimeError(result.stderr)
            return result

        ids = run("docker", "network", "ls", "-q").stdout.split()
        existing = json.loads(run("docker", "network", "inspect", *ids).stdout)
        allocated = [ipaddress.ip_network(pool["Subnet"]) for network in existing
                     for pool in network["IPAM"]["Config"] or [] if pool.get("Subnet")]
        subnet = next((ipaddress.ip_network(value) for value in
                       ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
                       if not any(pool.version == 4 and pool.overlaps(ipaddress.ip_network(value)) for pool in allocated)), None)
        if subnet is None:
            raise RuntimeError("No documentation subnet is available for the isolated Docker test")

        def write_config(*, fixed_frontend=False, separate_pool=False):
            service = {"image": image, "entrypoint": ["/bin/sh", "-c", "sleep 300"],
                       "read_only": True, "cap_drop": ["ALL"], "mem_limit": "32m", "pids_limit": 16}
            pool = {"subnet": str(subnet)}
            if separate_pool:
                pool["ip_range"] = str(list(subnet.subnets())[1])
            config = {"services": {
                "backend": {**service, "networks": {"internal": {"ipv4_address": str(subnet.network_address + 10)}}},
                "frontend": {**service, "networks": {"internal": {"ipv4_address": str(subnet.network_address + 11)} if fixed_frontend else {}}},
            }, "networks": {"internal": {"ipam": {"config": [pool]}}}}
            file.write_text(json.dumps(config))

        def check(*, safe):
            result = run(sys.executable, str(ROOT / "ops/check_compose_networks.py"), "--file", str(file), success=False)
            assert (result.returncode == 0) == safe, result.stderr

        try:
            write_config()
            check(safe=False)
            run(*compose, "create")
            run(*compose, "start", "frontend")
            # Pin to the address actually allocated to the dynamic peer, as
            # happens when an installation pins its running backend later.
            frontend = run(*compose, "ps", "-q", "frontend").stdout.strip()
            state = json.loads(run("docker", "inspect", frontend).stdout)[0]
            address = next(iter(state["NetworkSettings"]["Networks"].values()))["IPAddress"]
            config = json.loads(file.read_text())
            config["services"]["backend"]["networks"]["internal"]["ipv4_address"] = address
            file.write_text(json.dumps(config))
            run(*compose, "create", "backend")
            result = run(*compose, "start", "backend", success=False)
            assert result.returncode and "Address already in use" in result.stderr, result.stderr
            run(*compose, "down", "--timeout", "2")
            for fixed_frontend, separate_pool in ((True, False), (False, True)):
                write_config(fixed_frontend=fixed_frontend, separate_pool=separate_pool)
                check(safe=True)
                run(*compose, "create")
                for order in (("frontend", "backend"), ("backend", "frontend")):
                    for service in order:
                        run(*compose, "start", service)
                    ids = run(*compose, "ps", "-q").stdout.split()
                    states = json.loads(run("docker", "inspect", *ids).stdout)
                    assert len(states) == 2 and all(c["State"]["Running"] for c in states)
                    run(*compose, "stop", "--timeout", "2")
                run(*compose, "down", "--timeout", "2")
        finally:
            run(*compose, "down", "--timeout", "2")
    print("Compose network E2E passed: original collision rejected, both safe configurations survive either startup order")


if __name__ == "__main__":
    main()
