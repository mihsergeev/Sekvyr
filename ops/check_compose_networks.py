#!/usr/bin/env python3
"""Check the effective Compose networks before changing a running installation."""

import argparse
import ipaddress
import json
import os
import subprocess
import sys


def validate(config, inspect_network):
    networks = config.get("networks", {})
    groups = {}
    for service in config["services"].values():
        for name, endpoint in (service.get("networks") or {}).items():
            definition = networks.get(name, {})
            group = groups.setdefault(definition.get("name", name), {"endpoints": [], "definitions": []})
            group["endpoints"].append(endpoint or {})
            if definition not in group["definitions"]:
                group["definitions"].append(definition)

    for name, group in groups.items():
        endpoints = group["endpoints"]
        definitions = group["definitions"]
        for version, field in ((4, "ipv4_address"), (6, "ipv6_address")):
            fixed = [ipaddress.ip_address(endpoint[field]) for endpoint in endpoints if endpoint.get(field)]
            if not fixed:
                continue
            if any(address.version != version for address in fixed) or len(set(fixed)) != len(fixed):
                raise ValueError("duplicate or invalid static addresses")
            external = any(definition.get("external") for definition in definitions)
            if len(fixed) == len(endpoints) and not external:
                continue
            pools = [pool for definition in definitions for pool in definition.get("ipam", {}).get("config", [])]
            if not pools:
                pools = inspect_network(name)
            subnets, dynamic = [], []
            for pool in pools:
                subnet = ipaddress.ip_network(pool.get("subnet", pool.get("Subnet", "")), strict=False)
                if subnet.version != version:
                    continue
                allocation = ipaddress.ip_network(pool.get("ip_range", pool.get("IPRange")) or str(subnet), strict=False)
                if allocation.version != version or not allocation.subnet_of(subnet):
                    raise ValueError("invalid dynamic allocation range")
                subnets.append(subnet)
                dynamic.append(allocation)
            if any(not any(address in subnet for subnet in subnets)
                   or any(address in pool for pool in dynamic) for address in fixed):
                raise ValueError("static addresses overlap dynamic allocation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-f", "--file", action="append", default=[], help="Compose file, in merge order")
    parser.add_argument("--sudo", action="store_true", help="read Docker configuration through sudo -n")
    args = parser.parse_args()
    docker = (["sudo", "-n"] if args.sudo else []) + ["docker"]
    compose = docker + ["compose"]
    for file in args.file:
        compose += ["-f", file]

    def inspect_network(name):
        result = subprocess.run(docker + ["network", "inspect", name], capture_output=True, timeout=30)
        if result.returncode:
            return []
        return json.loads(result.stdout)[0]["IPAM"]["Config"] or []

    try:
        result = subprocess.run(compose + ["config", "--format", "json"], capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError("Compose render failed")
        validate(json.loads(result.stdout), inspect_network)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
        # The rendered configuration contains credentials. Neither it nor a
        # Docker exception or stderr belongs in installation logs.
        if os.environ.get("SEKVYR_LANG") == "ru":
            message = ("Не удалось подтвердить безопасность адресов Docker Compose. "
                       "Проверьте конфигурацию и доступ к Docker. Для сети со статическим IP "
                       "задайте разным сервисам разные статические адреса либо настройте "
                       "IPAM ip_range, исключающий все статические адреса. "
                       "Для внешней сети настройте этот диапазон при ее создании.")
        else:
            message = ("Docker Compose address safety could not be verified. "
                       "Check the configuration and Docker access. On a network with a static IP, "
                       "assign distinct static addresses to its services or configure an IPAM "
                       "ip_range excluding every static address. For an external network, "
                       "configure that allocation range when creating it.")
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
