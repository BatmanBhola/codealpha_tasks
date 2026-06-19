"""Helper to add a Windows firewall rule to block an IP or network.

This validates the provided IP/network and invokes `netsh` via
`subprocess.run` with `check=True` so failures raise exceptions.
"""

import subprocess
import ipaddress
import sys


def block_ip(ip: str) -> None:
    """Block the given IP address or network using Windows netsh.

    Raises ValueError for invalid addresses and CalledProcessError on command failure.
    """
    # Validate the provided IP or network to avoid injection risks
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IP or network: {ip}") from exc

    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name=NIDS_Block_{ip}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ]

    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python block.py <ip-or-network>")
        sys.exit(2)

    try:
        block_ip(sys.argv[1])
        print(f"Blocked {sys.argv[1]}")
    except (ValueError, subprocess.CalledProcessError) as exc:
        print(f"Failed to block {sys.argv[1]}: {exc}")
        sys.exit(1)
