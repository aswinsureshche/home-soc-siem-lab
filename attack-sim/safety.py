"""
Shared safety rails for attack-sim scripts.

Every script in this directory imports assert_lab_target() before doing
anything against a network target. It refuses non-RFC1918 addresses so a
typo can't send scan/exploit traffic outside your lab.
"""
import ipaddress
import sys

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # loopback, for local testing
]


def is_private(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # Not a literal IP (hostname) — caller should resolve first if it
        # wants strict checking. We don't do DNS here to avoid surprises.
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)


def assert_lab_target(host: str, *, interactive_confirm: bool = True) -> None:
    """Exit the process if `host` isn't a private-range literal IP, and
    optionally prompt for a typed confirmation before proceeding."""
    if not is_private(host):
        print(
            f"REFUSING: '{host}' is not an RFC1918/loopback address.\n"
            "This toolkit only targets private lab ranges (10.0.0.0/8, "
            "172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8). Pass the literal "
            "IP of a host you own on your lab VLAN.",
            file=sys.stderr,
        )
        sys.exit(1)

    if interactive_confirm:
        answer = input(
            f"About to run an attack simulation against {host}. "
            f"Type the IP again to confirm you own this host: "
        )
        if answer.strip() != host:
            print("Confirmation did not match. Aborting.", file=sys.stderr)
            sys.exit(1)
