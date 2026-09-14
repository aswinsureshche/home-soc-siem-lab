#!/usr/bin/env python3
"""
Safe Nmap wrapper for generating recon traffic against your own lab target,
to test the port-scan detections in wazuh/custom_rules/local_rules.xml
(Suricata-based and Windows-Firewall-log-based).

Requires nmap to be installed on this (attacker) box: apt install nmap

Usage:
    python3 nmap_scan.py --target 10.10.10.20 --profile quick
    python3 nmap_scan.py --target 10.10.10.20 --profile full --no-confirm
"""
import argparse
import shutil
import subprocess
import sys
from datetime import datetime

from safety import assert_lab_target

PROFILES = {
    # Fast SYN scan of common ports — should trip scan-threshold rules
    # within a few seconds.
    "quick": ["-sS", "-T4", "--top-ports", "100"],
    # Slower, full port range — more scan signature hits, more realistic
    # "someone is casing your network" traffic.
    "full": ["-sS", "-T3", "-p-"],
    # Service/version detection — generates different Suricata signatures
    # (banner grabs) than a plain SYN scan.
    "service": ["-sV", "-T4", "--top-ports", "200"],
    # OS fingerprinting + default scripts — noisiest, most realistic
    # "active recon" profile.
    "aggressive": ["-A", "-T4", "--top-ports", "500"],
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Lab target IP (RFC1918 only)")
    parser.add_argument("--profile", choices=PROFILES, default="quick")
    parser.add_argument(
        "--no-confirm", action="store_true", help="Skip the interactive confirmation prompt"
    )
    parser.add_argument("--out", default=None, help="Optional path to save Nmap output (-oN)")
    args = parser.parse_args()

    assert_lab_target(args.target, interactive_confirm=not args.no_confirm)

    if not shutil.which("nmap"):
        print("nmap not found on PATH. Install it first: apt install nmap", file=sys.stderr)
        sys.exit(1)

    cmd = ["nmap", *PROFILES[args.profile], args.target]
    if args.out:
        cmd += ["-oN", args.out]

    ts = datetime.now().isoformat(timespec="seconds")
    print(f"[{ts}] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
