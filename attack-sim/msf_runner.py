#!/usr/bin/env python3
"""
Drives Metasploit resource scripts (.rc.template files in scenarios/)
against a lab target, after substituting {{TARGET}}, {{ATTACKER_IP}}, and
{{WORDLIST}} placeholders.

Requires msfconsole on this (attacker) box.

Usage:
    python3 msf_runner.py --scenario smb_brute_force --target 10.10.10.20
    python3 msf_runner.py --scenario vsftpd_backdoor --target 10.10.10.21 \
        --attacker-ip 10.10.10.50
    python3 msf_runner.py --list
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from safety import assert_lab_target

SCENARIOS_DIR = Path(__file__).parent / "scenarios"
DEFAULT_WORDLIST = SCENARIOS_DIR / "wordlist_weak.txt"


def list_scenarios() -> list[str]:
    return sorted(p.stem.replace(".rc", "") for p in SCENARIOS_DIR.glob("*.rc.template"))


def render_scenario(name: str, target: str, attacker_ip: str, wordlist: Path) -> str:
    template_path = SCENARIOS_DIR / f"{name}.rc.template"
    if not template_path.exists():
        print(f"Unknown scenario '{name}'. Available: {', '.join(list_scenarios())}", file=sys.stderr)
        sys.exit(1)
    text = template_path.read_text()
    text = text.replace("{{TARGET}}", target)
    text = text.replace("{{ATTACKER_IP}}", attacker_ip)
    text = text.replace("{{WORDLIST}}", str(wordlist))
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", help="Scenario name (see --list)")
    parser.add_argument("--target", help="Lab target IP (RFC1918 only)")
    parser.add_argument("--attacker-ip", default=None, help="This box's IP, for reverse-shell scenarios")
    parser.add_argument("--wordlist", default=str(DEFAULT_WORDLIST))
    parser.add_argument("--no-confirm", action="store_true")
    parser.add_argument("--list", action="store_true", help="List available scenarios and exit")
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for s in list_scenarios():
            print(f"  - {s}")
        return

    if not args.scenario or not args.target:
        parser.error("--scenario and --target are required (or use --list)")

    assert_lab_target(args.target, interactive_confirm=not args.no_confirm)

    if not shutil.which("msfconsole"):
        print("msfconsole not found on PATH. Install Metasploit Framework first.", file=sys.stderr)
        sys.exit(1)

    attacker_ip = args.attacker_ip or ""
    if "{{ATTACKER_IP}}" in (SCENARIOS_DIR / f"{args.scenario}.rc.template").read_text() and not attacker_ip:
        parser.error(f"scenario '{args.scenario}' requires --attacker-ip")

    rc_content = render_scenario(args.scenario, args.target, attacker_ip, Path(args.wordlist))

    with tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False) as f:
        f.write(rc_content)
        rc_path = f.name

    print(f"[msf_runner] Running scenario '{args.scenario}' against {args.target}")
    print(f"[msf_runner] Resource script: {rc_path}")
    try:
        result = subprocess.run(["msfconsole", "-q", "-r", rc_path])
    finally:
        Path(rc_path).unlink(missing_ok=True)

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
