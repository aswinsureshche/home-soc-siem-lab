#!/usr/bin/env python3
"""
Pulls recent alerts from the Wazuh Indexer and correlates them into
incidents: alerts from the same source IP within a rolling time window are
grouped together and classified by attack stage (recon / brute force /
exploitation), based on the rule groups tagged in
wazuh/custom_rules/local_rules.xml.

Usage:
    python3 correlate.py --since 30m
    python3 correlate.py --since 2h --config config.yaml --out incidents.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from wazuh_api_client import Alert, WazuhIndexerClient

STAGE_GROUPS = {
    "recon": {"recon", "port_scan"},
    "brute_force": {"brute_force", "authentication_failures", "authentication_success_after_brute_force"},
    "exploitation": {
        "credential_access", "lsass_access", "execution", "suspicious_powershell",
        "lateral_movement", "persistence",
    },
    "multi_stage": {"multi_stage_attack", "incident"},
}


def classify_stage(groups: list[str]) -> str:
    group_set = set(groups)
    for stage, tags in STAGE_GROUPS.items():
        if group_set & tags:
            return stage
    return "other"


@dataclass
class Incident:
    source_ip: str
    first_seen: str
    last_seen: str
    stages: list[str]
    max_level: int
    alert_count: int
    alerts: list[dict] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if "multi_stage" in self.stages or self.max_level >= 14:
            return "CRITICAL"
        if self.max_level >= 11:
            return "HIGH"
        if self.max_level >= 8:
            return "MEDIUM"
        return "LOW"


def parse_since(value: str) -> dt.datetime:
    match = re.fullmatch(r"(\d+)([mhd])", value)
    if not match:
        raise ValueError("--since must look like 30m, 2h, or 1d")
    amount, unit = int(match.group(1)), match.group(2)
    delta = {"m": dt.timedelta(minutes=amount), "h": dt.timedelta(hours=amount), "d": dt.timedelta(days=amount)}[unit]
    return dt.datetime.now(dt.timezone.utc) - delta


def group_into_incidents(alerts: list[Alert], window_minutes: int) -> list[Incident]:
    by_ip: dict[str, list[Alert]] = {}
    for alert in alerts:
        if not alert.src_ip:
            continue
        by_ip.setdefault(alert.src_ip, []).append(alert)

    incidents: list[Incident] = []
    window = dt.timedelta(minutes=window_minutes)

    for ip, ip_alerts in by_ip.items():
        ip_alerts.sort(key=lambda a: a.timestamp)
        current: list[Alert] = []
        for alert in ip_alerts:
            if current and (alert.timestamp - current[-1].timestamp) > window:
                incidents.append(_build_incident(ip, current))
                current = []
            current.append(alert)
        if current:
            incidents.append(_build_incident(ip, current))

    incidents.sort(key=lambda i: i.max_level, reverse=True)
    return incidents


def _build_incident(ip: str, alerts: list[Alert]) -> Incident:
    stages = sorted({classify_stage(a.groups) for a in alerts})
    return Incident(
        source_ip=ip,
        first_seen=alerts[0].timestamp.isoformat(),
        last_seen=alerts[-1].timestamp.isoformat(),
        stages=stages,
        max_level=max(a.rule_level for a in alerts),
        alert_count=len(alerts),
        alerts=[
            {
                "timestamp": a.timestamp.isoformat(),
                "rule_id": a.rule_id,
                "level": a.rule_level,
                "description": a.rule_description,
                "agent": a.agent_name,
                "dst_ip": a.dst_ip,
                "groups": a.groups,
            }
            for a in alerts
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="30m", help="Lookback window, e.g. 30m, 2h, 1d")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", default="incidents.json")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config not found: {config_path}. Copy config.example.yaml to config.yaml first.", file=sys.stderr)
        sys.exit(1)
    config = yaml.safe_load(config_path.read_text())

    since = parse_since(args.since)

    client = WazuhIndexerClient(
        url=config["indexer"]["url"],
        username=config["indexer"]["username"],
        password=config["indexer"]["password"],
        verify_tls=config["indexer"].get("verify_tls", True),
    )

    print(f"Querying alerts since {since.isoformat()} (min level {config['correlation']['min_level']})...")
    alerts = client.search_alerts(
        index_pattern=config["indexer"]["alerts_index_pattern"],
        since=since,
        min_level=config["correlation"]["min_level"],
    )
    print(f"Fetched {len(alerts)} alerts.")

    incidents = group_into_incidents(alerts, config["correlation"]["window_minutes"])
    print(f"Grouped into {len(incidents)} incident(s).")
    for inc in incidents:
        print(f"  [{inc.severity}] {inc.source_ip}: {inc.alert_count} alerts, stages={inc.stages}")

    out_path = Path(args.out)
    out_path.write_text(json.dumps([{**asdict(i), "severity": i.severity} for i in incidents], indent=2))
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
