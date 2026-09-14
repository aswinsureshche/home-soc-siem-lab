"""
Thin, read-only client for the Wazuh Indexer (OpenSearch-compatible) REST
API. Only queries the alerts index — never touches rules, agents, or
active-response endpoints.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3


@dataclass
class Alert:
    timestamp: dt.datetime
    rule_id: str
    rule_level: int
    rule_description: str
    agent_name: str
    src_ip: str | None
    dst_ip: str | None
    groups: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class WazuhIndexerClient:
    def __init__(self, url: str, username: str, password: str, verify_tls: bool = True):
        self.url = url.rstrip("/")
        self.auth = (username, password)
        self.verify_tls = verify_tls
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def search_alerts(
        self,
        index_pattern: str,
        since: dt.datetime,
        min_level: int = 0,
        size: int = 1000,
    ) -> list[Alert]:
        """Fetch alerts at/after `since` with rule.level >= min_level."""
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"timestamp": {"gte": since.isoformat()}}},
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
        }
        resp = requests.post(
            f"{self.url}/{index_pattern}/_search",
            json=query,
            auth=self.auth,
            verify=self.verify_tls,
            timeout=30,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [self._parse_hit(h) for h in hits]

    @staticmethod
    def _parse_hit(hit: dict[str, Any]) -> Alert:
        src = hit.get("_source", {})
        rule = src.get("rule", {})
        data = src.get("data", {})
        ts_raw = src.get("timestamp") or src.get("@timestamp")
        timestamp = dt.datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else dt.datetime.now(dt.timezone.utc)

        src_ip = (
            data.get("srcip")
            or src.get("srcip")
            or data.get("win", {}).get("eventdata", {}).get("ipAddress")
            or data.get("alert", {}).get("src_ip")  # suricata
        )
        dst_ip = data.get("dstip") or data.get("alert", {}).get("dest_ip")

        return Alert(
            timestamp=timestamp,
            rule_id=str(rule.get("id", "")),
            rule_level=int(rule.get("level", 0)),
            rule_description=rule.get("description", ""),
            agent_name=src.get("agent", {}).get("name", "unknown"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            groups=rule.get("groups", []),
            raw=src,
        )
