# Architecture & Sizing

## Suggested VM layout

| VM | Role | vCPU | RAM | Disk | Notes |
|---|---|---|---|---|---|
| `siem01` | Wazuh manager + indexer + dashboard (Docker) | 4 | 8 GB | 100 GB | Indexer (OpenSearch) is the RAM hog; 4GB min heap |
| `win-target` | Windows Server, monitored | 2 | 4 GB | 60 GB | Wazuh agent + Sysmon; intentionally has a couple of weak local accounts for brute-force testing |
| `metasploitable` | Deliberately vulnerable Linux target | 1 | 1 GB | 20 GB | Metasploitable2/3, isolated on the same VLAN |
| `attacker` | Kali or similar | 2 | 4 GB | 40 GB | Runs `attack-sim/`; must NOT run the Wazuh agent |
| `sensor` (optional, can be `siem01`) | Suricata NIDS | 2 | 2 GB | 20 GB | Needs a mirrored/span port or to sit inline on the lab VLAN |

Put all of these on a dedicated, isolated VLAN/vSwitch — not your main home LAN —
so attack traffic can't leak to real devices and real devices don't add noise
to your detections.

## Network plan (fill in your actual ranges)

```
Lab VLAN:        10.10.10.0/24        <- edit to match your environment
  siem01:        10.10.10.10
  win-target:    10.10.10.20
  metasploitable:10.10.10.21
  attacker:      10.10.10.50
  sensor:        10.10.10.10 (colocated) or dedicated mirror port
Nutanix Prism:   10.10.10.x  (syslog source only, not a target)
```

Update `attack-sim/*` and `correlation/config.yaml` with these values before
running anything.

## Log sources into Wazuh

| Source | Transport | What it gives you |
|---|---|---|
| Windows Server (Sysmon) | Wazuh agent | Process creation (Event ID 1), network connections (3), LSASS access (10), new services (Sysmon 1 + Security 7045) |
| Windows Server (Security log) | Wazuh agent | 4624/4625 logons, 4688 process creation, 4720 account creation |
| Windows Defender Firewall | Wazuh agent (enable logging first) | Blocked/allowed connection attempts — cheap scan visibility even without Suricata |
| Nutanix AHV / Prism | Syslog → Wazuh manager UDP 514 | Cluster/host alerts, hypervisor-level auth events |
| Suricata (`eve.json`) | Wazuh agent's localfile module, JSON format | Signature hits for port scans, known exploit traffic, protocol anomalies |

Wazuh already ships decoders/rules for Sysmon, Windows eventchannel, and
Suricata `eve.json` — the custom rules in `wazuh/custom_rules/local_rules.xml`
only add lab-specific thresholds and tags on top of those.

## Ports to open between VMs

- Agents → Manager: TCP 1514 (events), TCP 1515 (enrollment)
- Your browser → Dashboard: TCP 443 on `siem01`
- Nutanix → Manager: UDP 514 (syslog)
- Manager → Indexer: TCP 9200 (internal to the Docker network, no need to expose)
