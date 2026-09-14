# Home SOC / SIEM Lab

A mini Security Operations Center for your own home network: Wazuh as the
SIEM/HIDS core, Suricata as a network sensor, Nmap/Metasploit for attack
simulation, and a Python correlation engine that turns raw alerts into
incident reports.

**Everything here targets private RFC1918 addresses only and refuses to run
against anything else.** This is for testing detections on infrastructure you
own.

## Why Wazuh alone isn't enough

Wazuh is host-centric (agents + log analysis). It's excellent at catching
brute force, lateral movement, and process-level attacks *after* they touch a
monitored host — but a plain Nmap SYN scan from an unmonitored attacker box
generates no Windows Event Log entries by default, so a HIDS-only deployment
would silently miss it. This lab adds **Suricata** as a lightweight NIDS
sensor so network-level recon (port scans, exploit signatures) is visible
too, feeding into the same Wazuh pipeline.

## Architecture

```mermaid
flowchart LR
    subgraph Targets["Monitored hosts (agents)"]
        WS[Windows Server\n+ Sysmon + Wazuh agent]
        NX[Nutanix AHV hosts\nsyslog / Prism alerts]
    end

    subgraph Sensor["Network sensor"]
        SU[Suricata NIDS\non mirrored/span port]
    end

    subgraph SOC["SIEM VM (Linux, Docker)"]
        WM[Wazuh Manager\n+ rules/decoders]
        WI[Wazuh Indexer\n(OpenSearch)]
        WD[Wazuh Dashboard]
    end

    ATT[Attacker box\nNmap / Metasploit\nagainst your own lab]

    WS -- agent --> WM
    NX -- syslog --> WM
    SU -- eve.json via agent --> WM
    WM --> WI --> WD
    ATT -.attacks.-> WS
    ATT -.scans.-> SU

    subgraph Correlation["Python tooling"]
        CO[correlate.py\npulls alerts from Indexer API]
        RP[generate_report.py\nMarkdown/PDF incident report]
    end
    WI -- REST API --> CO --> RP
```

## Layout

```
home-soc-lab/
├── docs/
│   └── architecture.md          # network plan, port list, sizing
├── wazuh/
│   ├── deploy_wazuh.sh          # stands up manager+indexer+dashboard via Docker
│   ├── custom_rules/local_rules.xml     # detections tuned for the attack-sim scenarios
│   ├── custom_decoders/local_decoder.xml
│   └── agent_configs/           # Windows agent, Sysmon, firewall logging
├── suricata/
│   ├── install_suricata.sh
│   └── suricata.yaml.snippet
├── attack-sim/
│   ├── nmap_scan.py             # safe, RFC1918-only Nmap wrapper
│   ├── msf_runner.py            # drives msfconsole resource scripts
│   ├── scenarios/*.rc           # individual Metasploit scenarios
│   └── run_attack_suite.py      # orchestrates a full attack run
└── correlation/
    ├── wazuh_api_client.py      # thin client for the Wazuh Indexer REST API
    ├── correlate.py             # groups raw alerts into incidents
    ├── generate_report.py       # renders Markdown + optional PDF
    ├── report_template.md.j2
    ├── config.example.yaml
    └── requirements.txt
```

## Setup order

1. **Read [docs/architecture.md](docs/architecture.md)** and fill in your actual IP ranges.
2. **Deploy Wazuh** — `wazuh/deploy_wazuh.sh` on your SIEM VM.
3. **Enroll agents** — Windows Server via `wazuh/agent_configs/`, Nutanix via syslog forwarding (see architecture doc).
4. **Deploy Suricata** — `suricata/install_suricata.sh` on a box that can see a mirrored/span port, or on the Wazuh manager host if it sits inline.
5. **Load custom detections** — copy `wazuh/custom_rules/local_rules.xml` and `custom_decoders/local_decoder.xml` into the manager and restart.
6. **Run attack simulations** — `attack-sim/run_attack_suite.py --target <lab-ip>` from an attacker box (a separate VM, not the SIEM itself).
7. **Watch alerts land** in the Wazuh dashboard, then run the correlator:
   ```bash
   cd correlation
   pip install -r requirements.txt
   cp config.example.yaml config.yaml   # fill in indexer URL + creds
   python correlate.py --since 30m
   python generate_report.py --incidents incidents.json --out report.md
   ```

## Safety rails baked in

- `attack-sim/*` refuse to target anything outside RFC1918 space, and `run_attack_suite.py` prompts for confirmation of the target before firing.
- Metasploit scenarios only use auxiliary/scanner modules and well-known lab-only exploits (e.g. against Metasploitable2); nothing is aimed at real-world CVEs on production software.
- `correlate.py` and `generate_report.py` are read-only against the Wazuh API — they never modify rules or take active response actions.
