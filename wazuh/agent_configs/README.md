# Windows Server agent setup

Run these in order on `win-target`.

## 1. Enable Windows Defender Firewall logging (cheap scan visibility)

```powershell
.\enable_windows_firewall_logging.ps1
```

## 2. Install Sysmon with a lab-tuned config

Download Sysmon from Microsoft Sysinternals, then:

```powershell
.\sysmon64.exe -accepteula -i sysmonconfig-lab.xml
```

`sysmonconfig-lab.xml` here is a trimmed config (based on SwiftOnSecurity's
baseline) focused on what the detection rules in
`wazuh/custom_rules/local_rules.xml` actually consume: process creation
(Event 1), network connections (Event 3), and process access into LSASS
(Event 10). Use the full SwiftOnSecurity config instead if you want broader
coverage — https://github.com/SwiftOnSecurity/sysmon-config — the rules here
only depend on those three event types so nothing else needs to change.

## 3. Install the Wazuh agent

Download the MSI from your Wazuh manager version (must match the manager's
major.minor), then:

```powershell
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<siem01-ip>" WAZUH_AGENT_GROUP="windows-lab"
```

## 4. Point the agent at Sysmon, Security log, and the firewall log

Merge `ossec_agent_windows.conf` snippet below into
`C:\Program Files (x86)\ossec-agent\ossec.conf`, then restart the
`WazuhSvc` service.

```xml
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>C:\Windows\System32\LogFiles\Firewall\pfirewall.log</location>
    <log_format>syslog</log_format>
  </localfile>
</ossec_config>
```

## 5. Verify enrollment

On `siem01`:

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l
```

You should see `win-target` listed as `Active`.
