#!/usr/bin/env bash
# Installs Suricata as a NIDS sensor and points its eve.json output at a
# location the Wazuh agent can tail. Run on whichever box can see lab
# traffic (a mirrored/span port, or the Wazuh manager host if it's inline
# on the lab VLAN).
#
# Usage: sudo ./install_suricata.sh <monitor-interface>

set -euo pipefail

IFACE="${1:?Usage: $0 <monitor-interface>, e.g. eth1}"

if [ "$EUID" -ne 0 ]; then
  echo "Run as root (needed for package install + interface config)."
  exit 1
fi

echo "== Installing Suricata =="
if command -v apt-get &>/dev/null; then
  add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
  apt-get update
  apt-get install -y suricata jq
elif command -v dnf &>/dev/null; then
  dnf install -y epel-release
  dnf install -y suricata jq
else
  echo "Unsupported package manager. Install Suricata manually: https://suricata.io/download/"
  exit 1
fi

echo "== Updating rule sources (Emerging Threats Open) =="
suricata-update enable-source et/open
suricata-update

echo "== Configuring interface: $IFACE =="
sed -i "s/^\s*interface: .*/  - interface: ${IFACE}/" /etc/suricata/suricata.yaml || true
echo "eve-log (JSON alerts) is enabled by default in stock suricata.yaml — verify with:"
echo "  grep -A3 'eve-log:' /etc/suricata/suricata.yaml"

cat <<EOF

Suricata installed and pointed at interface: $IFACE
eve.json path (default): /var/log/suricata/eve.json

Enable promiscuous mode / mirroring on $IFACE at the switch or hypervisor
level (Nutanix AHV: configure a port mirror / SPAN session on the vSwitch,
or if this VM sits inline, no mirroring needed).

Start it:
  systemctl enable --now suricata
  tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

Feed it into Wazuh — add this to the Wazuh agent's ossec.conf on THIS host
(install the Wazuh agent here too if this isn't already siem01):

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>

Wazuh ships built-in Suricata decoders/rules, so alerts should appear in the
dashboard immediately. The local_rules.xml frequency rules (100011/100012)
add scan-detection thresholds on top of the raw signature hits.
EOF
