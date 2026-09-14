#!/usr/bin/env bash
# Deploys a single-node Wazuh stack (manager + indexer + dashboard) via the
# official wazuh-docker repo. Run this on the Linux VM that will be siem01.
#
# Usage: ./deploy_wazuh.sh [wazuh-docker-tag]
# Default tag tracks the latest stable 4.x release line.

set -euo pipefail

WAZUH_TAG="${1:-v4.9.2}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/wazuh-docker}"

echo "== Home SOC Lab: Wazuh deploy (tag $WAZUH_TAG) =="

if ! command -v docker &>/dev/null; then
  echo "Docker is required. Install it first: https://docs.docker.com/engine/install/"
  exit 1
fi
if ! docker compose version &>/dev/null; then
  echo "docker compose (v2 plugin) is required."
  exit 1
fi

# Wazuh indexer (OpenSearch-based) needs this sysctl bump, same as Elasticsearch.
CURRENT_MAX_MAP=$(sysctl -n vm.max_map_count)
if [ "$CURRENT_MAX_MAP" -lt 262144 ]; then
  echo "Raising vm.max_map_count to 262144 (needs sudo)..."
  sudo sysctl -w vm.max_map_count=262144
  grep -q '^vm.max_map_count' /etc/sysctl.conf 2>/dev/null || \
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf >/dev/null
fi

if [ ! -d "$INSTALL_DIR" ]; then
  git clone --branch "$WAZUH_TAG" --depth 1 https://github.com/wazuh/wazuh-docker.git "$INSTALL_DIR"
else
  echo "$INSTALL_DIR already exists, reusing it."
fi

cd "$INSTALL_DIR/single-node"

echo "Generating TLS certificates for indexer/dashboard..."
docker compose -f generate-indexer-certs.yml run --rm generator

echo "Copying in home-soc-lab custom detections..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p config/wazuh_cluster
cp "$SCRIPT_DIR/custom_rules/local_rules.xml" config/wazuh_cluster/ 2>/dev/null || true
cp "$SCRIPT_DIR/custom_decoders/local_decoder.xml" config/wazuh_cluster/ 2>/dev/null || true

cat <<'EOF'

IMPORTANT (manual, one-time): wazuh-docker mounts custom rules/decoders via
docker-compose.yml volume entries. Add these two lines under the
wazuh.manager service's `volumes:` section in single-node/docker-compose.yml
before starting, if they're not already there:

  - ./config/wazuh_cluster/local_rules.xml:/var/ossec/etc/rules/local_rules.xml
  - ./config/wazuh_cluster/local_decoder.xml:/var/ossec/etc/decoders/local_decoder.xml

EOF
read -rp "Press Enter once you've confirmed the volume mounts (or to skip if already present)..." _

echo "Starting the stack (manager, indexer, dashboard)..."
docker compose up -d

cat <<EOF

== Done ==
Dashboard: https://<this-host-ip>:443  (default admin / admin-on-first-boot,
                                          wazuh-docker prints/generates real
                                          creds — check config/wazuh_indexer/)
Manager enrollment port: 1515   Event port: 1514

Next steps:
  1. Log into the dashboard and change default passwords immediately.
  2. Enroll the Windows agent: see ../wazuh/agent_configs/README.md
  3. Point Nutanix syslog at this host, UDP 514 (open the port / firewall rule).
  4. Restart the manager after any further rule changes:
       docker compose restart wazuh.manager
EOF
