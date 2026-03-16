#!/usr/bin/env bash
# Install the FoxESS local proxy — UniFi NAT rules via API.
#
# Creates two persistent NAT rules in UniFi (survive reboots):
#   1. DNAT: redirect dongle → cloud to relay host
#   2. MASQUERADE: hairpin NAT for same-subnet redirect
#
# These are managed by UniFi and visible in the Policy Engine UI.
# No SSH needed.
#
# To undo: ./scripts/uninstall.sh
set -euo pipefail

UNIFI_URL="${UNIFI_URL:?Set UNIFI_URL (e.g. https://192.168.0.1)}"
UNIFI_TOKEN="${UNIFI_TOKEN:?Set UNIFI_TOKEN (UniFi API key)}"
NETWORK_ID="${UNIFI_NETWORK_ID:?Set UNIFI_NETWORK_ID (network _id from UniFi)}"

DONGLE_IP="${FOXESS_DONGLE_IP:?Set FOXESS_DONGLE_IP}"
CLOUD_PORT="${FOXESS_UPSTREAM_PORT:-14431}"
RELAY_HOST="${FOXESS_RELAY_HOST:?Set FOXESS_RELAY_HOST}"

NAT_API="$UNIFI_URL/proxy/network/v2/api/site/default/nat"

echo "FoxESS local proxy — install (UniFi API)"
echo "  Dongle:  $DONGLE_IP:* → *:$CLOUD_PORT"
echo "  Relay:   $RELAY_HOST:$CLOUD_PORT"
echo ""

# Check for existing rules
EXISTING=$(curl -sk "$NAT_API" -H "X-API-KEY: $UNIFI_TOKEN" 2>&1)
if echo "$EXISTING" | grep -q "FoxESS Solar Relay"; then
  echo "Rules already exist. Use uninstall.sh first to recreate."
  echo "$EXISTING" | python3 -c "import json,sys; [print(f'  {r[\"type\"]}: {r[\"description\"]} (id={r[\"_id\"]})') for r in json.load(sys.stdin)]"
  exit 0
fi

# Create DNAT rule
echo "Creating DNAT rule..."
DNAT_RESULT=$(curl -sk -X POST "$NAT_API" \
  -H "X-API-KEY: $UNIFI_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"description\": \"FoxESS Solar Relay\",
    \"type\": \"DNAT\",
    \"enabled\": true,
    \"protocol\": \"tcp\",
    \"ip_version\": \"IPV4\",
    \"ip_address\": \"$RELAY_HOST\",
    \"in_interface\": \"$NETWORK_ID\",
    \"source_filter\": {
      \"address\": \"$DONGLE_IP\",
      \"filter_type\": \"ADDRESS_AND_PORT\",
      \"firewall_group_ids\": [],
      \"invert_address\": false,
      \"invert_port\": false
    },
    \"destination_filter\": {
      \"filter_type\": \"ADDRESS_AND_PORT\",
      \"firewall_group_ids\": [],
      \"invert_address\": false,
      \"invert_port\": false,
      \"port\": \"$CLOUD_PORT\"
    },
    \"logging\": false,
    \"exclude\": false,
    \"pppoe_use_base_interface\": false,
    \"rule_index\": 0,
    \"setting_preference\": \"manual\",
    \"is_predefined\": false
  }" 2>&1)
echo "  + DNAT: $(echo "$DNAT_RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('_id','FAILED'))" 2>/dev/null || echo "FAILED")"

# Create MASQUERADE rule (hairpin NAT)
echo "Creating MASQUERADE rule..."
MASQ_RESULT=$(curl -sk -X POST "$NAT_API" \
  -H "X-API-KEY: $UNIFI_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"description\": \"FoxESS Solar Relay - Hairpin MASQ\",
    \"type\": \"MASQUERADE\",
    \"enabled\": true,
    \"protocol\": \"tcp\",
    \"ip_version\": \"IPV4\",
    \"source_filter\": {
      \"address\": \"$DONGLE_IP\",
      \"filter_type\": \"ADDRESS_AND_PORT\",
      \"firewall_group_ids\": [],
      \"invert_address\": false,
      \"invert_port\": false
    },
    \"destination_filter\": {
      \"address\": \"$RELAY_HOST\",
      \"filter_type\": \"ADDRESS_AND_PORT\",
      \"firewall_group_ids\": [],
      \"invert_address\": false,
      \"invert_port\": false,
      \"port\": \"$CLOUD_PORT\"
    },
    \"logging\": false,
    \"exclude\": false,
    \"pppoe_use_base_interface\": false,
    \"rule_index\": 1,
    \"setting_preference\": \"manual\",
    \"is_predefined\": false
  }" 2>&1)
echo "  + MASQUERADE: $(echo "$MASQ_RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('_id','FAILED'))" 2>/dev/null || echo "FAILED")"

echo ""
echo "Done. Rules are persistent (survive router reboot)."
echo "Start the relay: uv run foxess-relay"
