"""Manage IoT network isolation for the FoxESS datalogger via UniFi API.

Creates a dedicated VLAN + WiFi SSID so the dongle's leaked WiFi password
only grants access to an isolated network, not the main LAN.

Usage:
    foxess-network setup      # Create network, SSID, firewall, NAT
    foxess-network teardown   # Remove everything (reverse order)
    foxess-network status     # Read-only health check
    foxess-network migrate    # Send netSet to dongle (needs AP connection)
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.request
from dataclasses import dataclass

# Tag all managed resources for idempotent find-or-create.
TAG = "foxess-local"


@dataclass
class Config:
    unifi_url: str
    unifi_token: str
    relay_host: str
    dongle_ip: str
    dongle_mac: str
    upstream_port: str
    iot_vlan_id: int
    iot_subnet: str
    iot_ssid_name: str
    iot_ssid_password: str
    iot_dongle_ip: str

    @classmethod
    def from_env(cls) -> Config:
        def req(key: str) -> str:
            val = os.environ.get(key)
            if not val:
                print(f"error: {key} not set", file=sys.stderr)
                sys.exit(1)
            return val

        return cls(
            unifi_url=req("UNIFI_URL"),
            unifi_token=req("UNIFI_TOKEN"),
            relay_host=req("FOXESS_RELAY_HOST"),
            dongle_ip=req("FOXESS_DONGLE_IP"),
            dongle_mac=os.environ.get("FOXESS_DONGLE_MAC", "your-dongle-mac-address"),
            upstream_port=os.environ.get("FOXESS_UPSTREAM_PORT", "14431"),
            iot_vlan_id=int(os.environ.get("IOT_VLAN_ID", "3")),
            iot_subnet=os.environ.get("IOT_SUBNET", "192.168.3.1/24"),
            iot_ssid_name=req("IOT_SSID_NAME"),
            iot_ssid_password=req("IOT_SSID_PASSWORD"),
            iot_dongle_ip=req("IOT_DONGLE_FIXED_IP"),
        )


# ---------------------------------------------------------------------------
# UniFi HTTP helpers
# ---------------------------------------------------------------------------

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _req(url: str, token: str, method: str = "GET", data: dict | None = None) -> dict | list | None:
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("X-API-KEY", token)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_CTX) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"  ! API error {e.code} {method} {url.split('/site/')[1] if '/site/' in url else url.split('/default/')[1] if '/default/' in url else url}", file=sys.stderr)
        if body:
            print(f"    {body[:200]}", file=sys.stderr)
        raise


def api_v1(cfg: Config, path: str, method: str = "GET", data: dict | None = None):
    """Call the v1 REST API (networkconf, wlanconf, stat)."""
    url = f"{cfg.unifi_url}/proxy/network/api/s/default/{path}"
    result = _req(url, cfg.unifi_token, method, data)
    if isinstance(result, dict):
        return result.get("data", result)
    return result


def api_v2(cfg: Config, path: str, method: str = "GET", data: dict | None = None):
    """Call the v2 API (nat, firewall-policies)."""
    url = f"{cfg.unifi_url}/proxy/network/v2/api/site/default/{path}"
    return _req(url, cfg.unifi_token, method, data)


# ---------------------------------------------------------------------------
# Find helpers
# ---------------------------------------------------------------------------

def find_network(cfg: Config) -> dict | None:
    for n in api_v1(cfg, "rest/networkconf"):
        if n.get("vlan") == cfg.iot_vlan_id and n.get("vlan_enabled"):
            return n
    return None


def find_wlan(cfg: Config) -> dict | None:
    for w in api_v1(cfg, "rest/wlanconf"):
        if w.get("name") == cfg.iot_ssid_name:
            return w
    return None


def find_fw_rules(cfg: Config) -> list[dict]:
    return [r for r in (api_v2(cfg, "firewall-policies") or [])
            if r.get("name", "").startswith("IoT:") and not r.get("predefined")]


def find_nat_rules(cfg: Config) -> list[dict]:
    return [r for r in (api_v2(cfg, "nat") or [])
            if TAG in r.get("description", "").lower() or "foxess" in r.get("description", "").lower()]


def find_dongle(cfg: Config) -> dict | None:
    for c in api_v1(cfg, "stat/sta"):
        if c.get("mac") == cfg.dongle_mac:
            return c
    return None


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def _iot_dhcp_start(subnet: str) -> str:
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    return f"{base}.100"


def _iot_dhcp_stop(subnet: str) -> str:
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    return f"{base}.254"


def cmd_setup(cfg: Config) -> bool:
    ok = True

    # 1. Network
    net = find_network(cfg)
    if net:
        print(f"  ✓ Network '{net['name']}' exists (vlan={cfg.iot_vlan_id}, id={net['_id']})")
    else:
        print(f"  + Creating VLAN {cfg.iot_vlan_id} network...")
        net = api_v1(cfg, "rest/networkconf", "POST", {
            "name": "IoT",
            "purpose": "corporate",
            "setting_preference": "manual",
            "vlan_enabled": True,
            "vlan": cfg.iot_vlan_id,
            "ip_subnet": cfg.iot_subnet,
            "dhcpd_enabled": True,
            "dhcpd_start": _iot_dhcp_start(cfg.iot_subnet),
            "dhcpd_stop": _iot_dhcp_stop(cfg.iot_subnet),
            "internet_access_enabled": True,
            "network_isolation_enabled": True,
            "is_nat": True,
            "enabled": True,
            "networkgroup": "LAN",
        })
        if isinstance(net, list):
            net = net[0]
        print(f"    id={net['_id']}, zone={net.get('firewall_zone_id', '?')}")
    net_id = net["_id"]
    zone_id = net.get("firewall_zone_id")

    # 2. WLAN
    wlan = find_wlan(cfg)
    if wlan:
        print(f"  ✓ SSID '{cfg.iot_ssid_name}' exists (id={wlan['_id']})")
    else:
        # Get AP group from existing WLAN
        existing_wlans = api_v1(cfg, "rest/wlanconf")
        ap_groups = existing_wlans[0].get("ap_group_ids", []) if existing_wlans else []

        print(f"  + Creating SSID '{cfg.iot_ssid_name}'...")
        wlan = api_v1(cfg, "rest/wlanconf", "POST", {
            "name": cfg.iot_ssid_name,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "wpa_enc": "ccmp",
            "x_passphrase": cfg.iot_ssid_password,
            "networkconf_id": net_id,
            "enabled": True,
            "l2_isolation": True,
            "wlan_band": "both",
            "ap_group_mode": "all",
            "ap_group_ids": ap_groups,
            "setting_preference": "manual",
        })
        if isinstance(wlan, list):
            wlan = wlan[0]
        print(f"    id={wlan['_id']}")

    # 3. Firewall rules
    # Find the Default LAN zone from existing networks.
    default_zone = None
    for n in api_v1(cfg, "rest/networkconf"):
        if n.get("name") == "Default":
            default_zone = n.get("firewall_zone_id")
            break

    existing_fw = find_fw_rules(cfg)
    if existing_fw:
        print(f"  ✓ Firewall rules exist ({len(existing_fw)} rules)")
    elif zone_id and default_zone:
        print("  + Creating firewall rules...")
        _fw_base = {
            "enabled": True,
            "ip_version": "IPV4",
            "logging": False,
            "connection_state_type": "ALL",
            "connection_states": [],
            "match_ip_sec": False,
            "match_opposite_protocol": False,
            "icmp_typename": "ANY",
            "icmp_v6_typename": "ANY",
            "schedule": {"mode": "ALWAYS"},
        }
        # Allow IoT → relay (exception to network isolation)
        api_v2(cfg, "firewall-policies", "POST", {
            **_fw_base,
            "name": "IoT: Allow Relay",
            "action": "ALLOW",
            "protocol": "tcp",
            "index": 2000,
            "source": {
                "zone_id": zone_id,
                "matching_target": "ANY",
                "port_matching_type": "ANY",
                "match_opposite_ports": False,
            },
            "destination": {
                "zone_id": default_zone,
                "matching_target": "IP",
                "matching_target_type": "SPECIFIC",
                "ips": [cfg.relay_host],
                "match_opposite_ips": False,
                "port_matching_type": "SPECIFIC",
                "port": cfg.upstream_port,
                "match_opposite_ports": False,
            },
        })
        print("    + Allow IoT → relay")

        # Block is handled by network_isolation_enabled on the network.
        # This is more reliable than custom same-zone firewall rules.
    else:
        print("  ! Could not determine zone IDs — create firewall rules manually")
        ok = False

    # 4. NAT rules
    existing_nat = find_nat_rules(cfg)
    if existing_nat:
        print(f"  ✓ NAT rules exist ({len(existing_nat)} rules)")
        # Check if in_interface needs updating (remove it for VLAN-agnostic matching).
        for r in existing_nat:
            if r.get("type") == "DNAT" and r.get("in_interface"):
                print("    ~ Removing in_interface from DNAT rule...")
                updated = {k: v for k, v in r.items() if k not in ("_id", "in_interface")}
                api_v2(cfg, f"nat/{r['_id']}", "PUT", updated)
                print("    ✓ DNAT rule updated (VLAN-agnostic)")
    else:
        print("  + Creating NAT rules...")
        _nat_filter = {
            "filter_type": "ADDRESS_AND_PORT",
            "firewall_group_ids": [],
            "invert_address": False,
            "invert_port": False,
        }

        # Use the IoT subnet for NAT source — works regardless of DHCP vs fixed IP.
        iot_net = cfg.iot_subnet.rsplit(".", 1)[0] + ".0/24"

        api_v2(cfg, "nat", "POST", {
            "description": f"FoxESS Solar Relay ({TAG})",
            "type": "DNAT",
            "enabled": True,
            "protocol": "tcp",
            "ip_version": "IPV4",
            "ip_address": cfg.relay_host,
            "source_filter": {**_nat_filter, "address": iot_net},
            "destination_filter": {**_nat_filter, "port": cfg.upstream_port},
            "logging": False,
            "exclude": False,
            "pppoe_use_base_interface": False,
            "rule_index": 0,
            "setting_preference": "manual",
            "is_predefined": False,
        })
        print("    + DNAT")
        # No MASQUERADE needed — cross-VLAN routing handles the return path.
        # MASQUERADE was only needed for same-subnet hairpin NAT.

    return ok


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def cmd_teardown(cfg: Config) -> None:
    # Reverse order: NAT → firewall → WLAN → network
    for r in find_nat_rules(cfg):
        print(f"  - NAT: {r['description']} ({r['_id']})")
        api_v2(cfg, f"nat/{r['_id']}", "DELETE")

    for r in find_fw_rules(cfg):
        print(f"  - Firewall: {r['name']} ({r['_id']})")
        api_v2(cfg, f"firewall-policies/{r['_id']}", "DELETE")

    wlan = find_wlan(cfg)
    if wlan:
        print(f"  - WLAN: {wlan['name']} ({wlan['_id']})")
        api_v1(cfg, f"rest/wlanconf/{wlan['_id']}", "DELETE")

    net = find_network(cfg)
    if net:
        print(f"  - Network: {net['name']} ({net['_id']})")
        api_v1(cfg, f"rest/networkconf/{net['_id']}", "DELETE")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def cmd_status(cfg: Config) -> None:
    net = find_network(cfg)
    print(f"  Network:  {'✓ ' + net['name'] + ' (id=' + net['_id'] + ')' if net else '✗ not found'}")

    wlan = find_wlan(cfg)
    print(f"  SSID:     {'✓ ' + wlan['name'] if wlan else '✗ not found'}")

    fw = find_fw_rules(cfg)
    print(f"  Firewall: {'✓ ' + str(len(fw)) + ' rules' if fw else '✗ no rules'}")

    nat = find_nat_rules(cfg)
    print(f"  NAT:      {'✓ ' + str(len(nat)) + ' rules' if nat else '✗ no rules'}")
    for r in nat:
        src = r.get("source_filter", {}).get("address", "?")
        iface = r.get("in_interface", "none")
        print(f"            {r['type']}: src={src}, in_interface={iface}")

    dongle = find_dongle(cfg)
    if dongle:
        print(f"  Dongle:   ✓ ip={dongle['ip']}, network={dongle.get('network', '?')}, essid={dongle.get('essid', '?')}")
    else:
        print("  Dongle:   ✗ not connected")


# ---------------------------------------------------------------------------
# Migrate
# ---------------------------------------------------------------------------

def cmd_migrate(cfg: Config) -> None:
    print("  To migrate the dongle to the IoT network:")
    print(f"  1. Connect to the dongle's WiFi AP (W-XXXXXXX / mtmt2020)")
    print(f"  2. Open a WebSocket to ws://192.168.1.1/")
    print(f"  3. Wait for the netInit response")
    print(f'  4. Send: {{"fun": "netSet", "ssid": "{cfg.iot_ssid_name}", "password": "{cfg.iot_ssid_password}"}}')
    print(f"  5. Dongle reboots (~60s), joins '{cfg.iot_ssid_name}'")
    print(f"  6. Run 'foxess-network status' to verify")
    print()
    print("  After migration, update the dongle's fixed IP:")
    print(f"    Current: {cfg.dongle_ip}")
    print(f"    Target:  {cfg.iot_dongle_ip}")
    print(f"  Assign via UniFi UI: Clients → Solar Panel → Fixed IP → {cfg.iot_dongle_ip}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="foxess-network",
        description="Manage IoT network isolation for the FoxESS datalogger.",
    )
    parser.add_argument("command", choices=["setup", "teardown", "status", "migrate"])
    args = parser.parse_args()

    cfg = Config.from_env()
    print(f"foxess-network {args.command}")

    if args.command == "setup":
        cmd_setup(cfg)
    elif args.command == "teardown":
        cmd_teardown(cfg)
    elif args.command == "status":
        cmd_status(cfg)
    elif args.command == "migrate":
        cmd_migrate(cfg)


if __name__ == "__main__":
    main()
