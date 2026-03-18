"""Manage IoT network isolation for the FoxESS datalogger via UniFi API.

Creates a dedicated VLAN + WiFi SSID so the dongle's leaked WiFi password
only grants access to an isolated network, not the main LAN.

Usage:
    foxess-network setup      # Create network, SSID, firewall, NAT (idempotent)
    foxess-network teardown   # Remove everything (requires --yes)
    foxess-network status     # Read-only health check
    foxess-network migrate    # Assign fixed IP after dongle joins IoT SSID
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from foxess_local.unifi import UniFiClient

DESCRIPTION_TAG = "foxess-local-managed"
FW_RULE_NAME = "IoT: Allow Relay"
DNAT_DESC = f"FoxESS Solar Relay ({DESCRIPTION_TAG})"


@dataclass
class Config:
    unifi_url: str
    unifi_token: str
    relay_host: str
    dongle_mac: str
    upstream_port: str
    iot_vlan_id: int
    iot_subnet: str
    iot_ssid_name: str
    iot_ssid_password: str
    iot_dongle_ip: str

    @property
    def iot_network_cidr(self) -> str:
        """Derive network CIDR from subnet (e.g. 192.168.3.1/24 → 192.168.3.0/24)."""
        base = self.iot_subnet.split("/")[0].rsplit(".", 1)[0]
        return f"{base}.0/24"

    @property
    def iot_dhcp_start(self) -> str:
        base = self.iot_subnet.split("/")[0].rsplit(".", 1)[0]
        return f"{base}.100"

    @property
    def iot_dhcp_stop(self) -> str:
        base = self.iot_subnet.split("/")[0].rsplit(".", 1)[0]
        return f"{base}.254"

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
            dongle_mac=req("FOXESS_DONGLE_MAC"),
            upstream_port=os.environ.get("FOXESS_UPSTREAM_PORT", "14431"),
            iot_vlan_id=int(os.environ.get("IOT_VLAN_ID", "3")),
            iot_subnet=os.environ.get("IOT_SUBNET", "192.168.3.1/24"),
            iot_ssid_name=req("IOT_SSID_NAME"),
            iot_ssid_password=req("IOT_SSID_PASSWORD"),
            iot_dongle_ip=req("IOT_DONGLE_FIXED_IP"),
        )

    def api(self) -> UniFiClient:
        return UniFiClient(self.unifi_url, self.unifi_token)


# ---------------------------------------------------------------------------
# Finders
# ---------------------------------------------------------------------------

def _find_network(api: UniFiClient, cfg: Config) -> dict | None:
    for n in api.v1("rest/networkconf"):
        if n.get("vlan") == cfg.iot_vlan_id and n.get("vlan_enabled"):
            return n
    return None


def _find_wlan(api: UniFiClient, cfg: Config) -> dict | None:
    for w in api.v1("rest/wlanconf"):
        if w.get("name") == cfg.iot_ssid_name:
            return w
    return None


def _find_fw_allow_rule(api: UniFiClient) -> dict | None:
    """Find our specific allow-relay firewall policy (not the auto-generated respond rule)."""
    for r in (api.v2("firewall-policies") or []):
        if r.get("name") == FW_RULE_NAME and not r.get("predefined"):
            return r
    return None


def _find_dnat_rule(api: UniFiClient) -> dict | None:
    for r in (api.v2("nat") or []):
        if DESCRIPTION_TAG in r.get("description", "") and r.get("type") == "DNAT":
            return r
    return None


def _find_all_managed_nat(api: UniFiClient) -> list[dict]:
    return [r for r in (api.v2("nat") or []) if DESCRIPTION_TAG in r.get("description", "")]


def _find_dongle(api: UniFiClient, cfg: Config) -> dict | None:
    for c in api.v1("stat/sta"):
        if c.get("mac") == cfg.dongle_mac:
            return c
    return None


def _find_default_zone(api: UniFiClient) -> str | None:
    for n in api.v1("rest/networkconf"):
        if n.get("name") == "Default":
            return n.get("firewall_zone_id")
    return None


# ---------------------------------------------------------------------------
# Setup (idempotent)
# ---------------------------------------------------------------------------

def cmd_setup(cfg: Config) -> bool:
    api = cfg.api()
    ok = True

    # 1. Network
    net = _find_network(api, cfg)
    if net:
        print(f"  ✓ Network '{net['name']}' (vlan={cfg.iot_vlan_id})")
    else:
        print(f"  + Creating VLAN {cfg.iot_vlan_id} network...")
        result = api.v1("rest/networkconf", "POST", {
            "name": "IoT",
            "purpose": "corporate",
            "setting_preference": "manual",
            "vlan_enabled": True,
            "vlan": cfg.iot_vlan_id,
            "ip_subnet": cfg.iot_subnet,
            "dhcpd_enabled": True,
            "dhcpd_start": cfg.iot_dhcp_start,
            "dhcpd_stop": cfg.iot_dhcp_stop,
            "internet_access_enabled": True,
            "network_isolation_enabled": True,
            "is_nat": True,
            "enabled": True,
            "networkgroup": "LAN",
        })
        net = result[0] if isinstance(result, list) else result
        print(f"    ✓ Created (id={net['_id']})")
    net_id = net["_id"]
    zone_id = net.get("firewall_zone_id")

    # 2. WLAN (2.4GHz only — dongle is ESP32)
    wlan = _find_wlan(api, cfg)
    if wlan:
        print(f"  ✓ SSID '{cfg.iot_ssid_name}'")
    else:
        existing_wlans = api.v1("rest/wlanconf")
        ap_groups = existing_wlans[0].get("ap_group_ids", []) if existing_wlans else []
        print(f"  + Creating SSID '{cfg.iot_ssid_name}'...")
        result = api.v1("rest/wlanconf", "POST", {
            "name": cfg.iot_ssid_name,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "wpa_enc": "ccmp",
            "x_passphrase": cfg.iot_ssid_password,
            "networkconf_id": net_id,
            "enabled": True,
            "l2_isolation": True,
            "wlan_band": "2g",
            "ap_group_mode": "all",
            "ap_group_ids": ap_groups,
            "setting_preference": "manual",
        })
        wlan = result[0] if isinstance(result, list) else result
        print(f"    ✓ Created (id={wlan['_id']})")

    # 3. Firewall — allow relay through network isolation
    fw = _find_fw_allow_rule(api)
    default_zone = _find_default_zone(api)
    if fw:
        print("  ✓ Firewall allow-relay rule")
    elif zone_id and default_zone:
        print("  + Creating firewall allow-relay rule...")
        api.v2("firewall-policies", "POST", {
            "name": FW_RULE_NAME,
            "enabled": True,
            "action": "ALLOW",
            "protocol": "tcp",
            "ip_version": "IPV4",
            "index": 2000,
            "logging": False,
            "connection_state_type": "ALL",
            "connection_states": [],
            "match_ip_sec": False,
            "match_opposite_protocol": False,
            "icmp_typename": "ANY",
            "icmp_v6_typename": "ANY",
            "schedule": {"mode": "ALWAYS"},
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
        print("    ✓ Created")
    else:
        print("  ! Could not determine zone IDs — create firewall rule manually")
        ok = False

    # 4. DNAT — redirect dongle traffic to relay (no MASQUERADE needed cross-VLAN)
    dnat = _find_dnat_rule(api)
    if dnat:
        src = dnat.get("source_filter", {}).get("address", "?")
        print(f"  ✓ DNAT rule (src={src})")
        if dnat.get("in_interface"):
            updated = {k: v for k, v in dnat.items() if k not in ("_id", "in_interface")}
            api.v2(f"nat/{dnat['_id']}", "PUT", updated)
            print("    ~ Removed in_interface (now VLAN-agnostic)")
    else:
        print("  + Creating DNAT rule...")
        _filter = {"filter_type": "ADDRESS_AND_PORT", "firewall_group_ids": [],
                    "invert_address": False, "invert_port": False}
        api.v2("nat", "POST", {
            "description": DNAT_DESC,
            "type": "DNAT",
            "enabled": True,
            "protocol": "tcp",
            "ip_version": "IPV4",
            "ip_address": cfg.relay_host,
            "source_filter": {**_filter, "address": cfg.iot_network_cidr},
            "destination_filter": {**_filter, "port": cfg.upstream_port},
            "logging": False,
            "exclude": False,
            "pppoe_use_base_interface": False,
            "rule_index": 0,
            "setting_preference": "manual",
            "is_predefined": False,
        })
        print("    ✓ Created")

    return ok


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def cmd_teardown(cfg: Config, force: bool = False) -> None:
    api = cfg.api()
    nat = _find_all_managed_nat(api)
    fw = _find_fw_allow_rule(api)
    wlan = _find_wlan(api, cfg)
    net = _find_network(api, cfg)

    items = []
    if nat:
        items += [f"NAT: {r['description']}" for r in nat]
    if fw:
        items.append(f"Firewall: {fw['name']}")
    if wlan:
        items.append(f"WLAN: {wlan['name']}")
    if net:
        items.append(f"Network: {net['name']}")

    if not items:
        print("  Nothing to remove.")
        return

    print("  Will remove:")
    for item in items:
        print(f"    - {item}")

    if not force:
        print("\n  Pass --yes to confirm teardown.")
        return

    for r in nat:
        api.v2(f"nat/{r['_id']}", "DELETE")
        print(f"  - {r['description']}")
    if fw:
        api.v2(f"firewall-policies/{fw['_id']}", "DELETE")
        print(f"  - {fw['name']}")
    if wlan:
        api.v1(f"rest/wlanconf/{wlan['_id']}", "DELETE")
        print(f"  - {wlan['name']}")
    if net:
        api.v1(f"rest/networkconf/{net['_id']}", "DELETE")
        print(f"  - {net['name']}")
    print("  ✓ Teardown complete")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def cmd_status(cfg: Config) -> None:
    api = cfg.api()
    net = _find_network(api, cfg)
    if net:
        isolated = net.get("network_isolation_enabled", False)
        tag = "✓" if isolated else "⚠ isolation OFF"
        print(f"  Network:  {tag} {net['name']} (vlan={cfg.iot_vlan_id}, isolated={isolated})")
    else:
        print("  Network:  ✗ not found")

    wlan = _find_wlan(api, cfg)
    if wlan:
        l2 = wlan.get("l2_isolation", False)
        band = wlan.get("wlan_band", "?")
        tag = "✓" if l2 else "⚠ l2_isolation OFF"
        print(f"  SSID:     {tag} {wlan['name']} (band={band}, l2_isolation={l2})")
    else:
        print("  SSID:     ✗ not found")

    fw = _find_fw_allow_rule(api)
    print(f"  Firewall: {'✓ allow-relay rule' if fw else '✗ no allow-relay rule'}")

    dnat = _find_dnat_rule(api)
    if dnat:
        src = dnat.get("source_filter", {}).get("address", "?")
        iface = dnat.get("in_interface")
        warn = " ⚠ has in_interface" if iface else ""
        print(f"  DNAT:     ✓ src={src}{warn}")
    else:
        print("  DNAT:     ✗ not found")

    dongle = _find_dongle(api, cfg)
    if dongle:
        ip = dongle.get("ip", "?")
        net_name = dongle.get("network", "?")
        ssid = dongle.get("essid", "?")
        on_iot = cfg.iot_ssid_name in str(ssid)
        tag = "✓" if on_iot else "⚠ not on IoT"
        print(f"  Dongle:   {tag} ip={ip}, network={net_name}, essid={ssid}")
    else:
        print("  Dongle:   ✗ not connected")


# ---------------------------------------------------------------------------
# Migrate — assign fixed IP after dongle has joined IoT SSID
# ---------------------------------------------------------------------------

def cmd_migrate(cfg: Config) -> None:
    api = cfg.api()
    dongle = _find_dongle(api, cfg)
    if not dongle:
        print("  ✗ Dongle not connected. Connect it to the IoT SSID first:")
        print("    1. Join dongle AP (W-XXXXXXX / mtmt2020)")
        print("    2. Open http://192.168.1.1/")
        print(f'    3. Set WiFi to "{cfg.iot_ssid_name}" with the configured password')
        print("    4. Dongle reboots (~60s), then re-run this command")
        return

    ssid = dongle.get("essid", "")
    if cfg.iot_ssid_name not in ssid:
        print(f"  ⚠ Dongle is on '{ssid}', not '{cfg.iot_ssid_name}'")
        print("    Reconfigure via dongle AP → http://192.168.1.1/")
        return

    current_ip = dongle.get("ip", "?")
    client_id = dongle["_id"]
    net = _find_network(api, cfg)

    if current_ip == cfg.iot_dongle_ip:
        print(f"  ✓ Dongle already at fixed IP {cfg.iot_dongle_ip}")
    else:
        print(f"  Dongle at {current_ip} (DHCP), assigning fixed IP {cfg.iot_dongle_ip}...")
        api.v1(f"rest/user/{client_id}", "PUT", {
            "use_fixedip": True,
            "fixed_ip": cfg.iot_dongle_ip,
            "network_id": net["_id"] if net else "",
        })
        print("  ✓ Fixed IP assigned. Takes effect on next DHCP renewal.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="foxess-network",
        description="Manage IoT network isolation for the FoxESS datalogger.",
    )
    parser.add_argument("command", choices=["setup", "teardown", "status", "migrate"])
    parser.add_argument("--yes", action="store_true", help="Confirm destructive operations")
    args = parser.parse_args()

    cfg = Config.from_env()
    print(f"foxess-network {args.command}")

    match args.command:
        case "setup":
            if not cmd_setup(cfg):
                sys.exit(1)
        case "teardown":
            cmd_teardown(cfg, force=args.yes)
        case "status":
            cmd_status(cfg)
        case "migrate":
            cmd_migrate(cfg)


if __name__ == "__main__":
    main()
