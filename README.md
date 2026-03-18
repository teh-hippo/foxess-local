# foxess-local

Local interception and decoding of FoxESS solar inverter data.

The FoxESS WiFi dongle uploads inverter data to remote servers over a custom binary protocol on TLS port 14431.
This project intercepts that traffic via a transparent TLS relay, decodes the binary frames, and stores decoded sensor readings in a local SQLite database.
The FoxESS cloud still receives all data normally — the relay is transparent.

## Quick start

```bash
# 1. Configure
cp .env.example .env
# Edit .env with your IPs, UniFi token, etc.

# 2. Generate TLS cert (one-time)
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.pem \
  -days 36500 -nodes -subj "/C=CN/ST=JiangSu/L=Wuxi/O=FoxESS/CN=monitor"

# 3. Set up network isolation + NAT rules
uv run foxess-network setup

# 4. Start the relay
uv run foxess-relay

# 5. Watch live stats
uv run foxess-live
```

## Commands

| Command | Description |
|---------|-------------|
| `uv run foxess-relay` | Start the TLS relay (writes to `data/foxess.db`) |
| `uv run foxess-live` | Live dashboard, updates every ~90s |
| `uv run foxess-live --once` | Print latest reading and exit |
| `uv run foxess-decode` | Show recent readings from database |
| `uv run foxess-decode --latest --json` | Latest reading as JSON |
| `uv run foxess-network setup` | Create isolated IoT network + NAT rules |
| `uv run foxess-network status` | Check network isolation status |
| `uv run foxess-network teardown` | Remove all managed network rules |

## ⚠️ Security: isolate the dongle

The FoxESS WiFi datalogger has a permanently broadcasting WiFi AP with a hardcoded password (`mtmt2020`) that cannot be changed.
Anyone within range can connect and retrieve the home WiFi password in cleartext — no interaction required.

**If the dongle is on your main network, a stolen password gives full LAN access.**

Place the dongle on an isolated VLAN WiFi with `foxess-network setup`.
The leaked password then only grants access to a network with one device on it.

See [docs/PROTOCOL.md §7](docs/PROTOCOL.md) for the full vulnerability details.

## Network setup

The dongle connects to a hardcoded IP on port 14431.
A DNAT rule on the router redirects this traffic to the relay.

`foxess-network` manages this via the UniFi API (no SSH required).
For non-UniFi routers:

```bash
iptables -t nat -A PREROUTING -s $DONGLE_IP -p tcp --dport 14431 -j DNAT --to-destination $RELAY_HOST
```

With VLAN isolation (dongle on a separate subnet), no MASQUERADE is needed — cross-VLAN routing handles the return path.

## Protocol

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full specification.

22 sensor fields decoded and verified against the FoxESS Cloud API.
2600+ frames captured with 0 CRC mismatches across 3 days.

## Development (WSL)

The relay runs in WSL. LAN devices can't reach WSL directly — Windows `netsh portproxy` bridges the gap.

```powershell
# Find WSL IP
wsl hostname -I

# Forward port 14431 from Windows to WSL
netsh interface portproxy add v4tov4 listenport=14431 listenaddress=0.0.0.0 connectport=14431 connectaddress=<WSL_IP>
netsh advfirewall firewall add rule name="FoxESS Local Proxy" dir=in action=allow protocol=TCP localport=14431

# WSL IP changes on restart — update the portproxy accordingly
```
