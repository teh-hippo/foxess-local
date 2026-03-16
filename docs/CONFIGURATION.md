# FoxESS Datalogger Configuration Interface

> Based on analysis of the Anatel Smart WiFi V2.0 / V3.0 USB Datalogger web interface.
> Source: traffic capture (HAR), JavaScript decompilation, and CVE research.

## 1. Access

The datalogger runs a web server and WebSocket on port 80.
It is accessible from two networks simultaneously:

| Network | Address | Access method |
|---------|---------|--------------|
| Dongle AP | `http://192.168.1.1/` | Connect to the dongle's WiFi AP (`W-XXXXXXX`) |
| LAN | `http://<dongle-ip>/` | Port 80 accepts TCP but may not respond to HTTP from the LAN in all firmware versions |

The dongle AP broadcasts continuously, even when the dongle is connected to the home WiFi in STA (client) mode.
There is no way to disable the AP.

### AP Credentials

| Property | Value |
|----------|-------|
| SSID | `W-` followed by the last 7 digits of the datalogger serial number |
| Password | `mtmt2020` (universal default, cannot be changed) |
| Encryption | WPA2 |
| Auth | None beyond the AP password — no login page, no serial number check |

## 2. WebSocket Protocol

The interface uses a single WebSocket connection at `ws://<address>/`.
Communication is JSON-based.
The server sends an initial state dump on connect, and the client sends commands as JSON with a `fun` field identifying the action.

### 2.1 Heartbeat

The client sends the string `heart` (not JSON) every 5 seconds to keep the connection alive.
Server timeout is 35 seconds.

### 2.2 Initial State — `netInit` (Server → Client)

Sent automatically on WebSocket connect.
Contains all device configuration **including the WiFi password in cleartext**.

```json
{
  "result": {
    "sn": "<datalogger:serial-number>",
    "ip": "<dongle:lan-ip>",
    "firm": "1.24",
    "password": "<HOME WIFI PASSWORD IN CLEARTEXT>",
    "nowport": "1",
    "maxportN": "5",
    "lap": "<home:wifi-ssid>",
    "mac": "<dongle:mac-address>",
    "ssid": ["<home:wifi-ssid>", "<neighbour:ssid>", "..."],
    "solf": "1.03"
  },
  "fun": "netInit"
}
```

| Field | Description |
|-------|-------------|
| `sn` | Datalogger module serial number |
| `ip` | Current STA (client) IP address on the home network |
| `firm` | Master firmware version |
| `solf` | Slave firmware version |
| `password` | **Home WiFi password in cleartext** |
| `nowport` | Current RS485 port number |
| `maxportN` | Maximum available RS485 ports |
| `lap` | Currently connected WiFi SSID |
| `mac` | Datalogger MAC address |
| `ssid` | List of visible WiFi networks (from last scan) |

### 2.3 WiFi Scan — `netScan` (Client → Server)

Triggers a WiFi network scan.
The dongle scans for available SSIDs.

```json
{"fun": "netScan"}
```

Response: a new `netInit` message with an updated `ssid` list.

### 2.4 WiFi Configuration — `netSet` (Client → Server)

Changes the WiFi network the dongle connects to.
**This sends the new password in cleartext over the WebSocket.**

```json
{"fun": "netSet", "ssid": "NewNetwork", "password": "NewPassword"}
```

Response:
```json
{"fun": "netResult", "result": 1}
```
Where `result`: `1` = success, other values = failure.

### 2.5 RS485 Port Selection — `portSet` (Client → Server)

Changes which RS485 port the datalogger communicates on.
Valid range: 1 to `maxportN` (typically 5).

```json
{"fun": "portSet", "port": "1"}
```

Response:
```json
{"fun": "portSet"}
```

### 2.6 Firmware Upgrade — `upFile` (Client → Server)

Uploads new firmware to the datalogger.
The process:

1. Client sends header: `{"fun": "upFile", "size": <bytes>, "sum": <checksum>}`
2. Server responds with `{"fun": "upPack", "result": <status>}`
3. Client sends firmware binary in 1024-byte chunks as raw ArrayBuffer
4. Server sends `upPack` status after each chunk:
   - `result >= 0 && < 32768`: continue sending
   - `result > 32768 && < 65535`: complete (100%)
   - `result == 65535`: failure

**Constraints:**
- Firmware file must have `.bin` extension
- Maximum size: 76 KB (`1024 * 76`)
- Checksum: simple byte sum modulo 256

**No authentication or signature verification is documented.** The checksum is a trivial byte sum, not a cryptographic signature.

### 2.7 HTML Interface Fields

The web page exposes these read/write fields:

| Field ID | Type | Description |
|----------|------|-------------|
| `ip` | Read-only | Current LAN IP address |
| `mac` | Read-only | MAC address |
| `id_input` | Select/text | WiFi SSID to connect to |
| `password` | Text | WiFi password (**toggles cleartext on focus**) |
| `sn` | Read-only | Module serial number |
| `solf` | Read-only | Slave firmware version |
| `firm` | Read-only | Master firmware version |
| `file` | File input | Firmware .bin file for upgrade |
| `portNum` | Select | RS485 port number |

### 2.8 UI Actions

| Button | Action | WebSocket command |
|--------|--------|-------------------|
| Save | Connect to selected WiFi | `netSet` |
| Refresh | Scan for WiFi networks | `netScan` |
| Clear | Reset WiFi form fields | (client-side only) |
| Upgrade | Upload firmware file | `upFile` |
| Set Up | Change RS485 port | `portSet` |
| Clear (firmware) | Reset firmware upload form | (client-side only) |

## 3. Security Vulnerabilities

### 3.1 WiFi Password Cleartext Exposure (CVE pending)

**Severity**: High

The `netInit` WebSocket message, sent automatically on connection, contains the home WiFi password in cleartext.
Combined with the permanently-enabled AP using a default password, this allows anyone within WiFi range to:

1. Connect to the dongle AP (SSID `W-XXXXXXX`, password `mtmt2020`)
2. Open `http://192.168.1.1/`
3. Read the home WiFi password from the WebSocket response

**Status**: Reported to FoxESS.
No fix issued.
No CVE ID assigned.

Reference: [CP-at-home/FoxESS-CVE](https://github.com/CP-at-home/FoxESS-CVE)

### 3.2 Unauthenticated Firmware Upload

**Severity**: High

The firmware upgrade mechanism (`upFile`) has no authentication beyond the AP password, and the integrity check is a trivial byte sum (mod 256).
There is no documented cryptographic signature verification.
This could allow:

1. Upload of modified firmware to the datalogger
2. Persistent compromise of the device
3. Potential pivot to the inverter via RS485

**Note**: This is inferred from the JavaScript source.
It has not been tested with an actual firmware upload.
The ESP32 bootloader may have additional flash encryption or secure boot checks not visible in the web interface.

### 3.3 Permanent AP Broadcast

**Severity**: Medium

The dongle broadcasts its AP at all times, creating a persistent attack surface.
The AP cannot be disabled or reconfigured.
The SSID contains part of the serial number, making the device identifiable.

### 3.4 No Transport Encryption

**Severity**: Medium

The web interface uses plain HTTP and unencrypted WebSocket (`ws://`, not `wss://`).
All data, including the WiFi password, is transmitted in cleartext over the air.

## 4. Mitigation

| Mitigation | Effect | Feasibility |
|------------|--------|------------|
| Move dongle to a dedicated VLAN WiFi | Leaked password only grants IoT VLAN access | ✅ Best option |
| Physical shielding / RF attenuation | Reduce AP broadcast range | Partial |
| Monitor for unknown clients on the AP | Detect exploitation attempts | Possible |
| Replace dongle with RS485 hardware adapter | Eliminates the dongle entirely | ✅ Permanent fix |
| Block dongle AP with WiFi deauth | Aggressive, may affect dongle STA | ⚠️ Unreliable |
