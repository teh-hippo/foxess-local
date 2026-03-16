# Other Efforts & Related Research

> Research compiled 2026-03-16. Claims marked with confidence levels.
> This document covers prior art, related projects, hardware details, and areas for further investigation.

## 1. Protocol Prior Art

**We appear to be the first to publicly document the FoxESS cloud upload protocol.**

No public project documents the `7E7E`/`E7E7` framing, TCP port 14431, or the binary data frame structure.
Community efforts focus on either the Cloud REST API or direct Modbus RS485, bypassing the datalogger entirely.

### Closest Related Protocol: Growatt (grott)

The [Grott project](https://github.com/johanmeijer/grott) is conceptually identical to our approach — a transparent proxy that intercepts the Growatt WiFi dongle's cloud uploads.
Key differences:

| Property | FoxESS (ours) | Growatt (grott) |
|----------|---------------|-----------------|
| Port | TCP 14431 | TCP 5279 |
| Encryption | TLS (self-signed) | Plaintext + XOR obfuscation |
| Framing | `7E7E`/`E7E7` | Modbus-like 8-byte header |
| Checksum | CRC-16/Modbus (BE) | CRC-16/Modbus (MSB-first) |
| Interception | DNAT + TLS proxy | DNAT (no TLS needed) |
| Documentation | [nwf's Ramblings](https://www.ietfng.org/nwf/misc/growatt-protocol.html) | Well documented |

**Significance**: Grott proves the proxy-interception approach works long-term for HA integration.
It's been stable in production for years.
Our FoxESS equivalent would be the first of its kind.

### SOLARMAN V5 Protocol

[SOLARMAN](https://github.com/jmccrohan/pysolarmanv5) (IGEN Tech) is a white-label monitoring platform used by 176+ inverter brands (Deye, Sofar, Omnik, ZCS Azzurro).
**FoxESS does NOT use SOLARMAN.** Key differences:

| Property | FoxESS | SOLARMAN V5 |
|----------|--------|-------------|
| Frame start | `0x7E7E` (2 bytes) | `0xA5` (1 byte) |
| Frame end | `0xE7E7` (2 bytes) | `0x15` (1 byte) |
| Local port | None | TCP 8899 |
| CRC endianness | Big-endian | Little-endian |
| Payload | Direct sensor values | Wrapped Modbus RTU |

### Other Brands — No Protocol Match

| Brand | Project | Protocol Notes |
|-------|---------|---------------|
| Solis/Ginlong | [ginlong-solis](https://github.com/hn/ginlong-solis) | HTTPS/MQTT to Alibaba Cloud, different framing |
| Sofar | [Sofar_LSW3](https://github.com/MichaluxPL/Sofar_LSW3) | SOLARMAN V5 protocol |
| SolaX | [Solax Pocket WiFi V3 Hack](https://github.com/Svenson84/Solax-Pocket-Wifi-V3.0-Hack) | HTTP local API, ESP32-S2 |
| GoodWe | [Protocol teardown](https://smlx.dev/posts/goodwe-sems-protocol-teardown/) | HTTP POST + AES encryption |
| Sungrow | winet-extractor | WebSocket proprietary on TCP 16668 |
| Huawei | [huawei_solar](https://github.com/wlcrs/huawei_solar) | Modbus TCP 502, proprietary encrypted cloud |
| Deye | [deye-inverter-mqtt](https://github.com/kbialek/deye-inverter-mqtt) | SOLARMAN V5 (local port 8899) |

**No other brand uses `7E7E`/`E7E7` framing or TCP 14431.** The protocol is FoxESS-specific.

### Server Infrastructure

Multiple Chinese solar brands independently host on Alibaba Cloud Singapore (`47.91.x.x`):
- FoxESS: `47.91.86.144`, `8.211.27.249` — port 14431
- Growatt: `47.91.67.66` — port 5279
- Solis: `47.91.x.x` range — HTTPS 443

These are separate tenants, not a shared platform.

Source: [FCC/Alibaba IP ownership](https://whois.arin.net/), web search results.

## 2. Hardware Details

### FoxESS Smart WiFi V2.0 Datalogger

| Property | Value | Confidence |
|----------|-------|------------|
| WiFi MCU | Espressif (ESP32-WROOM-32 or variant) | 🟡 High — MAC prefix confirmed Espressif, community reports ESP32 |
| Protocol MCU | STM32F103C8T6 (Cortex-M3) | 🟡 High — community forum reports, not officially confirmed |
| Architecture | Dual-MCU: ESP32 (WiFi/cloud) + STM32 (RS485/Modbus) | 🟡 High |
| WiFi | 802.11 b/g/n, 2.4 GHz | 🟢 Confirmed — official datasheet |
| Inverter connector | **USB-A physical shape, but NOT standard USB electrically.** Carries RS485 differential signals (A/B) + 7–12V DC power. Do not connect standard USB devices. | 🟢 Confirmed |
| RS485 baud | 9600/8/N/1 | 🟢 Confirmed — official datasheet |
| Power | DC 7–12V from inverter (via the USB-A connector, not 5V) | 🟢 Confirmed |
| IP Rating | IP65 | 🟢 Confirmed |
| Persistent AP | SSID `W-XXXXXXXX`, password `mtmt2020` | 🟢 Confirmed — official guides + CVE |

> **The "USB" connector is misleading.**
> FoxESS markets this as a "USB WiFi dongle" and uses a standard USB-A plug, but the electrical interface is proprietary: RS485 data + 7–12V power, not USB 2.0 signals + 5V.
> This is a cost-saving measure — USB-A connectors are cheap and weatherproof variants are readily available.
> Plugging a standard USB device into the inverter's datalogger port could damage it.

Source: Official FoxESS datasheet, [foxesscommunity.com](https://foxesscommunity.com), [CP-at-home/FoxESS-CVE](https://github.com/CP-at-home/FoxESS-CVE).

### Firmware

Three components:
- **Master** (v1.24): ESP32 application — WiFi, TLS, cloud protocol
- **Slave** (v1.03): STM32 application — RS485 Modbus master
- **Manager** (v1.31): Coordinator/bootloader (unclear which MCU)

Updates are pushed via FoxCloud (OTA) or USB stick (`/UPDATE/` folder structure).
No public firmware downloads.
Community tracks versions at [foxesscommunity.com/viewtopic.php?t=1927](https://foxesscommunity.com/viewtopic.php?t=1927).

### FoxESS LAN Dongle (Smart L 3.0)

The Ethernet variant historically exposed Modbus TCP on port 502, but:
- **Firmware ≤v1.52**: Local Modbus TCP worked
- **Firmware v1.70+**: Local access **permanently disabled**, cloud-only

Source: Community reports on foxesscommunity.com.
**Do not update** if you have old firmware with local access.

## 3. Security

### WiFi Password Leak (Unpatched)

Documented: [CP-at-home/FoxESS-CVE](https://github.com/CP-at-home/FoxESS-CVE)

1. Dongle broadcasts persistent AP even while connected to home WiFi
2. Default AP password `mtmt2020` is universal and unchangeable
3. Connecting to the AP and browsing to `192.168.1.1` exposes the WiFi settings page
4. Clicking the password field triggers a WebSocket response containing the home WiFi password **in cleartext**
5. No CVE ID assigned. FoxESS closed support tickets without fixing.

### Broader Solar Inverter Security

[Forescout's SUN:DOWN research](https://www.forescout.com/resources/sun-down-research/) documented 46 vulnerabilities across Sungrow, Growatt, and SMA inverters — but did not cover FoxESS.
The FoxESS datalogger's security posture (persistent AP, cleartext password, self-signed TLS) suggests similar vulnerability classes likely exist.

## 4. Key GitHub Projects

### FoxESS-Specific

| Project | Purpose | Stars |
|---------|---------|-------|
| [nathanmarlor/foxess_modbus](https://github.com/nathanmarlor/foxess_modbus) | HA integration via RS485 Modbus (bypasses dongle) | ~257 |
| [macxq/foxess-ha](https://github.com/macxq/foxess-ha) | HA integration via Cloud API | ~187 |
| [TonyM1958/FoxESS-Cloud](https://github.com/TonyM1958/FoxESS-Cloud) | Python Cloud API library | ~42 |
| [assembly12/Foxess-T-series-ESPHome](https://github.com/assembly12/Foxess-T-series-ESPHome-Home-Assistant) | ESP32+RS485 ESPHome gateway for T-series | ~41 |
| [mypi-home/HA-ESPHome-FOXESS-Inverter-Modbus](https://github.com/mypi-home/HA-ESPHome-FOXESS-Inverter-Modbus) | ESP32+RS485 ESPHome gateway for H1/AC1 | — |
| [FozzieUK/FoxESS-Canbus-Protocol](https://github.com/FozzieUK/FoxESS-Canbus-Protocol) | CAN-bus protocol between inverter and BMS | ~11 |
| [CP-at-home/FoxESS-CVE](https://github.com/CP-at-home/FoxESS-CVE) | WiFi password leak disclosure | — |

### Related (Other Brands)

| Project | Brand | Relevance |
|---------|-------|-----------|
| [johanmeijer/grott](https://github.com/johanmeijer/grott) | Growatt | Same architecture as our project (transparent proxy) |
| [jmccrohan/pysolarmanv5](https://github.com/jmccrohan/pysolarmanv5) | SOLARMAN | V5 protocol documentation + library |
| [Hypfer/deye-microinverter-cloud-free](https://github.com/Hypfer/deye-microinverter-cloud-free) | Deye | Cloud-free alternative firmware |

## 5. Things to Investigate Tomorrow

### High Priority

1. **Firmware dump via esptool**: This requires opening the dongle's housing and connecting directly to the ESP32 chip's UART test pads on the PCB.
   You need a **USB-to-TTL serial adapter** (e.g. CP2102 or CH340G, ~$2 on AliExpress — search "CP2102 USB TTL 3.3V").
   This is a small board that converts your laptop's USB to 3.3V serial signals.
   It is completely unrelated to the dongle's external USB-A connector.

   Connect the adapter to the ESP32's UART0 test pads on the PCB:
   - Adapter TX → ESP32 GPIO3 (RX)
   - Adapter RX → ESP32 GPIO1 (TX)
   - Adapter GND → ESP32 GND
   - Adapter 3.3V → ESP32 3.3V (to power the chip during dump)
   - Hold GPIO0 to GND at power-up to enter bootloader mode

   Then run:
   ```
   espefuse.py --chip esp32 --port /dev/ttyUSB0 summary  # check if flash encryption is enabled
   esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 921600 read_flash 0 0x400000 foxess_dump.bin
   ```
   **Likelihood of success**: High.
   Most cheap Chinese IoT devices do not enable flash encryption or secure boot (cost/convenience tradeoff).
   If `FLASH_CRYPT_CNT` eFuse has an odd number of bits set, flash is encrypted and the dump will be garbage.
   If eFuses are clear, the dump will contain readable firmware.

   **What the dump would reveal**:
   - Hardcoded server IPs and port (confirming our discovery of port 14431)
   - TLS certificate handling (does it validate? pin? accept any?)
   - The cloud protocol state machine (confirming our reverse engineering)
   - The ESP32↔STM32 internal UART protocol (currently unknown)
   - NVS partition: stored WiFi credentials, server config, device serial numbers
   - OTA update mechanism and any signature verification

   **What you need** depends on what's inside the housing (unknown until opened):

   | Option | Cost | Requires soldering | Best if... |
   |--------|------|--------------------|------------|
   | [Pogo pin snap-on programmer](https://www.tindie.com/products/petl/esp32-and-esp32-s3-wroom-pogo-pin-programmer-board/) | ~$25 | No | ESP32-WROOM module is physically accessible and unobstructed. Press onto module, USB-C to laptop, run esptool. Built-in CH340, reset + boot buttons. [Open-source design](https://github.com/petl/ESP32_wroom_pogo_pin_programmer). |
   | CP2102 USB-to-TTL adapter | ~$3 | Yes (or hold wires) | Cramped PCB, test pads only. 4 wires: TX→RX, RX→TX, GND, 3.3V. Manually hold GPIO0 low at boot. Search AliExpress "CP2102 USB TTL 3.3V". |
   | Do nothing yet | $0 | — | **Recommended first step.** Open the housing, photograph the PCB, then decide. |

   **Step 1 is always: open the case and photograph the PCB.**
   We don't know if the ESP32-WROOM is exposed, if test pads are labelled, or if other components block access.
   The choice of tool depends entirely on what's inside.

   Once open, also run `espefuse.py summary` before attempting a full dump — if flash encryption is enabled, the dump will be unreadable garbage and there's no point continuing.

   **The dual-MCU complication**: The ESP32 flash only contains the WiFi/cloud firmware.
   The STM32 (Modbus/RS485 handler) has its own flash, dumpable via SWD if read protection isn't set.
   The STM32 firmware would reveal the Modbus register polling sequence and the internal UART protocol.

   **Analysis tools**: [ESP-Firmware-Toolbox](https://github.com/wilco375/ESP-Firmware-Toolbox), `binwalk`, `strings`, Ghidra with Xtensa processor module.

2. **The 0x37 embedded frame**: Our captures show cmd `0x37` embeds a `0x02` data frame.
   Is this "last known reading before reconnect"?
   Or historical data?
   Capture multiple reconnects to compare.

3. **Unmapped offsets 72–95**: These 24 bytes between temperatures and the counters are
   likely the battery data region (battery voltage, SoC, charge/discharge power).
   This inverter has no battery, so they're zero — but the field positions should match the `foxess_modbus` register map for battery models.

4. **The `0x91`/`0x11` exchange**: What is the datalogger requesting from the server?
   Configuration?
   Time sync?
   Firmware check?
   The correlation ID pattern suggests request-response semantics.

5. **Port scan the datalogger** (`<dongle:lan-ip>`): We checked common ports but not
   exhaustively.
   A full nmap scan during daytime might reveal hidden services.

### Medium Priority

6. **Modbus register comparison**: Map our protocol offsets against the
   [foxess_modbus register map](https://github.com/nathanmarlor/foxess_modbus).
   If the data frame is just serialized Modbus registers, the order should match.

7. ~~**Multi-day todayYield tracking**~~: **RESOLVED**.
   `todayYield` resets to 0.0 at inverter power-up each morning (not midnight).
   `generation` (lifetime) is continuous and never resets.
   Confirmed across the overnight capture session.

8. ~~**Offline behavior**~~: **RESOLVED**.
   The relay handles disconnection and reconnection gracefully.
   Ran 15+ hours overnight with no crashes.
   Dongle reconnects at sunrise to a potentially different server IP each day.

9. **FoxESS LAN dongle protocol**: Does it use the same `7E7E`/`E7E7` protocol
   but over Ethernet?
   If someone has an old-firmware LAN dongle with Modbus TCP, we could compare.

### Lower Priority

10. **Grott-style integration**: Build a proper HA integration modeled on grott's
    architecture (proxy + MQTT + HA discovery).

11. **Protocol completeness**: We've only seen daytime + sunset. Need to capture
    sunrise, cloud cover events, and potentially inverter fault states.

12. **Alternative ESP32 firmware**: Could we flash the dongle with custom firmware
    that adds a local TCP API while keeping cloud upload?
    The dual-MCU design makes this complex — the ESP32↔STM32 UART protocol is unknown.

## 6. Community Discussion Threads

- [macxq/foxess-ha Discussion #49](https://github.com/macxq/foxess-ha/discussions/49) — Raw hex dumps from RS485 WiFi connector sniffing, includes `7E7E` markers
- [foxesscommunity.com/viewtopic.php?t=1122](https://foxesscommunity.com/viewtopic.php?t=1122) — H1 WiFi Datalogger Capabilities
- [foxesscommunity.com/viewtopic.php?t=512](https://foxesscommunity.com/viewtopic.php?t=512) — How to get access to modbus data (H3)
- [foxesscommunity.com/viewtopic.php?t=145](https://foxesscommunity.com/viewtopic.php?t=145) — Potential ESP32 comms interface
- [foxesscommunity.com/viewtopic.php?t=769](https://foxesscommunity.com/viewtopic.php?t=769) — Possible security flaw in Anatel WiFi Dongle
- [community.home-assistant.io/t/foxess-realtime-monitoring/778850](https://community.home-assistant.io/t/foxess-realtime-monitoring/778850) — Foxess Realtime Monitoring
- [eevblog.com/forum/dodgy-technology/foxess-inverter-ethernet-data](https://www.eevblog.com/forum/dodgy-technology/foxess-inverter-ethernet-data-to-pc-data-and-other-monitoring-lie/) — Ethernet data monitoring discussion
