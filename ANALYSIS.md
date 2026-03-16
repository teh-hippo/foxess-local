# FoxESS Local Protocol Analysis

## Overview

The FoxESS WiFi dongle (ESP chip) communicates with FoxESS monitoring servers using a custom binary protocol over TLS with a self-signed certificate (`O=FoxESS, CN=monitor`).
The servers listen on port 14431 and are load-balanced across multiple IPs.

This document describes what we can extract locally vs. what the FoxESS Cloud API provides, and proposes a path toward a fully local Home Assistant integration.

## Protocol Summary

### Connection
- **Transport**: TCP + TLS (self-signed cert, CN=monitor)
- **Server**: FoxESS monitoring server(s) on port 14431 (load-balanced, multiple IPs)
- **Direction**: Dongle initiates; server mostly just ACKs
- **Framing**: `7e7e` start / `e7e7` end (control frames), `7f7f` / `f7f7` (data frames)
- **Byte order**: Big-endian

### Message Types (observed)

| Magic  | Cmd  | Len  | Dir | Frequency | Purpose |
|--------|------|------|-----|-----------|---------|
| `7e7e` | 0x2a | 40B  | C→S | Once (connect) | Handshake — contains module SN + timestamp |
| `7e7e` | 0xaa | 18B  | S→C | Once (reply)   | Handshake ACK |
| `7e7e` | 0x2c | 17B  | C→S | Once | Auth/capability exchange |
| `7e7e` | 0xac | 13B  | S→C | Once | Auth ACK |
| `7e7e` | 0x2b | 14B  | C→S | Once | Session setup |
| `7e7e` | 0xab | 14B  | S→C | Once | Session ACK |
| `7e7e` | 0x06 | 99B  | C→S | Every ~30s | Device registration — contains device SN |
| `7e7e` | 0x01 | 121B | C→S | Every ~30s | Firmware/version report |
| `7e7e` | 0x02 | 251B | C→S | Every ~30s | **Real-time sensor data** |
| `7f7f` | 0x37 | 277B | C→S | Once (connect) | Extended data (initial dump) |
| `7f7f` | 0x91 | 72B  | C→S | Rare | Unknown (possibly historical?) |
| `7f7f` | 0x11 | 19B  | S→C | Rare | Unknown server message |

### Cmd 0x02 — Real-time Data Frame (251 bytes)

This is the primary data message.
Sent every ~90 seconds.

**Structure**: `7e7e` + cmd(1) + seq(4) + len(2) + payload(238) + checksum(2) + `e7e7`

**Payload offsets** (2-byte big-endian signed int16 unless noted):

| Offset | Scale  | Variable             | Cloud API equivalent     | Verified |
|--------|--------|----------------------|--------------------------|----------|
| 0      | raw    | Grid direction flag  | (-1=export, 0/1=import?) | ⚠️ inferred |
| 2      | /1000  | Net grid power (kW)  | feedinPower (negated)    | ✅ |
| 4      | /1000  | Grid import (kW)     | gridConsumptionPower     | ✅ (always 0 during export) |
| 6      | /1000  | Generation power (kW)| generationPower / RPower | ✅ |
| 8      | /1000  | S-phase power (kW)   | SPower                   | ✅ (0, single-phase) |
| 10     | /1000  | Load power (kW)      | loadsPower               | ✅ |
| 12     | /10    | R-phase voltage (V)  | RVolt                    | ✅ |
| 14     | /10    | R-phase current (A)  | RCurrent                 | ✅ |
| 16     | /100   | R-phase freq (Hz)    | RFreq                    | ✅ |
| 18     | /1000  | R-phase power (kW)   | RPower                   | ✅ |
| 20-34  | —      | S/T-phase (all zero) | SVolt..TPower            | ✅ (single-phase inverter) |
| 36     | /10    | PV1 voltage (V)      | pv1Volt                  | ✅ |
| 38     | /10    | PV1 current (A)      | pv1Current               | ✅ |
| 40     | ?      | PV1 power?           | pv1Power                 | ❌ always 0 — calculated server-side? |
| 42     | /10    | PV2 voltage (V)      | pv2Volt                  | ✅ |
| 44     | /10    | PV2 current (A)      | pv2Current               | ✅ |
| 46     | ?      | PV2 power?           | pv2Power                 | ❌ always 0 — calculated server-side? |
| 48     | /10    | PV3 voltage (V)      | pv3Volt                  | ✅ |
| 50     | /10    | PV3 current (A)      | pv3Current               | ✅ |
| 52     | ?      | PV3 power?           | pv3Power                 | ❌ always 0 |
| 54     | /10    | PV4 voltage (V)      | pv4Volt                  | ✅ |
| 56     | /10    | PV4 current (A)      | pv4Current               | ✅ |
| 58     | ?      | PV4 power?           | pv4Power                 | ❌ always 0 |
| 60     | raw °C | Boost temperature    | boostTemperation         | ✅ |
| 62     | raw °C | Inverter temperature | invTemperation           | ✅ |
| 64     | raw °C | Ambient temperature  | ambientTemperation       | ✅ |
| 66     | /10    | Today's yield (kWh)  | todayYield               | ✅ (monotonically increasing) |
| 68-71  | u32/10 | Cumulative gen (kWh) | generation               | ✅ |
| 72-95  | —      | Mostly zero          | Unknown / battery?       | — |
| 96     | raw    | Unknown counter      | ?                        | — |
| 98-101 | u32    | Unknown              | ?                        | — |
| 118    | ?      | Unknown (~830)       | ?                        | — |
| 154    | raw    | Unknown (2)          | ?                        | — |
| 156    | raw    | Unknown (3)          | ?                        | — |
| 170-173| u32    | Unknown              | ?                        | — |

**Derived values** (not in the frame, calculated from above):
- `pvPower` = sum of PVn voltage × current for active strings
- `pv1Power` = pv1Volt × pv1Current / 1000
- `feedinPower` = abs(offset 2) / 1000 (when grid direction = -1)
- `gridConsumptionPower` = offset 4 / 1000 (when grid direction >= 0)

## Local vs. Cloud API Comparison

### What we get locally (from dongle interception)

| Category | Data | Update rate | Notes |
|----------|------|-------------|-------|
| **Grid power** | voltage, current, frequency, power (R/S/T phases) | ~90s | Real-time, all phases |
| **PV strings** | voltage + current for PV1-PV4 | ~90s | Power must be calculated (V×A) |
| **Temperatures** | ambient, boost, inverter | ~90s | Integer °C |
| **Energy totals** | today's yield, cumulative generation | ~90s | |
| **Grid flow** | feed-in power, grid consumption, direction | ~90s | Signed value indicates direction |
| **Load power** | household consumption | ~90s | |
| **Device info** | device SN, module SN, firmware versions | On connect | From cmd 0x01 and 0x06 |

### What the Cloud API provides (that we don't get locally)

| Data | API endpoint | Notes |
|------|-------------|-------|
| **Historical data** | `/op/v0/device/report/query` | Hourly/daily/monthly aggregates |
| **Battery data** | `/op/v0/device/battery/soc/get` | SoC, charge/discharge — N/A for this inverter |
| **Running state code** | `runningState` | 163 = on-grid. Might be in unmapped offsets |
| **Fault info** | `currentFault`, `currentFaultCount` | Not yet identified in local data |
| **Reactive power** | `ReactivePower` | Not identified — likely in unmapped offsets |
| **Power factor** | `PowerFactor` | Not identified |
| **Daily grid/feedin totals** | `gridConsumption`, `feedin`, `loads` | Daily energy counters |

### Advantages of local interception

| Advantage | Detail |
|-----------|--------|
| **Lower latency** | ~90s from inverter vs. cloud API's 5-min cache + network round-trip |
| **No API rate limit** | Cloud API limited to 1,440 calls/day (1/min). Local has no limit. |
| **No internet dependency** | Works during internet outages |
| **No cloud account needed** | No API key management or token renewal |
| **Privacy** | Data stays on local network |
| **Reliability** | Cloud API response time ~1.3s and occasionally unavailable |

### Disadvantages / gaps

| Disadvantage | Mitigation |
|-------------|-----------|
| **No historical data** | Build local database — capture every 90s and aggregate ourselves |
| **PV power not directly provided** | Calculate: `pvNPower = pvNVolt × pvNCurrent / 1000` |
| **Some fields unmapped** | Continue analysis; offsets 72-170 likely contain battery/fault/reactive data |
| **Requires network rules** | iptables DNAT on router (non-persistent, reapply after reboot) |
| **Binary protocol may change** | FoxESS firmware updates could alter the format |

## Proposed Architecture for HA Integration

### Option A: Local Proxy + HA Integration (current approach)

```
[Dongle] --TLS--> [Router DNAT] --> [Local Proxy] --TLS--> [FoxESS Cloud]
                                          |
                                    [JSON-lines log]
                                          |
                                    [HA Integration]
                                     reads latest frame
```

- **Pros**: Cloud still works, transparent, battle-tested
- **Cons**: Requires router iptables rule, Windows port forward, relay process running

### Option B: Local-only server (replace cloud entirely)

```
[Dongle] --TLS--> [Router DNAT] --> [Local Server]
                                          |
                                    [Parse + store]
                                          |
                                    [HA Integration]
```

- **Pros**: No internet needed, full control, simpler
- **Cons**: Loses cloud dashboard/app, firmware updates may require cloud

### Option C: Modbus direct (hardware, no WiFi dongle needed)

- **Pros**: Well-documented protocol, many existing HA integrations
- **Cons**: Requires RS485 adapter hardware, physical wiring to inverter

### Recommendation

Start with **Option A** (transparent relay) — it's working now and low-risk.
Build the HA integration to read from the relay's capture log.
Can migrate to Option B later if cloud dependency isn't needed.

## Building a Local Historical Database

Since local interception gives us real-time data every ~90s but no history, we should build our own:

1. **Raw capture storage**: JSON-lines files (already doing this)
2. **Parsed time-series DB**: SQLite or InfluxDB with decoded values
3. **Aggregation**: Hourly/daily/monthly rollups matching cloud API format
4. **HA long-term statistics**: Feed into HA's `statistics` framework for
   energy dashboard compatibility

This would eventually make the cloud API entirely redundant for monitoring.
