# FoxESS Datalogger Protocol Specification

> **Status**: Reverse-engineered from traffic capture. Not official documentation.
> **Version**: Based on FoxESS WiFi Datalogger V2.0 with an ENR-series inverter, firmware 1.24/1.03/1.31.
> **Date**: 2026-03-17
> **Verified**: 261 data frames, 0 anomalies across a full day (sunrise to sunset) on 2026-03-17.

## 1. Transport

| Property | Value |
|----------|-------|
| Transport | TCP |
| Encryption | TLS 1.3 (server cert: self-signed, `O=FoxESS, CN=monitor`) |
| Server port | 14431 |
| Server IPs | Load-balanced across multiple IPs (observed: 3 different Alibaba Cloud IPs across 3 sessions). Each session may connect to a different server. |
| Initiator | Datalogger (client) connects outbound to server |
| Session | Single long-lived TCP connection per power cycle. Connects at sunrise when PV voltage exceeds ~80V, disconnects at sunset when PV drops below ~80V. |

## 2. Frame Format

All messages use the same envelope structure.
Two frame types exist, distinguished by their magic bytes.

### 2.1 Control Frame (`7E7E` / `E7E7`)

Used for handshake, authentication, data reporting, and device registration.

```
┌──────────┬─────────┬───────────┬──────────┬─────────────────┬──────────┬──────────┐
│ Magic    │ Command │ Timestamp │ Length   │ Payload         │ Checksum │ Magic    │
│ 2 bytes  │ 1 byte  │ 4 bytes   │ 2 bytes  │ (Length) bytes  │ 2 bytes  │ 2 bytes  │
│ 7E 7E    │         │           │          │                 │          │ E7 E7    │
└──────────┴─────────┴───────────┴──────────┴─────────────────┴──────────┴──────────┘
```

### 2.2 Extended Frame (`7F7F` / `F7F7`)

Used for historical/bulk data.
May embed a control frame in its payload.

```
┌──────────┬─────────┬───────────┬──────────┬─────────────────┬──────────┬──────────┐
│ Magic    │ Command │ Timestamp │ Length   │ Payload         │ Checksum │ Magic    │
│ 2 bytes  │ 1 byte  │ 4 bytes   │ 2 bytes  │ (Length) bytes  │ 2 bytes  │ 2 bytes  │
│ 7F 7F    │         │           │          │                 │          │ F7 F7    │
└──────────┴─────────┴───────────┴──────────┴─────────────────┴──────────┴──────────┘
```

### 2.3 Field Definitions

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| Magic Start | 2 | Fixed | `7E7E` for control frames, `7F7F` for extended frames |
| Command | 1 | uint8 | Message type identifier. Client commands use `0x00-0x3F`, server responses use `0x80-0xBF`. |
| Timestamp | 4 | uint32 BE | Unix timestamp (seconds since epoch, UTC) for control frames and cmd `0x37`. For extended query/response pairs (`0x91`/`0x11`, `0x92`/`0x12`), this field is a **correlation ID** shared between request and response. |
| Length | 2 | uint16 BE | Byte count of Payload (excludes header, checksum, and magic) |
| Payload | var | varies | Command-specific data |
| Checksum | 2 | CRC-16 | CRC-16/Modbus over `[Command .. Payload]`, stored in **standard Modbus wire order** (low byte first, little-endian) |
| Magic End | 2 | Fixed | `E7E7` for control frames, `F7F7` for extended frames |

### 2.4 Checksum Algorithm

CRC-16/Modbus (polynomial 0xA001, init 0xFFFF) computed over all bytes between the start and end magic markers, excluding the checksum itself.
The result is stored in **standard Modbus wire order** (low byte first, little-endian).
Verified against 2015 frames across 5 capture sessions with 0 mismatches.

```python
def checksum(data: bytes) -> bytes:
    """Compute FoxESS frame checksum. Input is [cmd .. payload]."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return bytes([(crc & 0xFF), (crc >> 8) & 0xFF])  # low byte first (standard Modbus)
```

### 2.5 Command Numbering Convention

| Range | Direction | Purpose |
|-------|-----------|---------|
| `0x01–0x0F` | Client → Server | Periodic reporting (data, device info, registration) |
| `0x2A–0x2F` | Client → Server | Session setup (handshake, auth) |
| `0x37` | Client → Server | Extended data (7F7F frame) |
| `0x91–0x92` | Client → Server | Extended queries (7F7F frame) |
| `0xAA–0xAF` | Server → Client | Session setup responses (ACKs) |
| `0x11–0x12` | Server → Client | Extended responses (7F7F frame) |

Server response commands for control frames mirror the client command with bit 7 set (`cmd | 0x80`): `0x2A→0xAA`, `0x2B→0xAB`, `0x2C→0xAC`.
Extended frame responses (`0x11`, `0x12`) follow a separate numbering scheme, matching `0x91`/`0x92` respectively by clearing bit 7.

### 2.6 Complete Message Type Inventory

All message types observed across 2015 frames in 5 capture sessions:

| Cmd | Magic | Dir | Size | Count | Name |
|-----|-------|-----|------|-------|------|
| `0x2A` | `7E7E` | c2s | 40B | 5 | Handshake |
| `0xAA` | `7E7E` | s2c | 18B | 5 | Handshake ACK |
| `0x2C` | `7E7E` | c2s | 17B | 5 | Auth Request |
| `0xAC` | `7E7E` | s2c | 13B | 5 | Auth ACK |
| `0x2B` | `7E7E` | c2s | 14B | 5 | Session Start |
| `0xAB` | `7E7E` | s2c | 14B | 5 | Session ACK |
| `0x02` | `7E7E` | c2s | 251B | 649 | Real-Time Data Report |
| `0x06` | `7E7E` | c2s | 99B | 652 | Device Registration |
| `0x01` | `7E7E` | c2s | 121B | 651 | Firmware Report |
| `0x37` | `7F7F` | c2s | 277B | 9 | Extended Data |
| `0x91` | `7F7F` | c2s | 72B | 7 | Extended Query |
| `0x91` | `7F7F` | c2s | 24B | 1 | Extended Query (time sync variant) |
| `0x11` | `7F7F` | s2c | 19B | 8 | Extended Query Response |
| `0x92` | `7F7F` | c2s | 19B | 4 | Extended Client Message |
| `0x12` | `7F7F` | s2c | 28B | 4 | Extended Response |

All frame sizes are consistent (no variation per type except `0x91` which has two known sizes).
CRC-16/Modbus verified on all 2015 frames with 0 mismatches.

## 3. Session Lifecycle

### 3.1 Connection Sequence

```
Datalogger                                Server
    │                                        │
    │──── TLS ClientHello ──────────────────→│
    │←─── TLS ServerHello (self-signed) ────│
    │──── TLS Finished ────────────────────→│
    │                                        │
    │──── Handshake (0x2A) ────────────────→│  Contains module SN + timestamp
    │←─── Handshake ACK (0xAA) ────────────│
    │──── Auth Request (0x2C) ─────────────→│  Protocol version info
    │←─── Auth ACK (0xAC) ─────────────────│  Empty payload = success
    │──── Session Start (0x2B) ────────────→│  Payload: 0x00
    │←─── Session ACK (0xAB) ──────────────│  Payload: 0x01 = accepted
    │                                        │
    │   ┌─── Repeating cycle (~90s) ────┐   │
    │   │                                │   │
    │───┤── Data Report (0x02) ─────────→│   │  Real-time sensor readings
    │   │── Device Register (0x06) ─────→│   │  Device SN + model
    │   │── Firmware Report (0x01) ──────→│   │  Version strings + model
    │   │                                │   │
    │   └────────────────────────────────┘   │
    │                                        │
    │  (at sunset, PV voltage drops below ~80V)
    │──── Connection closes ─────────────────│
```

### 3.2 Session Timing

| Event | Observed | Notes |
|-------|----------|-------|
| Connect | Around sunrise | Datalogger powers up when PV voltage exceeds ~80V. Varies with cloud cover. |
| Data cycle | Every ~90s | 3 messages per cycle: 0x02, 0x06, 0x01 (circular — starting point varies per session, all three rotations observed) |
| Disconnect | Around sunset | PV voltage drops below ~80V. Last data frame sent, then TCP close. |
| Session duration | Daylight hours | Matches daylight hours. Varies with season and weather. |

### 3.3 Sunrise Boot Sequence

When PV voltage rises above threshold at sunrise:

1. Inverter powers up. PV strings show open-circuit voltage (300–400V) but zero current.
2. Datalogger (ESP) boots, connects to WiFi, then TLS to the monitoring server.
3. Handshake + auth + session setup (same as §3.1).
4. First data frame: `todayYield = 0.0`, `generation` continues from previous total.
5. `generationPower` starts at ~0.05–0.08 kW (inverter standby/parasitic power).
6. Grid direction is `0` (importing) since house load exceeds minimal generation.
7. Over the next 30–60 minutes, PV current ramps up and generation increases.

### 3.4 Sunset Shutdown Sequence

1. Generation power decreases gradually as sunlight fades.
2. Grid direction oscillates between `-1` (export) and `0` (import) as generation fluctuates around load.
3. PV voltages drop below ~80V. Generation reaches ~0.075 kW (standby/parasitic).
4. Data frames continue at normal ~90s interval but with near-zero production values.
5. Datalogger sends final data frame, then closes the TCP connection.
6. FoxESS Cloud reports inverter status as "off-line".

### 3.5 Daily Value Resets

| Field | Reset behavior |
|-------|---------------|
| `todayYield` (offset 66) | Resets to 0.0 at inverter power-up each morning. Not midnight. |
| `generation` (offset 68–71) | Never resets. Lifetime cumulative total, continuous across days. |
| Session frame counter (offset 118) | Resets per session (starts fresh on each connection). |

## 4. Message Reference

### 4.1 Handshake — `0x2A` (Client → Server)

Sent once at connection start.
Contains the datalogger's module serial number and a timestamp.

**Total frame size**: 40 bytes

| Offset | Size | Type | Field | Example | Notes |
|--------|------|------|-------|---------|-------|
| 0 | 1 | uint8 | Protocol version | `0x04` | |
| 1 | 1 | uint8 | Unknown | `0x01` | Possibly sub-version |
| 2 | 1 | uint8 | Unknown | `0x04` | |
| 3 | 1 | uint8 | Unknown | `0x12` | |
| 4 | 1 | uint8 | Unknown | `0x0F` | |
| 5 | 17 | ASCII | Module SN | `<datalogger:serial-number>` | Null-padded to 17 bytes |
| 22 | 1 | uint8 | Unknown | `0x04` | |
| 23 | 4 | ASCII | Build/batch code | `2210` | Possibly manufacturing date |

### 4.2 Handshake ACK — `0xAA` (Server → Client)

**Total frame size**: 18 bytes

| Offset | Size | Type | Field | Example | Notes |
|--------|------|------|-------|---------|-------|
| 0 | 1 | uint8 | Status | `0x01` | 1 = accepted |
| 1 | 1 | uint8 | Unknown | `0x01` | |
| 2 | 1 | uint8 | Unknown | `0x01` | |
| 3 | 2 | uint16 BE | Unknown | `0x0000` | |

### 4.3 Auth Request — `0x2C` (Client → Server)

**Total frame size**: 17 bytes

| Offset | Size | Type | Field | Example | Notes |
|--------|------|------|-------|---------|-------|
| 0 | 1 | uint8 | Unknown | `0xE1` | Possibly capability flags |
| 1 | 1 | uint8 | Unknown | `0x01` | |
| 2 | 1 | uint8 | Protocol variant | `0x02` | |
| 3 | 1 | uint8 | Unknown | `0x00` | |

### 4.4 Auth ACK — `0xAC` (Server → Client)

**Total frame size**: 13 bytes.
**Payload length: 0** — empty payload indicates success.

### 4.5 Session Start — `0x2B` (Client → Server)

**Total frame size**: 14 bytes

| Offset | Size | Type | Field | Example | Notes |
|--------|------|------|-------|---------|-------|
| 0 | 1 | uint8 | Request | `0x00` | |

### 4.6 Session ACK — `0xAB` (Server → Client)

**Total frame size**: 14 bytes

| Offset | Size | Type | Field | Example | Notes |
|--------|------|------|-------|---------|-------|
| 0 | 1 | uint8 | Accepted | `0x01` | 1 = session active |

### 4.7 Real-Time Data Report — `0x02` (Client → Server)

Primary data message.
Sent every ~90 seconds as the first message in a repeating 3-message cycle (`0x02` → `0x06` → `0x01`).
Contains all real-time inverter sensor readings.

**Total frame size**: 251 bytes.
**Payload length**: 238 bytes.

All sensor values are **signed 16-bit big-endian integers** unless otherwise noted.

| Offset | Size | Type | Scale | Field | Unit | Cloud API equivalent |
|--------|------|------|-------|-------|------|---------------------|
| 0 | 2 | int16 BE | raw | Grid direction | — | -1 = exporting, 0 = importing/balanced |
| 2 | 2 | int16 BE | ÷1000 | Net grid power | kW | Signed: negative = feed-in (export), positive = grid consumption (import) |
| 4 | 2 | int16 BE | ÷1000 | (Reserved) | — | Always 0 in observations |
| 6 | 2 | int16 BE | ÷1000 | Generation power | kW | `generationPower` |
| 8 | 2 | int16 BE | ÷1000 | S-phase power | kW | `SPower` (0 for single-phase) |
| 10 | 2 | int16 BE | ÷1000 | Total load | kW | `loadsPower` — equals generation + grid import |
| 12 | 2 | int16 BE | ÷10 | R-phase voltage | V | `RVolt` |
| 14 | 2 | int16 BE | ÷10 | R-phase current | A | `RCurrent` |
| 16 | 2 | int16 BE | ÷100 | R-phase frequency | Hz | `RFreq` |
| 18 | 2 | int16 BE | ÷1000 | R-phase power | kW | `RPower` (= generation for single-phase) |
| 20 | 2 | int16 BE | ÷10 | S-phase voltage | V | `SVolt` (0) |
| 22 | 2 | int16 BE | ÷10 | S-phase current | A | `SCurrent` (0) |
| 24 | 2 | int16 BE | ÷100 | S-phase frequency | Hz | `SFreq` (0) |
| 26 | 2 | int16 BE | ÷1000 | S-phase power | kW | `SPower` (0) |
| 28 | 2 | int16 BE | ÷10 | T-phase voltage | V | `TVolt` (0) |
| 30 | 2 | int16 BE | ÷10 | T-phase current | A | `TCurrent` (0) |
| 32 | 2 | int16 BE | ÷100 | T-phase frequency | Hz | `TFreq` (0) |
| 34 | 2 | int16 BE | ÷1000 | T-phase power | kW | `TPower` (0) |
| 36 | 2 | int16 BE | ÷10 | PV1 voltage | V | `pv1Volt` |
| 38 | 2 | int16 BE | ÷10 | PV1 current | A | `pv1Current` |
| 40 | 2 | int16 BE | — | PV1 (reserved) | — | Always 0. Power calculated as V×A. |
| 42 | 2 | int16 BE | ÷10 | PV2 voltage | V | `pv2Volt` |
| 44 | 2 | int16 BE | ÷10 | PV2 current | A | `pv2Current` |
| 46 | 2 | int16 BE | — | PV2 (reserved) | — | Always 0 |
| 48 | 2 | int16 BE | ÷10 | PV3 voltage | V | `pv3Volt` |
| 50 | 2 | int16 BE | ÷10 | PV3 current | A | `pv3Current` |
| 52 | 2 | int16 BE | — | PV3 (reserved) | — | Always 0 |
| 54 | 2 | int16 BE | ÷10 | PV4 voltage | V | `pv4Volt` |
| 56 | 2 | int16 BE | ÷10 | PV4 current | A | `pv4Current` |
| 58 | 2 | int16 BE | — | PV4 (reserved) | — | Always 0 |
| 60 | 2 | int16 BE | raw | Boost temperature | °C | `boostTemperation` |
| 62 | 2 | int16 BE | raw | Inverter temperature | °C | `invTemperation` |
| 64 | 2 | int16 BE | raw | Ambient temperature | °C | `ambientTemperation` |
| 66 | 2 | int16 BE | ÷10 | Today's yield | kWh | `todayYield` — resets to 0 at inverter power-up each morning |
| 68 | 4 | uint32 BE | ÷10 | Lifetime generation | kWh | `generation` — never resets, continuous across days |
| 72–95 | 24 | — | — | Unknown / battery region | — | Likely battery data for models with storage |
| 96 | 2 | int16 BE | — | Multiplexed type indicator | — | Rotates through values: 0, 4, 52, 53. Determines meaning of offsets 98–110. See §5.4. |
| 98–110 | 14 | int16 BE | — | Multiplexed data | — | Meaning depends on off96 type. See §5.4. |
| 112–117 | 6 | — | — | Unknown | — | Mostly zeros |
| 118 | 2 | int16 BE | — | Session message counter | — | Increments by 3 per reporting cycle (one per message: 0x02 + 0x06 + 0x01). Resets per session. |
| 120 | 2 | int16 BE | — | Unknown counter | — | Small values (1–8), increments slowly through the day |
| 122–153 | 32 | — | — | Unknown | — | Mostly zeros |
| 154 | 2 | int16 BE | — | Static flag | — | Values: 0 or 2 |
| 156 | 2 | int16 BE | — | Static flag | — | Always 3 |
| 158–169 | 12 | — | — | Unknown | — | Zeros |
| 170 | 4 | uint32 BE | — | Unknown accumulator | — | Large values (215M–288M), slowly varying |
| 174–237 | 64 | — | — | Unknown / reserved | — | All zeros |

### 5.4 Multiplexed Data Block (offsets 96–110)

Offsets 96 through 110 carry different data depending on the type indicator at offset 96.
The type rotates through a 4-state cycle approximately every 10 data frames (~15 minutes).
The entire 16-byte block changes meaning per type.

| off96 value | off98 | off100 | off102 | off104 | off106 | off108 | off110 |
|-------------|-------|--------|--------|--------|--------|--------|--------|
| 0 | 0 | 0 | ~2051 | ~2166 | 0 | ~2039 | 0 |
| 4 | 0 | Large counter | 0 | 0 | 0 | 0 | 0 |
| 52 (0x34) | Negative (varies) | 17 | 0 | 0 | 0 | 0 | 0 |
| 53 (0x35) | Large negative | Small increasing | ~386 | ~355 | 0 | ~349 | 2026 |

When off96=0, off102/104/108 show values consistent with three-phase grid voltages (÷10: ~205V, ~217V, ~204V).
These may be S-phase and T-phase measurements from the grid CT.

When off96=53, off102/104/108 appear to be different quantities (possibly temperatures or firmware-related, as off110=2026 could be a year).

The exact meaning of each type is under investigation.
Cross-referencing with the `foxess_modbus` Modbus register map may help identify these fields.

### 5.5 PV3/PV4 Phantom Voltage

On inverters without PV strings connected to inputs 3 and 4, the PV3 voltage field (offset 48) intermittently shows small values (20–24V) with zero current.
This is a phantom/floating voltage on the unconnected input and does not represent real power generation.
PV4 remains consistently zero in this configuration.

**Derived values** (not transmitted, calculated from the above):
- `pv1Power` = `pv1Volt × pv1Current ÷ 1000` (kW)
- `pvPower` = sum of all PV string powers
- `feedinPower` = `abs(netGridPower)` when grid direction = -1
- `gridConsumptionPower` = `netGridPower` when grid direction = 0

### 4.8 Device Registration — `0x06` (Client → Server)

Sent every ~90 seconds as part of the repeating cycle (`0x02` → `0x06` → `0x01`).
Contains the inverter device serial number.

**Total frame size**: 99 bytes.
**Payload length**: 86 bytes.

| Offset | Size | Type | Field | Example | Notes |
|--------|------|------|-------|---------|-------|
| 0 | 6 | ASCII | Model prefix | `A10500` | |
| 6 | 24 | ASCII | Device SN | `<inverter:device-serial>` | Null-padded |
| 30 | 24 | — | Reserved | All `0x00` | |
| 54 | 24 | ASCII | Secondary ID | `000000000000...` | All ASCII zeros |
| 78 | 8 | — | Reserved | All `0x00` | |

### 4.9 Firmware Report — `0x01` (Client → Server)

Sent every ~90 seconds as the last message in the repeating cycle.
Contains firmware version strings and inverter model.

**Total frame size**: 121 bytes.
**Payload length**: 108 bytes.

| Offset | Size | Type | Field | Example | Notes |
|--------|------|------|-------|---------|-------|
| 0 | 6 | ASCII | Master version | `1.24\0\0` | Null-terminated, 6-byte slot |
| 6 | 6 | ASCII | Slave version | `1.03\0\0` | |
| 12 | 6 | ASCII | Manager version | `1.31\0\0` | |
| 18 | 6 | ASCII | Unknown version | `0.00\0\0` | Battery firmware? |
| 24 | 6 | — | Unknown | | |
| 30 | 20 | ASCII | Inverter model | `<inverter:model>` | Null-padded |
| 50 | 4 | uint16 BE × 2 | Unknown | `0x1F40 003C` | 8000, 60 — max power / config? |
| 54 | 6 | ASCII | Master version | `1.24\0\0` | Repeated |
| 60 | 6 | ASCII | Slave version | `1.03\0\0` | Repeated |
| 66 | 6 | ASCII | Manager version | `1.31\0\0` | Repeated |
| 72 | 6 | ASCII | Unknown version | `0.00\0\0` | Repeated |
| 78 | 30 | — | Reserved | All `0x00` | |

### 4.10 Extended Data — `0x37` (Client → Server, `7F7F` frame)

Sent shortly after connection.
Contains a preamble and an embedded `0x02` data frame.

**Total frame size**: 277 bytes (outer `7F7F` frame).

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0 | 4 | uint32 BE | Embedded timestamp | Timestamp of the embedded data frame |
| 4 | 8 | — | Zeros | |
| 12 | 1 | uint8 | Marker | `0xFB` |
| 13 | 251 | frame | Embedded 0x02 frame | Complete control frame with `7E7E`/`E7E7` magic |

The embedded frame is a standard cmd `0x02` real-time data report (see §4.7), possibly representing the last reading before the connection was established.

### 4.11 Extended Query — `0x91` (Client → Server, `7F7F` frame)

Observed twice during a session.
Purpose unknown — possibly requesting configuration or historical data.
The timestamp field acts as a **correlation ID** shared with the server's `0x11` response.

**Total frame size**: 72 bytes.

### 4.12 Extended Query Response — `0x11` / `0x12` (Server → Client, `7F7F` frame)

Server responses to extended queries.
The timestamp field contains the **same correlation ID** as the corresponding client request (`0x91` → `0x11`, `0x92` → `0x12`).

- `0x11`: 19 bytes. Response to `0x91`. Payload contains `0104277E001C` — possibly configuration parameters.
- `0x12`: 28 bytes. Response to `0x92`. Payload includes what appears to be a date/time encoding.

### 4.13 Extended Client Message — `0x92` (Client → Server, `7F7F` frame)

Observed once, immediately following a `0x12` server response.
Shares the same correlation ID.

**Total frame size**: 19 bytes.

## 5. Observed Behaviors

### 5.1 Grid Direction Transitions

| Grid direction (offset 0) | Net grid power (offset 2) | Meaning |
|---------------------------|--------------------------|---------|
| `-1` | Negative (e.g. `-5263`) | Exporting to grid. Feed-in = abs(value) ÷ 1000 kW. |
| `0` | Positive (e.g. `+1755`) | Importing from grid. Consumption = value ÷ 1000 kW. |
| `0` | Zero or small positive | Balanced — generation ≈ load. |
| `-1` | Small negative (e.g. `-85`) | Marginal export, generation slightly exceeds load. |

Direction oscillates rapidly when generation is close to load.
During the sunset transition, direction flipped between `-1` and `0` multiple times as household appliances turned on and off.

### 5.2 PV Startup Behavior

At sunrise, PV strings show **open-circuit voltage before producing current**:

| Time after boot | PV voltage | PV current | Generation |
|----------------|-----------|-----------|-----------|
| 0 min | 330–410V | 0.0A | 0.05 kW (standby) |
| ~15 min | 370–400V | 0.1–0.2A | 0.1–0.2 kW |
| ~30 min | 370–400V | 1–3A | 0.5–1.5 kW |
| ~60 min | 370–400V | 5–10A | 3–5 kW |

The inverter enters standby as soon as PV voltage is sufficient (~80V), even before meaningful current flows.
The `generationPower` field shows ~0.05–0.08 kW during this standby phase, which is the inverter's own parasitic consumption.

### 5.3 Data Rates

| Metric | Value |
|--------|-------|
| Data frame interval | ~90 seconds (avg 90.5s, median 90.4s over 167 samples) |
| Full cycle (0x02, 0x06, 0x01) | ~90 seconds (3 messages back-to-back, then ~60s pause). Cycle order is circular; starting message varies per session. |
| Bytes per data frame | 251 |
| Daily upload volume | ~190 KB |
| Daily download volume | ~485 KB |
| Session count per day | 1 (sunrise to sunset) |

### 5.4 Server Load Balancing

The datalogger connects to a different FoxESS server IP on each session.
Across three observed sessions, three distinct IPs were used — all on Alibaba Cloud, all presenting the same self-signed cert (`O=FoxESS, CN=monitor`) but with **different key pairs** per server.

## 6. Verification

Protocol decoded through transparent TLS relay interception, with all fields cross-referenced against the FoxESS Cloud OpenAPI (`/op/v0/device/real/query`).

**Day 1 (afternoon → sunset):**
- 25 correlation cycles over 4 hours 21 minutes.
- 22 fields definitively verified (exact match with cloud API when sampled simultaneously).
- 0 true mismatches — all observed differences attributed to timing lag.
- Full sunset transition captured — grid direction changes, generation decay, disconnection.

**Overnight:**
- Relay ran 15+ hours continuously with no crashes (8 overnight health checks, all passed).
- Dongle offline from sunset to sunrise.

**Day 2 (sunrise):**
- Dongle reconnected at sunrise (different server IP from day 1).
- `todayYield` confirmed reset to 0.0 at power-up.
- `generation` confirmed continuous across overnight boundary.
- Sunrise correlation: 14/19 match (remaining drifts are timing lag during rapid voltage changes at dawn).
