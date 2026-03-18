"""Decode FoxESS datalogger binary frames into readable sensor data.

Protocol: custom binary over TLS on port 14431.
Framing: 7e7e (start) / e7e7 (end) for control, 7f7f / f7f7 for data.
Byte order: big-endian. Values are signed int16 unless noted.

Usage:
    uv run foxess-decode              # decode recent readings from database
    uv run foxess-decode --latest     # show only the most recent reading
    uv run foxess-decode --json       # output as JSON
"""

import argparse
import json
import sys
from dataclasses import dataclass


@dataclass
class SolarReading:
    """Decoded sensor values from a single cmd 0x02 data frame."""

    timestamp: str

    # Grid (R-phase, single-phase inverter)
    grid_direction: int  # -1 = exporting, 0/1 = importing (unverified at import)
    feedin_power_kw: float  # power exported to grid
    grid_consumption_kw: float  # power imported from grid
    generation_power_kw: float  # total inverter output
    load_power_kw: float  # household consumption

    r_volt: float
    r_current: float
    r_freq: float
    r_power_kw: float

    # PV strings
    pv1_volt: float
    pv1_current: float
    pv2_volt: float
    pv2_current: float
    pv3_volt: float
    pv3_current: float
    pv4_volt: float
    pv4_current: float

    # Temperatures
    boost_temp_c: float
    inv_temp_c: float
    ambient_temp_c: float

    # Energy totals
    today_yield_kwh: float
    generation_total_kwh: float

    @property
    def pv1_power_kw(self) -> float:
        return round(self.pv1_volt * self.pv1_current / 1000.0, 3)

    @property
    def pv2_power_kw(self) -> float:
        return round(self.pv2_volt * self.pv2_current / 1000.0, 3)

    @property
    def pv3_power_kw(self) -> float:
        return round(self.pv3_volt * self.pv3_current / 1000.0, 3)

    @property
    def pv4_power_kw(self) -> float:
        return round(self.pv4_volt * self.pv4_current / 1000.0, 3)

    @property
    def pv_power_kw(self) -> float:
        return round(
            self.pv1_power_kw + self.pv2_power_kw + self.pv3_power_kw + self.pv4_power_kw, 3
        )



def _i16(data: bytes, offset: int) -> int:
    v = (data[offset] << 8) | data[offset + 1]
    return v if v < 32768 else v - 65536


def _u32(data: bytes, offset: int) -> int:
    return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]


def decode_data_frame(raw: bytes, timestamp: str) -> SolarReading | None:
    """Decode a cmd 0x02 data frame (251 bytes) into a SolarReading."""
    if len(raw) < 251:
        return None
    if raw[:2] != b"\x7e\x7e" or raw[2] != 0x02:
        return None

    # Inner payload: strip header (9 bytes) and trailer (4 bytes: checksum + e7e7)
    inner = raw[9:-4]
    if len(inner) < 170:
        return None

    grid_power_raw = _i16(inner, 2)

    # off2 is signed net grid power: negative = exporting (feedin), positive = importing
    feedin = abs(grid_power_raw) / 1000.0 if grid_power_raw < 0 else 0.0
    grid_consumption = grid_power_raw / 1000.0 if grid_power_raw > 0 else 0.0

    return SolarReading(
        timestamp=timestamp,
        grid_direction=_i16(inner, 0),
        feedin_power_kw=feedin,
        grid_consumption_kw=grid_consumption,
        generation_power_kw=_i16(inner, 6) / 1000.0,
        load_power_kw=_i16(inner, 10) / 1000.0,
        r_volt=_i16(inner, 12) / 10.0,
        r_current=_i16(inner, 14) / 10.0,
        r_freq=_i16(inner, 16) / 100.0,
        r_power_kw=_i16(inner, 18) / 1000.0,
        pv1_volt=_i16(inner, 36) / 10.0,
        pv1_current=_i16(inner, 38) / 10.0,
        pv2_volt=_i16(inner, 42) / 10.0,
        pv2_current=_i16(inner, 44) / 10.0,
        pv3_volt=_i16(inner, 48) / 10.0,
        pv3_current=_i16(inner, 50) / 10.0,
        pv4_volt=_i16(inner, 54) / 10.0,
        pv4_current=_i16(inner, 56) / 10.0,
        boost_temp_c=_i16(inner, 60),
        inv_temp_c=_i16(inner, 62),
        ambient_temp_c=_i16(inner, 64),
        today_yield_kwh=_i16(inner, 66) / 10.0,
        generation_total_kwh=_u32(inner, 68) / 10.0,
    )


def _format_reading(r: SolarReading) -> str:
    lines = [
        f"--- {r.timestamp} ---",
        f"  Generation: {r.generation_power_kw:.3f} kW  |  Feed-in: {r.feedin_power_kw:.3f} kW  |  Load: {r.load_power_kw:.3f} kW",
        f"  Grid: {r.r_volt:.1f}V  {r.r_current:.1f}A  {r.r_freq:.2f}Hz  {r.r_power_kw:.3f}kW",
        f"  PV1: {r.pv1_volt:.1f}V {r.pv1_current:.1f}A = {r.pv1_power_kw:.3f}kW  |  PV2: {r.pv2_volt:.1f}V {r.pv2_current:.1f}A = {r.pv2_power_kw:.3f}kW",
    ]
    if r.pv3_volt > 0 or r.pv4_volt > 0:
        lines.append(f"  PV3: {r.pv3_volt:.1f}V {r.pv3_current:.1f}A  |  PV4: {r.pv4_volt:.1f}V {r.pv4_current:.1f}A")
    lines += [
        f"  Temp: ambient={r.ambient_temp_c}°C  boost={r.boost_temp_c}°C  inv={r.inv_temp_c}°C",
        f"  Today: {r.today_yield_kwh:.1f} kWh  |  Lifetime: {r.generation_total_kwh:.1f} kWh",
    ]
    return "\n".join(lines)


def _reading_to_json(r: SolarReading) -> str:
    d = r.__dict__.copy()
    d["pv1_power_kw"] = r.pv1_power_kw
    d["pv2_power_kw"] = r.pv2_power_kw
    d["pv_power_kw"] = r.pv_power_kw
    return json.dumps(d)


def main():
    from foxess_local.store import open_db, get_latest_reading, query_readings

    parser = argparse.ArgumentParser(description="Decode FoxESS readings")
    parser.add_argument("--latest", action="store_true", help="Show only the latest reading")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--limit", type=int, default=20, help="Number of readings to show")
    parser.add_argument("--db", type=str, help="Database path")
    args = parser.parse_args()

    conn = open_db(args.db)

    if args.latest:
        reading = get_latest_reading(conn)
        if not reading:
            print("No readings in database.", file=sys.stderr)
            sys.exit(1)
        print(_reading_to_json(reading) if args.json else _format_reading(reading))
    else:
        readings = query_readings(conn, limit=args.limit)
        if not readings:
            print("No readings in database.", file=sys.stderr)
            sys.exit(1)
        for r in readings:
            print(_reading_to_json(r) if args.json else _format_reading(r))

    conn.close()


if __name__ == "__main__":
    main()
