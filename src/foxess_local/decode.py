"""CLI for viewing decoded FoxESS readings from the database.

Usage:
    uv run foxess-decode              # recent readings
    uv run foxess-decode --latest     # most recent only
    uv run foxess-decode --json       # output as JSON
"""

from __future__ import annotations

import argparse
import json
import sys

from foxess_local.models import SolarReading


def _format(r: SolarReading) -> str:
    lines = [
        f"--- {r.timestamp} ---",
        f"  Gen: {r.generation_power_kw:.3f} kW  |  Feed-in: {r.feedin_power_kw:.3f} kW  |  Load: {r.load_power_kw:.3f} kW",
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


def main():
    from foxess_local.store import get_latest_reading, open_db, query_readings

    parser = argparse.ArgumentParser(description="Decode FoxESS readings")
    parser.add_argument("--latest", action="store_true", help="Show only the latest reading")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--limit", type=int, default=20, help="Number of readings to show")
    parser.add_argument("--db", type=str, help="Database path")
    args = parser.parse_args()

    conn = open_db(args.db)
    readings = [get_latest_reading(conn)] if args.latest else query_readings(conn, limit=args.limit)
    conn.close()

    readings = [r for r in readings if r]
    if not readings:
        print("No readings in database.", file=sys.stderr)
        sys.exit(1)

    for r in readings:
        print(json.dumps(r.to_dict()) if args.json else _format(r))


if __name__ == "__main__":
    main()
