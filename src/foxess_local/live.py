"""Live stats — watch decoded solar readings as they arrive.

Usage:
    uv run foxess-live           # follow latest readings from database
    uv run foxess-live --once    # print latest reading and exit
"""

import argparse
import sys
import time

from foxess_local.models import SolarReading
from foxess_local.store import get_latest_reading, open_db


def format_reading(r: SolarReading) -> str:
    ts_local = r.timestamp.replace("T", " ").replace("Z", " UTC")

    W = 52
    top = f"┌{'─' * W}┐"
    bot = f"└{'─' * W}┘"
    div = f"├{'─' * W}┤"

    def row(left: str, right: str) -> str:
        content = f" {left:<26s}{right:>23s} "
        return f"│{content}│"

    def header(text: str) -> str:
        content = f" {text:<{W - 2}s} "
        return f"│\033[1m{content}\033[0m│"

    lines = [
        top,
        header(f"FoxESS Local · {ts_local}"),
        div,
        row("Generation",       f"{r.generation_power_kw:.3f} kW"),
        row("Feed-in",          f"{r.feedin_power_kw:.3f} kW"),
        row("Grid Import",      f"{r.grid_consumption_kw:.3f} kW"),
        row("Load",             f"{r.load_power_kw:.3f} kW"),
        div,
        row("PV1",              f"{r.pv1_volt:.1f}V × {r.pv1_current:.1f}A = {r.pv1_power_kw:.3f} kW"),
        row("PV2",              f"{r.pv2_volt:.1f}V × {r.pv2_current:.1f}A = {r.pv2_power_kw:.3f} kW"),
    ]
    if r.pv3_volt > 0:
        lines.append(row("PV3", f"{r.pv3_volt:.1f}V × {r.pv3_current:.1f}A = {r.pv3_power_kw:.3f} kW"))
    if r.pv4_volt > 0:
        lines.append(row("PV4", f"{r.pv4_volt:.1f}V × {r.pv4_current:.1f}A = {r.pv4_power_kw:.3f} kW"))
    lines += [
        row("PV Total",         f"{r.pv_power_kw:.3f} kW"),
        div,
        row("Grid Voltage",     f"{r.r_volt:.1f} V"),
        row("Grid Current",     f"{r.r_current:.1f} A"),
        row("Grid Frequency",   f"{r.r_freq:.2f} Hz"),
        div,
        row("Temp (ambient)",   f"{r.ambient_temp_c}°C"),
        row("Temp (boost)",     f"{r.boost_temp_c}°C"),
        row("Temp (inverter)",  f"{r.inv_temp_c}°C"),
        div,
        row("Today",            f"{r.today_yield_kwh:.1f} kWh"),
        row("Lifetime",         f"{r.generation_total_kwh:.1f} kWh"),
        bot,
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Live FoxESS solar stats")
    parser.add_argument("--once", action="store_true", help="Print latest reading and exit")
    parser.add_argument("--db", type=str, help="Database path")
    args = parser.parse_args()

    conn = open_db(args.db)

    if args.once:
        reading = get_latest_reading(conn)
        if reading:
            print(format_reading(reading))
        else:
            print("No readings in database.", file=sys.stderr)
            sys.exit(1)
        conn.close()
        return

    print("Following database... (Ctrl+C to stop)\n")
    last_ts = None
    try:
        while True:
            reading = get_latest_reading(conn)
            if reading and reading.timestamp != last_ts:
                print("\033[2J\033[H", end="")
                print(format_reading(reading))
                print("\n  \033[2mUpdates every ~90s. Ctrl+C to stop.\033[0m")
                last_ts = reading.timestamp
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
