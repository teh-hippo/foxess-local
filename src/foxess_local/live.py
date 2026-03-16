"""Live stats — watch decoded solar readings as they arrive.

Usage:
    uv run foxess-live           # follow latest capture file
    uv run foxess-live --once    # print latest reading and exit
"""

import argparse
import glob
import json
import os
import pathlib
import sys
import time

from foxess_local.decode import decode_data_frame, SolarReading


CAPTURE_DIR = pathlib.Path(__file__).parent.parent.parent / "captures"


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


def get_latest_capture_file() -> pathlib.Path | None:
    files = sorted(CAPTURE_DIR.glob("capture_*.jsonl"))
    return files[-1] if files else None


def tail_readings(path: pathlib.Path):
    """Follow a capture file and yield new SolarReadings as they appear."""
    with open(path) as f:
        # Seek to end
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record["dir"] != "c2s" or record["len"] != 251:
                continue
            raw = bytes.fromhex(record["hex"])
            reading = decode_data_frame(raw, record["ts"])
            if reading:
                yield reading


def get_latest_reading(path: pathlib.Path) -> SolarReading | None:
    """Get the most recent data frame reading from the file."""
    last = None
    with open(path) as f:
        for line in f:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record["dir"] != "c2s" or record["len"] != 251:
                continue
            raw = bytes.fromhex(record["hex"])
            reading = decode_data_frame(raw, record["ts"])
            if reading:
                last = reading
    return last


def main():
    parser = argparse.ArgumentParser(description="Live FoxESS solar stats")
    parser.add_argument("--once", action="store_true", help="Print latest reading and exit")
    parser.add_argument("--dir", type=str, help="Captures directory")
    args = parser.parse_args()

    capture_dir = pathlib.Path(args.dir) if args.dir else CAPTURE_DIR
    if not capture_dir.exists():
        print(f"No captures directory: {capture_dir}", file=sys.stderr)
        sys.exit(1)

    path = sorted(capture_dir.glob("capture_*.jsonl"))
    if not path:
        print("No capture files found. Is the relay running?", file=sys.stderr)
        sys.exit(1)

    latest_file = path[-1]

    if args.once:
        reading = get_latest_reading(latest_file)
        if reading:
            print(format_reading(reading))
        else:
            print("No data frames in capture file.", file=sys.stderr)
            sys.exit(1)
        return

    print(f"Following {latest_file.name}... (Ctrl+C to stop)\n")
    try:
        for reading in tail_readings(latest_file):
            # Clear previous output
            print("\033[2J\033[H", end="")
            print(format_reading(reading))
            print(f"\n  \033[2mUpdates every ~90s. Ctrl+C to stop.\033[0m")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
