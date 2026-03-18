"""SQLite storage for FoxESS relay data.

Stores raw protocol frames and decoded sensor readings in a single database file.
Designed for a single writer (relay) with concurrent readers (live dashboard, decode CLI).
"""

from __future__ import annotations

import json
import pathlib
import sqlite3

from foxess_local.decode import SolarReading, decode_data_frame

DEFAULT_DB_PATH = pathlib.Path(__file__).parent.parent.parent / "data" / "foxess.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS frames (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('c2s', 's2c')),
    length INTEGER NOT NULL,
    cmd INTEGER,
    magic TEXT,
    raw BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_frames_ts ON frames(ts);
CREATE INDEX IF NOT EXISTS idx_frames_cmd ON frames(cmd);

CREATE TABLE IF NOT EXISTS readings (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL UNIQUE,
    generation_kw REAL,
    feedin_kw REAL,
    grid_import_kw REAL,
    load_kw REAL,
    pv1_v REAL, pv1_a REAL,
    pv2_v REAL, pv2_a REAL,
    pv3_v REAL, pv3_a REAL,
    pv4_v REAL, pv4_a REAL,
    grid_volt REAL,
    grid_current REAL,
    grid_freq REAL,
    grid_power_kw REAL,
    temp_boost INTEGER,
    temp_inv INTEGER,
    temp_ambient INTEGER,
    today_kwh REAL,
    lifetime_kwh REAL
);
"""


def open_db(path: pathlib.Path | str | None = None) -> sqlite3.Connection:
    """Open (or create) the database, apply pragmas and schema."""
    path = pathlib.Path(path) if path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), timeout=5.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


def insert_frame(conn: sqlite3.Connection, ts: str, direction: str, raw: bytes) -> SolarReading | None:
    """Insert a raw frame. If it's a 0x02 data frame, also decode and insert a reading.

    Returns the decoded SolarReading if one was created, else None.
    """
    cmd = raw[2] if len(raw) > 2 else None
    magic = raw[:2].hex() if len(raw) >= 2 else None

    conn.execute(
        "INSERT INTO frames (ts, direction, length, cmd, magic, raw) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, direction, len(raw), cmd, magic, raw),
    )

    reading = None
    if magic == "7e7e" and cmd == 0x02 and len(raw) == 251 and direction == "c2s":
        reading = decode_data_frame(raw, ts)
        if reading:
            _insert_reading(conn, reading)

    conn.commit()
    return reading


def _insert_reading(conn: sqlite3.Connection, r: SolarReading) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO readings
        (ts, generation_kw, feedin_kw, grid_import_kw, load_kw,
         pv1_v, pv1_a, pv2_v, pv2_a, pv3_v, pv3_a, pv4_v, pv4_a,
         grid_volt, grid_current, grid_freq, grid_power_kw,
         temp_boost, temp_inv, temp_ambient,
         today_kwh, lifetime_kwh)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            r.timestamp,
            r.generation_power_kw, r.feedin_power_kw, r.grid_consumption_kw, r.load_power_kw,
            r.pv1_volt, r.pv1_current, r.pv2_volt, r.pv2_current,
            r.pv3_volt, r.pv3_current, r.pv4_volt, r.pv4_current,
            r.r_volt, r.r_current, r.r_freq, r.r_power_kw,
            r.boost_temp_c, r.inv_temp_c, r.ambient_temp_c,
            r.today_yield_kwh, r.generation_total_kwh,
        ),
    )


def get_latest_reading(conn: sqlite3.Connection) -> SolarReading | None:
    """Get the most recent decoded reading."""
    row = conn.execute("SELECT * FROM readings ORDER BY id DESC LIMIT 1").fetchone()
    return _row_to_reading(row) if row else None


def query_readings(conn: sqlite3.Connection, since_id: int = 0, limit: int = 100) -> list[SolarReading]:
    """Get readings newer than since_id."""
    rows = conn.execute(
        "SELECT * FROM readings WHERE id > ? ORDER BY id LIMIT ?",
        (since_id, limit),
    ).fetchall()
    return [_row_to_reading(r) for r in rows]


def _row_to_reading(row: tuple) -> SolarReading:
    """Convert a database row to a SolarReading."""
    return SolarReading(
        timestamp=row[1],
        grid_direction=0,  # not stored separately, derived from feedin/grid_import
        feedin_power_kw=row[3],
        grid_consumption_kw=row[4],
        generation_power_kw=row[2],
        load_power_kw=row[5],
        r_volt=row[14], r_current=row[15], r_freq=row[16], r_power_kw=row[17],
        pv1_volt=row[6], pv1_current=row[7],
        pv2_volt=row[8], pv2_current=row[9],
        pv3_volt=row[10], pv3_current=row[11],
        pv4_volt=row[12], pv4_current=row[13],
        boost_temp_c=row[18], inv_temp_c=row[19], ambient_temp_c=row[20],
        today_yield_kwh=row[21],
        generation_total_kwh=row[22],
    )


def import_jsonl(conn: sqlite3.Connection, path: pathlib.Path) -> tuple[int, int]:
    """Import a jsonl capture file into the database.

    Returns (frames_imported, readings_imported).
    """
    frames = 0
    readings = 0
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            raw = bytes.fromhex(rec["hex"])
            ts = rec["ts"]
            direction = rec["dir"]

            reading = insert_frame(conn, ts, direction, raw)
            frames += 1
            if reading:
                readings += 1

    return frames, readings
