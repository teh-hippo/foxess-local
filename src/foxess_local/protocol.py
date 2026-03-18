"""Decode FoxESS binary protocol frames.

Frame structure: magic(2) + cmd(1) + timestamp(4) + length(2) + payload(var) + crc(2) + magic(2)
See docs/PROTOCOL.md for the full specification.
"""

from __future__ import annotations

import struct

from foxess_local.models import SolarReading


def _i16(data: bytes, offset: int) -> int:
    v = struct.unpack_from(">h", data, offset)[0]
    return v


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def decode_data_frame(raw: bytes, timestamp: str) -> SolarReading | None:
    """Decode a cmd 0x02 data frame (251 bytes) into a SolarReading."""
    if len(raw) < 251 or raw[:2] != b"\x7e\x7e" or raw[2] != 0x02:
        return None

    inner = raw[9:-4]  # strip header (9 bytes) and trailer (crc + end magic)
    # Inner payload is 238 bytes for a 251-byte frame. Check conservatively.
    if len(inner) < 72:  # highest accessed offset: u32 at 68 = 4 bytes
        return None

    grid_raw = _i16(inner, 2)

    return SolarReading(
        timestamp=timestamp,
        grid_direction=_i16(inner, 0),
        feedin_power_kw=abs(grid_raw) / 1000.0 if grid_raw < 0 else 0.0,
        grid_consumption_kw=grid_raw / 1000.0 if grid_raw > 0 else 0.0,
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
