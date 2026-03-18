"""Data models for FoxESS solar readings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SolarReading:
    """Decoded sensor values from a single cmd 0x02 data frame."""

    timestamp: str

    # Grid
    grid_direction: int
    feedin_power_kw: float
    grid_consumption_kw: float
    generation_power_kw: float
    load_power_kw: float

    # R-phase (single-phase inverter)
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

    def _pv_power(self, v: float, a: float) -> float:
        return round(v * a / 1000.0, 3)

    @property
    def pv1_power_kw(self) -> float:
        return self._pv_power(self.pv1_volt, self.pv1_current)

    @property
    def pv2_power_kw(self) -> float:
        return self._pv_power(self.pv2_volt, self.pv2_current)

    @property
    def pv3_power_kw(self) -> float:
        return self._pv_power(self.pv3_volt, self.pv3_current)

    @property
    def pv4_power_kw(self) -> float:
        return self._pv_power(self.pv4_volt, self.pv4_current)

    @property
    def pv_power_kw(self) -> float:
        return round(self.pv1_power_kw + self.pv2_power_kw + self.pv3_power_kw + self.pv4_power_kw, 3)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["pv1_power_kw"] = self.pv1_power_kw
        d["pv2_power_kw"] = self.pv2_power_kw
        d["pv_power_kw"] = self.pv_power_kw
        return d
