"""Data models for pybyd."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class RemoteCommand(StrEnum):
    LOCK = "LOCKDOOR"
    UNLOCK = "OPENDOOR"
    START_CLIMATE = "OPENAIR"
    STOP_CLIMATE = "CLOSEAIR"
    FLASH_LIGHTS = "FLASHLIGHTNOWHISTLE"
    HORN = "FINDCAR"
    CLOSE_WINDOWS = "CLOSEWINDOW"


@dataclass(slots=True)
class AuthToken:
    user_id: str
    sign_token: str
    encry_token: str


@dataclass(slots=True)
class Vehicle:
    vin: str
    model_name: str | None
    brand_name: str | None
    energy_type: str | None
    auto_alias: str | None
    auto_plate: str | None
    raw: dict[str, Any]


@dataclass(slots=True)
class VehicleRealtimeData:
    elec_percent: float | None
    endurance_mileage: float | None
    charging_state: str | None
    trunk_lid: str | None
    raw: dict[str, Any]


@dataclass(slots=True)
class GpsInfo:
    latitude: float | None
    longitude: float | None
    speed: float | None
    direction: float | None
    gps_timestamp: str | None
    raw: dict[str, Any]


@dataclass(slots=True)
class RemoteControlResult:
    control_state: int
    success: bool
    request_serial: str | None
    raw: dict[str, Any]
