"""Configuration models for pybyd."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class DeviceProfile:
    imei_md5: str = "00000000000000000000000000000000"
    network_type: str = "wifi"
    device_type: str = "0"
    mobile_brand: str = "XIAOMI"
    mobile_model: str = "POCO F1"
    os_type: str = "15"
    os_version: str = "35"
    ostype: str = "and"
    imei: str = "BANGCLE01234"
    mac: str = "00:00:00:00:00:00"
    model: str = "POCO F1"
    sdk: str = "35"
    mod: str = "Xiaomi"


@dataclass(slots=True)
class BydConfig:
    username: str
    password: str
    base_url: str = "https://dilinkappoversea-eu.byd.auto"
    country_code: str = "NL"
    language: str = "en"
    time_zone: str = "Europe/Amsterdam"
    app_version: str = "3.2.3"
    app_inner_version: str = "323"
    soft_type: str = "0"
    tbox_version: str = "3"
    is_auto: str = "1"
    device: DeviceProfile = field(default_factory=DeviceProfile)
