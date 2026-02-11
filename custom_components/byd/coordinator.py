"""DataUpdateCoordinator for BYD."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from aiohttp import ClientSession
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .pybyd import BydClient, BydConfig

from .const import DEFAULT_SCAN_INTERVAL


@dataclass
class BydSnapshot:
    """Current BYD snapshot data."""

    vin: str
    vehicle: Any
    realtime: Any
    gps: Any


class BydDataCoordinator(DataUpdateCoordinator[BydSnapshot]):
    """BYD data coordinator."""

    def __init__(
        self,
        hass: HomeAssistant,
        username: str,
        password: str,
        country_code: str,
        base_url: str,
        vin: str | None,
        session: ClientSession,
    ) -> None:
        config = BydConfig(
            username=username,
            password=password,
            country_code=country_code,
            base_url=base_url,
        )
        self.client = BydClient(config=config, session=session)
        self._vin = vin
        super().__init__(
            hass,
            logger=logging.getLogger(__name__),
            name="BYD",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )

    async def async_initialize(self) -> None:
        await self.client.__aenter__()
        await self.client.login()

    async def async_shutdown(self) -> None:
        await self.client.__aexit__(None, None, None)

    async def _async_update_data(self) -> BydSnapshot:
        try:
            vehicles = await self.client.get_vehicles()
            if not vehicles:
                raise UpdateFailed("No vehicles returned")
            if not self._vin:
                self._vin = vehicles[0].vin
            vehicle = next((v for v in vehicles if v.vin == self._vin), vehicles[0])
            realtime = await self.client.get_vehicle_realtime(vehicle.vin)
            gps = await self.client.get_gps_info(vehicle.vin)
            return BydSnapshot(vin=vehicle.vin, vehicle=vehicle, realtime=realtime, gps=gps)
        except Exception as err:
            raise UpdateFailed(str(err)) from err

    async def async_lock(self) -> None:
        await self.client.lock(self.data.vin)
        await self.async_request_refresh()

    async def async_unlock(self) -> None:
        await self.client.unlock(self.data.vin)
        await self.async_request_refresh()

    async def async_start_climate(self) -> None:
        await self.client.start_climate(self.data.vin)
        await self.async_request_refresh()

    async def async_stop_climate(self) -> None:
        await self.client.stop_climate(self.data.vin)
        await self.async_request_refresh()

    async def async_flash_lights(self) -> None:
        await self.client.flash_lights(self.data.vin)

    async def async_honk_alarm(self) -> None:
        await self.client.honk_horn(self.data.vin)

    def realtime_raw(self) -> dict[str, Any]:
        raw = getattr(self.data.realtime, "raw", None) if self.data else None
        return raw if isinstance(raw, dict) else {}

    def gps_raw(self) -> dict[str, Any]:
        raw = getattr(self.data.gps, "raw", None) if self.data else None
        return raw if isinstance(raw, dict) else {}
