"""DataUpdateCoordinator for BYD."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pprint import pformat
from datetime import timedelta
from typing import Any

from aiohttp import ClientSession
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .pybyd import BydClient, BydConfig

from .const import DEFAULT_SCAN_INTERVAL


def _safe_repr(value: Any, limit: int = 2000) -> str:
    """Render value for debug logs without blowing up log size."""
    try:
        rendered = pformat(value)
    except Exception:  # pragma: no cover - defensive logging helper
        rendered = repr(value)
    if len(rendered) > limit:
        return f"{rendered[:limit]}... <truncated {len(rendered) - limit} chars>"
    return rendered


def _raw_payload(value: Any) -> Any:
    """Extract raw payload from pybyd models when available."""
    raw = getattr(value, "raw", None)
    return raw if raw is not None else value


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
        self._logger = logging.getLogger(__name__)
        self._logger.debug(
            "Initialized BYD coordinator for base_url=%s country_code=%s vin=%s username=%s",
            base_url,
            country_code,
            vin,
            username,
        )
        super().__init__(
            hass,
            logger=self._logger,
            name="BYD",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )

    async def async_initialize(self) -> None:
        self._logger.debug("Opening BYD client session")
        await self.client.__aenter__()
        self._logger.debug("Authenticating BYD client")
        await self.client.login()
        self._logger.debug("BYD client authenticated successfully")

    async def async_shutdown(self) -> None:
        self._logger.debug("Shutting down BYD client session")
        await self.client.__aexit__(None, None, None)

    async def _async_update_data(self) -> BydSnapshot:
        try:
            self._logger.debug("Requesting vehicle list from BYD server")
            vehicles = await self.client.get_vehicles()
            self._logger.debug(
                "BYD get_vehicles returned %s vehicles",
                len(vehicles) if vehicles else 0,
            )
            self._logger.debug(
                "BYD get_vehicles payload: %s",
                _safe_repr([_raw_payload(v) for v in vehicles]),
            )
            if not vehicles:
                raise UpdateFailed("No vehicles returned")
            if not self._vin:
                self._vin = vehicles[0].vin
                self._logger.debug(
                    "No VIN configured; selected first VIN from response: %s", self._vin
                )
            vehicle = next((v for v in vehicles if v.vin == self._vin), vehicles[0])
            self._logger.debug("Using VIN=%s for data refresh", vehicle.vin)

            self._logger.debug("Requesting realtime payload for VIN=%s", vehicle.vin)
            realtime = await self.client.get_vehicle_realtime(vehicle.vin)
            self._logger.debug(
                "BYD realtime payload for VIN=%s: %s",
                vehicle.vin,
                _safe_repr(_raw_payload(realtime)),
            )

            self._logger.debug("Requesting GPS payload for VIN=%s", vehicle.vin)
            gps = await self.client.get_gps_info(vehicle.vin)
            self._logger.debug(
                "BYD GPS payload for VIN=%s: %s",
                vehicle.vin,
                _safe_repr(_raw_payload(gps)),
            )

            snapshot = BydSnapshot(
                vin=vehicle.vin, vehicle=vehicle, realtime=realtime, gps=gps
            )
            self._logger.debug("BYD snapshot update complete for VIN=%s", vehicle.vin)
            return snapshot
        except Exception as err:
            self._logger.exception("BYD data refresh failed: %s", err)
            raise UpdateFailed(str(err)) from err

    async def async_lock(self) -> None:
        self._logger.debug("Sending lock command for VIN=%s", self.data.vin)
        await self.client.lock(self.data.vin)
        self._logger.debug(
            "Lock command completed for VIN=%s; requesting refresh", self.data.vin
        )
        await self.async_request_refresh()

    async def async_unlock(self) -> None:
        self._logger.debug("Sending unlock command for VIN=%s", self.data.vin)
        await self.client.unlock(self.data.vin)
        self._logger.debug(
            "Unlock command completed for VIN=%s; requesting refresh", self.data.vin
        )
        await self.async_request_refresh()

    async def async_start_climate(self) -> None:
        self._logger.debug("Sending climate start command for VIN=%s", self.data.vin)
        await self.client.start_climate(self.data.vin)
        self._logger.debug(
            "Climate start command completed for VIN=%s; requesting refresh",
            self.data.vin,
        )
        await self.async_request_refresh()

    async def async_stop_climate(self) -> None:
        self._logger.debug("Sending climate stop command for VIN=%s", self.data.vin)
        await self.client.stop_climate(self.data.vin)
        self._logger.debug(
            "Climate stop command completed for VIN=%s; requesting refresh",
            self.data.vin,
        )
        await self.async_request_refresh()

    async def async_flash_lights(self) -> None:
        self._logger.debug("Sending flash lights command for VIN=%s", self.data.vin)
        await self.client.flash_lights(self.data.vin)
        self._logger.debug("Flash lights command completed for VIN=%s", self.data.vin)

    async def async_honk_alarm(self) -> None:
        self._logger.debug("Sending honk horn command for VIN=%s", self.data.vin)
        await self.client.honk_horn(self.data.vin)
        self._logger.debug("Honk horn command completed for VIN=%s", self.data.vin)

    def realtime_raw(self) -> dict[str, Any]:
        raw = getattr(self.data.realtime, "raw", None) if self.data else None
        return raw if isinstance(raw, dict) else {}

    def gps_raw(self) -> dict[str, Any]:
        raw = getattr(self.data.gps, "raw", None) if self.data else None
        return raw if isinstance(raw, dict) else {}
