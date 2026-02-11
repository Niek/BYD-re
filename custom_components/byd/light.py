"""Light platform for BYD."""

from __future__ import annotations

from homeassistant.components.light import LightEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydVehicleLight(coordinator)])


class BydVehicleLight(BydEntity, LightEntity):
    """Vehicle lights command."""

    _attr_name = "Lights"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_lights"

    async def async_turn_on(self, **kwargs):
        await self.coordinator.async_flash_lights()

    async def async_turn_off(self, **kwargs):
        return
