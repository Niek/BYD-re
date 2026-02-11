"""Siren platform for BYD."""

from __future__ import annotations

from homeassistant.components.siren import SirenEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydSiren(coordinator)])


class BydSiren(BydEntity, SirenEntity):
    """BYD siren mapped to horn command."""

    _attr_name = "Alarm"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_alarm"

    async def async_turn_on(self, **kwargs) -> None:
        await self.coordinator.async_honk_alarm()

    async def async_turn_off(self, **kwargs) -> None:
        return
