"""Switch platform for BYD."""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydHeatedSeatsSwitch(coordinator), BydChargingSwitch(coordinator)])


class BydHeatedSeatsSwitch(BydEntity, SwitchEntity):
    """Heated seats toggle (placeholder command mapping)."""

    _attr_name = "Heated Seats"
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_heated_seats"

    @property
    def is_on(self) -> bool | None:
        raw = self.coordinator.realtime_raw()
        val = raw.get("seatHeatStatus")
        if val is None:
            return None
        return str(val) == "1"

    async def async_turn_on(self, **kwargs):
        raise HomeAssistantError("Heated-seats control is not mapped to the BYD API yet")

    async def async_turn_off(self, **kwargs):
        raise HomeAssistantError("Heated-seats control is not mapped to the BYD API yet")


class BydChargingSwitch(BydEntity, SwitchEntity):
    """Charging toggle (placeholder command mapping)."""

    _attr_name = "Charging"
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_charging"

    @property
    def is_on(self) -> bool | None:
        state = self.coordinator.data.realtime.charging_state
        if state is None:
            return None
        return str(state) in {"1", "2", "charging", "CHARGING"}

    async def async_turn_on(self, **kwargs):
        raise HomeAssistantError("Charging control is not mapped to the BYD API yet")

    async def async_turn_off(self, **kwargs):
        raise HomeAssistantError("Charging control is not mapped to the BYD API yet")
