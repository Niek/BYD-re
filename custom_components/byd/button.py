"""Button platform for BYD."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydFlashLightsButton(coordinator), BydAlarmButton(coordinator), BydWindowUpButton(coordinator)])


class BydFlashLightsButton(BydEntity, ButtonEntity):
    """Vehicle flash lights button."""

    _attr_name = "Flash Lights"
    # Action endpoints are not fully mapped yet, so keep buttons disabled by default.
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_flash_lights"

    async def async_press(self) -> None:
        raise HomeAssistantError("Flash-lights control is not mapped to the BYD API yet")


class BydAlarmButton(BydEntity, ButtonEntity):
    """Vehicle alarm (horn) button."""

    _attr_name = "Alarm"
    # Action endpoints are not fully mapped yet, so keep buttons disabled by default.
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_alarm"

    async def async_press(self) -> None:
        raise HomeAssistantError("Alarm control is not mapped to the BYD API yet")


class BydWindowUpButton(BydEntity, ButtonEntity):
    """Vehicle window up button."""

    _attr_name = "Window Up"
    # Action endpoints are not fully mapped yet, so keep buttons disabled by default.
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_window_up"

    async def async_press(self) -> None:
        raise HomeAssistantError("Window-up control is not mapped to the BYD API yet")
