"""Device tracker platform for BYD."""

from __future__ import annotations

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydDeviceTracker(coordinator)])


class BydDeviceTracker(BydEntity, TrackerEntity):
    """BYD GPS tracker."""

    _attr_name = "Location"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_location"

    @property
    def latitude(self):
        return self.coordinator.data.gps.latitude

    @property
    def longitude(self):
        return self.coordinator.data.gps.longitude

    @property
    def source_type(self):
        return SourceType.GPS
