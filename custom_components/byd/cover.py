"""Cover platform for BYD."""

from __future__ import annotations

from homeassistant.components.cover import CoverEntity, CoverEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydWindowsCover(coordinator)])


class BydWindowsCover(BydEntity, CoverEntity):
    """Represents all windows as one cover."""

    _attr_name = "Windows"
    _attr_supported_features = CoverEntityFeature.OPEN

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_windows"

    @property
    def is_closed(self) -> bool | None:
        raw = self.coordinator.realtime_raw()
        windows = [
            raw.get("leftFrontWindow"),
            raw.get("rightFrontWindow"),
            raw.get("leftRearWindow"),
            raw.get("rightRearWindow"),
            raw.get("skylight"),
        ]
        known = [v for v in windows if v is not None]
        if not known:
            return None
        # BYD window mapping: 1=closed/up, 2=open/down.
        return all(str(v) == "1" for v in known)

    async def async_open_cover(self, **kwargs):
        raise HomeAssistantError("Windows-up remote command code is not mapped yet")
