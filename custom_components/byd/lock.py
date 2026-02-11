"""Lock platform for BYD."""

from __future__ import annotations

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydDoorLock(coordinator)])


class BydDoorLock(BydEntity, LockEntity):
    """Door lock entity."""

    _attr_name = "Door Lock"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_door_lock"

    @property
    def is_locked(self) -> bool | None:
        raw = self.coordinator.realtime_raw()
        locks = [
            raw.get("leftFrontDoorLock"),
            raw.get("rightFrontDoorLock"),
            raw.get("leftRearDoorLock"),
            raw.get("rightRearDoorLock"),
        ]
        known = [v for v in locks if v is not None]
        if not known:
            return None
        # Recent BYD payloads report door lock state as 2=locked, 1=unlocked.
        # Keep string coercion for compatibility with legacy numeric/string payloads.
        return all(str(v) == "2" for v in known)

    async def async_lock(self, **kwargs):
        await self.coordinator.async_lock()

    async def async_unlock(self, **kwargs):
        await self.coordinator.async_unlock()
