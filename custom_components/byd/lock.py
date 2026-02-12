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
        self._attr_is_locking = False
        self._attr_is_unlocking = False

    @staticmethod
    def _door_lock_values(raw: dict) -> list[str]:
        """Collect known per-door lock values from realtime payload variants."""
        key_variants = (
            ("leftFrontDoorLock", "frontLeftDoorLock", "lfDoorLock"),
            ("rightFrontDoorLock", "frontRightDoorLock", "rfDoorLock"),
            ("leftRearDoorLock", "rearLeftDoorLock", "lrDoorLock"),
            ("rightRearDoorLock", "rearRightDoorLock", "rrDoorLock"),
        )

        values: list[str] = []
        for variants in key_variants:
            value = next((raw.get(key) for key in variants if raw.get(key) is not None), None)
            if value is not None:
                values.append(str(value))
        return values

    @property
    def is_locked(self) -> bool | None:
        raw = self.coordinator.realtime_raw()
        known = self._door_lock_values(raw)
        if not known:
            return None
        # BYD lock mapping is 2=locked, 1=unlocked. Door lock fields should match,
        # but pick the first known value for stability when payloads briefly diverge.
        return known[0] == "2"

    async def async_lock(self, **kwargs):
        self._attr_is_locking = True
        self._attr_is_unlocking = False
        self.async_write_ha_state()
        try:
            await self.coordinator.async_lock(command_pwd=kwargs.get("code"))
        finally:
            self._attr_is_locking = False
            self.async_write_ha_state()

    async def async_unlock(self, **kwargs):
        self._attr_is_unlocking = True
        self._attr_is_locking = False
        self.async_write_ha_state()
        try:
            await self.coordinator.async_unlock(command_pwd=kwargs.get("code"))
        finally:
            self._attr_is_unlocking = False
            self.async_write_ha_state()
