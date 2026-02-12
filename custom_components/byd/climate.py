"""Climate platform for BYD."""

from __future__ import annotations

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import HVACMode
from homeassistant.const import UnitOfTemperature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BydClimate(coordinator)])


class BydClimate(BydEntity, ClimateEntity):
    """BYD climate on/off."""

    _attr_name = "Climate"
    _attr_hvac_modes = [HVACMode.OFF, HVACMode.HEAT_COOL]
    # Home Assistant's climate capability handling expects an iterable of
    # ClimateEntityFeature values (even when empty).
    _attr_supported_features: tuple = ()
    _attr_temperature_unit = UnitOfTemperature.CELSIUS

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self.unique_base}_climate"

    @property
    def hvac_mode(self) -> HVACMode | None:
        raw = self.coordinator.realtime_raw()
        # Newer BYD payloads expose runtime state in airRunState (1=on, 0/2=off).
        # Keep fallback to airconditionStatus for older payload variants.
        run_state = raw.get("airRunState")
        if run_state is not None:
            return HVACMode.HEAT_COOL if str(run_state) == "1" else HVACMode.OFF

        climate = raw.get("airconditionStatus")
        if climate is not None:
            return HVACMode.HEAT_COOL if str(climate) == "1" else HVACMode.OFF
        return HVACMode.OFF

    @property
    def current_temperature(self) -> float | None:
        raw = self.coordinator.realtime_raw()
        value = raw.get("tempInCar")
        if value is None:
            return None
        try:
            temp = float(value)
        except (TypeError, ValueError):
            return None
        return None if temp == -129 else temp

    @property
    def target_temperature(self) -> float | None:
        raw = self.coordinator.realtime_raw()
        value = raw.get("mainSettingTempNew")
        if value is None:
            value = raw.get("mainSettingTemp")
        if value is None:
            return None
        try:
            temp = float(value)
        except (TypeError, ValueError):
            return None
        return None if temp == -129 else temp

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        raise HomeAssistantError("Climate control is not mapped to the BYD API yet")
