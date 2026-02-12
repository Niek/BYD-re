"""Climate platform for BYD."""

from __future__ import annotations

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import ClimateEntityFeature, HVACMode
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
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
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
    def target_temperature(self) -> float | None:
        raw = self.coordinator.realtime_raw()
        value = raw.get("mainSettingTemp")
        if value is None:
            return None
        try:
            temp = float(value)
        except (TypeError, ValueError):
            return None
        if temp == -129:
            return None
        # Some BYD payloads report 0 when HVAC is off and no set point is available.
        # Returning None avoids showing a misleading 0°C target in Home Assistant.
        if temp == 0 and self.hvac_mode == HVACMode.OFF:
            return None
        return temp

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        raise HomeAssistantError("Climate control is not mapped to the BYD API yet")

    async def async_set_temperature(self, **kwargs) -> None:
        raise HomeAssistantError("Setting climate temperature is not mapped to the BYD API yet")
