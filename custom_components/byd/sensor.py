"""Sensor platform for BYD."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfLength, PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity

SENSORS = [
    SensorEntityDescription(key="battery", name="Battery", native_unit_of_measurement=PERCENTAGE, device_class=SensorDeviceClass.BATTERY),
    SensorEntityDescription(key="range", name="Range", native_unit_of_measurement=UnitOfLength.KILOMETERS),
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(BydSensor(coordinator, desc) for desc in SENSORS)


class BydSensor(BydEntity, SensorEntity):
    """BYD basic sensors."""

    def __init__(self, coordinator, description: SensorEntityDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{self.unique_base}_{description.key}"

    @property
    def native_value(self):
        rt = self.coordinator.data.realtime
        if self.entity_description.key == "battery":
            return rt.elec_percent
        if self.entity_description.key == "range":
            return rt.endurance_mileage
        return None
