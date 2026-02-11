"""Sensor platform for BYD."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfLength, UnitOfTemperature, UnitOfTime, PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity

SENSORS = [
    SensorEntityDescription(key="battery", name="Battery", native_unit_of_measurement=PERCENTAGE, device_class=SensorDeviceClass.BATTERY),
    SensorEntityDescription(key="range", name="Range", native_unit_of_measurement=UnitOfLength.KILOMETERS),
    SensorEntityDescription(
        key="inside_temperature",
        name="Inside Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
    ),
    SensorEntityDescription(
        key="outside_temperature",
        name="Outside Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
    ),
    SensorEntityDescription(
        key="charge_time_remaining",
        name="Charge Time Remaining",
        native_unit_of_measurement=UnitOfTime.MINUTES,
        device_class=SensorDeviceClass.DURATION,
    ),
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
        raw = self.coordinator.realtime_raw()
        if self.entity_description.key == "battery":
            return rt.elec_percent
        if self.entity_description.key == "range":
            return rt.endurance_mileage
        if self.entity_description.key == "inside_temperature":
            value = raw.get("tempInCar")
            return float(value) if value is not None else None
        if self.entity_description.key == "outside_temperature":
            value = raw.get("tempOutCar")
            return float(value) if value is not None else None
        if self.entity_description.key == "charge_time_remaining":
            hours = raw.get("remainingHours")
            minutes = raw.get("remainingMinutes")
            if hours is None and minutes is None:
                return None
            total_minutes = (int(float(hours)) if hours is not None else 0) * 60
            total_minutes += int(float(minutes)) if minutes is not None else 0
            return total_minutes
        return None
