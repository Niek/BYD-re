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
        suggested_display_precision=0,
    ),
    SensorEntityDescription(
        key="outside_temperature",
        name="Outside Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        suggested_display_precision=0,
    ),
    SensorEntityDescription(
        key="charge_time_remaining",
        name="Charge Time Remaining",
        native_unit_of_measurement=UnitOfTime.MINUTES,
        device_class=SensorDeviceClass.DURATION,
    ),
]


def _parse_temperature(value: float | str | None) -> float | None:
    """Parse temperature values and filter unavailable sentinel values."""
    if value is None:
        return None

    temp = float(value)
    return None if temp == -129 else temp


def _first_temperature(raw: dict, *keys: str) -> float | None:
    """Return the first valid temperature from the given payload keys."""
    for key in keys:
        parsed = _parse_temperature(raw.get(key))
        if parsed is not None:
            return parsed
    return None


def _temperature_without_decimals(raw: dict, *keys: str) -> int | None:
    """Return rounded temperature without decimals from the given payload keys."""
    temperature = _first_temperature(raw, *keys)
    if temperature is None:
        return None
    return round(temperature)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    raw = coordinator.realtime_raw()
    inside_temp = _first_temperature(raw, "tempInCar", "insideTemperature")

    descriptions = [
        desc
        for desc in SENSORS
        if desc.key != "inside_temperature" or inside_temp is not None
    ]

    async_add_entities(BydSensor(coordinator, desc) for desc in descriptions)


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
            value = rt.elec_percent
            return None if value is None else round(float(value))
        if self.entity_description.key == "range":
            value = rt.endurance_mileage
            return None if value is None else round(float(value))
        if self.entity_description.key == "inside_temperature":
            return _temperature_without_decimals(raw, "tempInCar", "insideTemperature")
        if self.entity_description.key == "outside_temperature":
            outside_temp = _temperature_without_decimals(raw, "tempOutCar", "outsideTemperature")
            if outside_temp is not None:
                return outside_temp

            return _temperature_without_decimals(raw, "tempInCar", "insideTemperature")
        if self.entity_description.key == "charge_time_remaining":
            hours = self._parse_remaining_component(raw.get("remainingHours"), minimum=0)
            minutes = self._parse_remaining_component(raw.get("remainingMinutes"), minimum=0, maximum=59)
            if hours is None and minutes is None:
                return None
            total_minutes = (hours if hours is not None else 0) * 60
            total_minutes += minutes if minutes is not None else 0
            return total_minutes
        return None

    @staticmethod
    def _parse_remaining_component(value, *, minimum: int, maximum: int | None = None) -> int | None:
        """Parse and validate a charge remaining component from raw payload."""
        if value is None:
            return None
        parsed = int(float(value))
        if parsed < minimum:
            return None
        if maximum is not None and parsed > maximum:
            return None
        return parsed
