"""Binary sensors for BYD."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity, BinarySensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import BydEntity

BINARY_SENSORS = [
    BinarySensorEntityDescription(key="bonnet", name="Front Bonnet"),
    BinarySensorEntityDescription(key="doors", name="Doors", device_class=BinarySensorDeviceClass.DOOR),
    BinarySensorEntityDescription(key="windows", name="Windows", device_class=BinarySensorDeviceClass.WINDOW),
    BinarySensorEntityDescription(key="boot", name="Boot", device_class=BinarySensorDeviceClass.OPENING),
    BinarySensorEntityDescription(key="charging", name="Charging", device_class=BinarySensorDeviceClass.BATTERY_CHARGING),
    BinarySensorEntityDescription(
        key="online",
        name="Online",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(BydBinarySensor(coordinator, d) for d in BINARY_SENSORS)


class BydBinarySensor(BydEntity, BinarySensorEntity):
    """BYD binary sensor."""

    def __init__(self, coordinator, description: BinarySensorEntityDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{self.unique_base}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        raw = self.coordinator.realtime_raw()

        if self.entity_description.key == "bonnet":
            value = raw.get("engineCover")
            return None if value is None else str(value) == "1"

        if self.entity_description.key == "doors":
            fields = ["leftFrontDoor", "rightFrontDoor", "leftRearDoor", "rightRearDoor"]
            values = [raw.get(k) for k in fields if raw.get(k) is not None]
            return None if not values else any(str(v) == "1" for v in values)

        if self.entity_description.key == "windows":
            fields = ["leftFrontWindow", "rightFrontWindow", "leftRearWindow", "rightRearWindow", "skylight"]
            values = [raw.get(k) for k in fields if raw.get(k) is not None]
            if not values:
                return None
            # BYD window encoding is inconsistent by model/region. In observed payloads:
            #   1 = closed/up
            #   2 = open/down
            # Some payloads can still use 0 for open.
            return any(str(v) in {"0", "2"} for v in values)

        if self.entity_description.key == "boot":
            value = raw.get("trunkLid")
            if value is None:
                value = raw.get("backCover")
            return None if value is None else str(value) == "1"

        if self.entity_description.key == "charging":
            value = self.coordinator.data.realtime.charging_state
            if value is None:
                return None
            try:
                return int(float(value)) != -1
            except (TypeError, ValueError):
                return str(value).strip().lower() in {"1", "2", "charging", "true", "on"}

        if self.entity_description.key == "online":
            value = raw.get("onlineState")
            return None if value is None else str(value) == "1"

        return None
