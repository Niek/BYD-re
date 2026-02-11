"""Shared BYD entity helpers."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import BydDataCoordinator


class BydEntity(CoordinatorEntity[BydDataCoordinator]):
    """Base BYD coordinator entity."""

    _attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        vehicle = self.coordinator.data.vehicle
        return DeviceInfo(
            identifiers={(DOMAIN, self.coordinator.data.vin)},
            name=vehicle.auto_alias or vehicle.model_name or "BYD Vehicle",
            manufacturer=vehicle.brand_name or "BYD",
            model=vehicle.model_name,
        )

    @property
    def unique_base(self) -> str:
        return self.coordinator.data.vin
