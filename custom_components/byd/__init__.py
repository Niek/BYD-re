"""BYD integration."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import CONF_BASE_URL, CONF_COUNTRY_CODE, CONF_VIN, DOMAIN, PLATFORMS
from .coordinator import BydDataCoordinator

LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up BYD from a config entry."""
    LOGGER.debug("Setting up BYD entry_id=%s title=%s", entry.entry_id, entry.title)
    coordinator = BydDataCoordinator(
        hass=hass,
        email=entry.data[CONF_EMAIL],
        password=entry.data[CONF_PASSWORD],
        country_code=entry.data[CONF_COUNTRY_CODE],
        base_url=entry.data[CONF_BASE_URL],
        vin=entry.data.get(CONF_VIN),
        session=async_get_clientsession(hass),
    )

    await coordinator.async_initialize()
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    LOGGER.debug(
        "Stored coordinator for entry_id=%s and forwarding platforms: %s",
        entry.entry_id,
        PLATFORMS,
    )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    LOGGER.debug("BYD setup complete for entry_id=%s", entry.entry_id)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    LOGGER.debug("Unloading BYD entry_id=%s", entry.entry_id)
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_shutdown()
        LOGGER.debug("BYD unload complete for entry_id=%s", entry.entry_id)
    else:
        LOGGER.debug(
            "BYD unload skipped for entry_id=%s because platform unload failed",
            entry.entry_id,
        )
    return unload_ok
