"""Config flow for BYD."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers import selector
from .pybyd import BydClient, BydConfig

from .const import (
    CONF_BASE_URL,
    CONF_COUNTRY_CODE,
    CONF_CONTROL_PIN,
    CONF_SERVER_REGION,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_SERVER_REGION,
    DOMAIN,
)

LOGGER = logging.getLogger(__name__)


class BydConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for BYD."""

    VERSION = 1

    async def _async_validate_and_build_entry_data(
        self, user_input: dict[str, Any]
    ) -> tuple[dict[str, str], dict[str, Any] | None]:
        """Validate credentials and return normalized entry data."""
        region = f"-{user_input[CONF_SERVER_REGION].strip().lstrip('-').lower()}"
        base_url = f"https://dilinkappoversea{region}.byd.auto"

        LOGGER.debug(
            "Starting config flow validation for user=%s region=%s base_url=%s country_code=%s",
            user_input[CONF_EMAIL],
            region,
            base_url,
            user_input[CONF_COUNTRY_CODE],
        )

        config = BydConfig(
            user_input[CONF_EMAIL],
            user_input[CONF_PASSWORD],
            base_url=base_url,
            country_code=user_input[CONF_COUNTRY_CODE],
            control_pin=user_input.get(CONF_CONTROL_PIN) or None,
        )

        try:
            async with BydClient(config) as client:
                LOGGER.debug("Attempting BYD login during config flow")
                await client.login()
                LOGGER.debug("BYD login successful during config flow")
        except Exception:
            LOGGER.exception(
                "BYD login failed during config flow for user=%s region=%s base_url=%s",
                user_input[CONF_EMAIL],
                region,
                base_url,
            )
            return {"base": "cannot_connect"}, None

        return {}, {
            CONF_EMAIL: user_input[CONF_EMAIL],
            CONF_PASSWORD: user_input[CONF_PASSWORD],
            CONF_COUNTRY_CODE: user_input[CONF_COUNTRY_CODE],
            CONF_SERVER_REGION: region,
            CONF_BASE_URL: base_url,
            CONF_CONTROL_PIN: user_input.get(CONF_CONTROL_PIN) or "",
        }

    @staticmethod
    def _build_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
        """Build a shared schema for user/reconfigure forms."""
        defaults = defaults or {}
        default_region = (
            defaults.get(CONF_SERVER_REGION, DEFAULT_SERVER_REGION).lstrip("-")
        )
        return vol.Schema(
            {
                vol.Required(CONF_EMAIL, default=defaults.get(CONF_EMAIL, "")): str,
                vol.Required(CONF_PASSWORD, default=defaults.get(CONF_PASSWORD, "")): str,
                vol.Required(
                    CONF_COUNTRY_CODE,
                    default=defaults.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
                ): str,
                vol.Optional(
                    CONF_CONTROL_PIN,
                    default=defaults.get(CONF_CONTROL_PIN, ""),
                ): str,
                vol.Required(
                    CONF_SERVER_REGION,
                    default=default_region,
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=["eu", "au"],
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
            }
        )

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            errors, entry_data = await self._async_validate_and_build_entry_data(user_input)
            if not errors and entry_data is not None:
                await self.async_set_unique_id(f"{entry_data[CONF_EMAIL]}:{entry_data[CONF_BASE_URL]}")
                self._abort_if_unique_id_configured()
                LOGGER.debug(
                    "Creating config entry for user=%s base_url=%s",
                    entry_data[CONF_EMAIL],
                    entry_data[CONF_BASE_URL],
                )
                return self.async_create_entry(
                    title=f"BYD ({entry_data[CONF_EMAIL]})",
                    data=entry_data,
                )

        schema = self._build_schema()

        if errors:
            LOGGER.debug("Config flow returning form with errors: %s", errors)

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Handle reconfiguration of an existing BYD entry."""
        errors: dict[str, str] = {}
        entry = self._get_reconfigure_entry()

        if user_input is not None:
            errors, entry_data = await self._async_validate_and_build_entry_data(user_input)
            if not errors and entry_data is not None:
                await self.async_set_unique_id(f"{entry_data[CONF_EMAIL]}:{entry_data[CONF_BASE_URL]}")
                self._abort_if_unique_id_configured(updates={"entry_id": entry.entry_id})

                self.hass.config_entries.async_update_entry(
                    entry,
                    title=f"BYD ({entry_data[CONF_EMAIL]})",
                    data=entry_data,
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                LOGGER.debug("Reconfigured BYD entry_id=%s", entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")

        schema = self._build_schema(entry.data)

        if errors:
            LOGGER.debug("Reconfigure flow returning form with errors: %s", errors)

        return self.async_show_form(
            step_id="reconfigure", data_schema=schema, errors=errors
        )
