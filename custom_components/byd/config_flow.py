"""Config flow for BYD."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers import selector

from .const import (
    CONF_BASE_URL,
    CONF_COUNTRY_CODE,
    CONF_CONTROL_PIN,
    CONF_SERVER_REGION,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_SERVER_REGION,
    DOMAIN,
)
from .pybyd import BydClient, BydConfig

LOGGER = logging.getLogger(__name__)

SERVER_REGION_OPTIONS = [
    selector.SelectOptionDict(value="eu", label="Europe"),
    selector.SelectOptionDict(value="au", label="Australia"),
]


class BydConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for BYD."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize flow state."""
        self._credentials_input: dict[str, Any] | None = None

    @staticmethod
    def _credentials_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
        """Build schema for credentials step."""
        defaults = defaults or {}
        return vol.Schema(
            {
                vol.Required(CONF_EMAIL, default=defaults.get(CONF_EMAIL, "")): str,
                vol.Required(CONF_PASSWORD, default=defaults.get(CONF_PASSWORD, "")): str,
                vol.Required(
                    CONF_CONTROL_PIN,
                    default=defaults.get(CONF_CONTROL_PIN, ""),
                ): str,
            }
        )

    @staticmethod
    def _server_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
        """Build schema for server selection step."""
        defaults = defaults or {}
        default_region = defaults.get(CONF_SERVER_REGION, DEFAULT_SERVER_REGION).lstrip("-")
        return vol.Schema(
            {
                vol.Required(
                    CONF_SERVER_REGION,
                    default=default_region,
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=SERVER_REGION_OPTIONS,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                )
            }
        )

    async def _async_validate_and_build_entry_data(
        self, user_input: dict[str, Any]
    ) -> tuple[dict[str, str], dict[str, Any] | None]:
        """Validate credentials and return normalized entry data."""
        region = f"-{user_input[CONF_SERVER_REGION].strip().lstrip('-').lower()}"
        base_url = f"https://dilinkappoversea{region}.byd.auto"

        LOGGER.debug(
            "Starting config flow validation for user=%s region=%s base_url=%s",
            user_input[CONF_EMAIL],
            region,
            base_url,
        )

        config = BydConfig(
            user_input[CONF_EMAIL],
            user_input[CONF_PASSWORD],
            base_url=base_url,
            country_code=DEFAULT_COUNTRY_CODE,
            control_pin=user_input[CONF_CONTROL_PIN],
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
            CONF_COUNTRY_CODE: DEFAULT_COUNTRY_CODE,
            CONF_SERVER_REGION: region,
            CONF_BASE_URL: base_url,
            CONF_CONTROL_PIN: user_input[CONF_CONTROL_PIN],
        }

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle first step of initial setup."""
        if user_input is not None:
            self._credentials_input = user_input
            return await self.async_step_server()

        return self.async_show_form(
            step_id="user",
            data_schema=self._credentials_schema(),
            errors={},
        )

    async def async_step_server(self, user_input: dict[str, Any] | None = None):
        """Handle server selection step for new configuration."""
        errors: dict[str, str] = {}

        if user_input is not None and self._credentials_input is not None:
            full_input = {**self._credentials_input, **user_input}
            errors, entry_data = await self._async_validate_and_build_entry_data(full_input)
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

        return self.async_show_form(
            step_id="server",
            data_schema=self._server_schema(),
            errors=errors,
        )

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Handle first reconfiguration step."""
        entry = self._get_reconfigure_entry()

        if user_input is not None:
            self._credentials_input = user_input
            return await self.async_step_reconfigure_server()

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self._credentials_schema(entry.data),
            errors={},
        )

    async def async_step_reconfigure_server(
        self, user_input: dict[str, Any] | None = None
    ):
        """Handle server selection reconfiguration step."""
        errors: dict[str, str] = {}
        entry = self._get_reconfigure_entry()

        if user_input is not None and self._credentials_input is not None:
            full_input = {**self._credentials_input, **user_input}
            errors, entry_data = await self._async_validate_and_build_entry_data(full_input)
            if not errors and entry_data is not None:
                new_unique_id = f"{entry_data[CONF_EMAIL]}:{entry_data[CONF_BASE_URL]}"
                for existing_entry in self._async_current_entries():
                    if (
                        existing_entry.entry_id != entry.entry_id
                        and existing_entry.unique_id == new_unique_id
                    ):
                        errors["base"] = "already_configured"
                        break

                if not errors:
                    self.hass.config_entries.async_update_entry(
                        entry,
                        unique_id=new_unique_id,
                        title=f"BYD ({entry_data[CONF_EMAIL]})",
                        data=entry_data,
                    )
                    await self.hass.config_entries.async_reload(entry.entry_id)
                    LOGGER.debug("Reconfigured BYD entry_id=%s", entry.entry_id)
                    return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="reconfigure_server",
            data_schema=self._server_schema(entry.data),
            errors=errors,
        )
