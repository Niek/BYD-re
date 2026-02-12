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
    CONF_SERVER_REGION,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_SERVER_REGION,
    DOMAIN,
)

LOGGER = logging.getLogger(__name__)


class BydConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for BYD."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
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
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(
                    f"{user_input[CONF_EMAIL]}:{base_url}"
                )
                self._abort_if_unique_id_configured()
                LOGGER.debug(
                    "Creating config entry for user=%s base_url=%s",
                    user_input[CONF_EMAIL],
                    base_url,
                )
                return self.async_create_entry(
                    title=f"BYD ({user_input[CONF_EMAIL]})",
                    data={
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_COUNTRY_CODE: user_input[CONF_COUNTRY_CODE],
                        CONF_SERVER_REGION: region,
                        CONF_BASE_URL: base_url,
                    },
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_EMAIL): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(CONF_COUNTRY_CODE, default=DEFAULT_COUNTRY_CODE): str,
                vol.Required(
                    CONF_SERVER_REGION,
                    default=DEFAULT_SERVER_REGION.lstrip("-"),
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=["eu", "au"],
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
            }
        )

        if errors:
            LOGGER.debug("Config flow returning form with errors: %s", errors)

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
