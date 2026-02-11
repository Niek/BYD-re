"""Config flow for BYD."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from .pybyd import BydClient, BydConfig

from .const import (
    CONF_BASE_URL,
    CONF_COUNTRY_CODE,
    CONF_SERVER_REGION,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_SERVER_REGION,
    DOMAIN,
)


class BydConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for BYD."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            region = user_input[CONF_SERVER_REGION].strip()
            base_url = f"https://dilinkappoversea{region}.byd.auto"

            config = BydConfig(
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                country_code=user_input[CONF_COUNTRY_CODE],
                base_url=base_url,
            )

            try:
                async with BydClient(config) as client:
                    await client.login()
            except Exception:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(f"{user_input[CONF_USERNAME]}:{base_url}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"BYD ({user_input[CONF_USERNAME]})",
                    data={
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_COUNTRY_CODE: user_input[CONF_COUNTRY_CODE],
                        CONF_SERVER_REGION: region,
                        CONF_BASE_URL: base_url,
                    },
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(CONF_COUNTRY_CODE, default=DEFAULT_COUNTRY_CODE): str,
                vol.Required(CONF_SERVER_REGION, default=DEFAULT_SERVER_REGION): str,
            }
        )

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
