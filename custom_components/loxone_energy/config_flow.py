"""Config flow for Loxone Energy integration."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, DEFAULT_PORT, DOMAIN
from .loxone_api import LoxoneConnection
from .loxone_api.exceptions import LoxoneAuthError, LoxoneConnectionError

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


class LoxoneEnergyConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Loxone Energy."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            connection = LoxoneConnection(
                host=user_input[CONF_HOST],
                port=user_input[CONF_PORT],
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                session=session,
            )

            try:
                structure = await connection.start(
                    on_state_update=lambda _: None,
                )
            except LoxoneAuthError:
                errors["base"] = "invalid_auth"
            except (LoxoneConnectionError, aiohttp.ClientError, TimeoutError):
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during setup")
                errors["base"] = "unknown"
            else:
                # Use serial number as unique ID
                serial = structure.miniserver_info.serial_nr if structure.miniserver_info else ""
                await connection.stop()

                if serial:
                    await self.async_set_unique_id(serial)
                    self._abort_if_unique_id_configured()

                title = (
                    structure.miniserver_info.name
                    if structure.miniserver_info
                    else user_input[CONF_HOST]
                )
                return self.async_create_entry(title=title, data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
