"""Push-based DataUpdateCoordinator for Loxone Energy."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN
from .loxone_api import LoxoneConnection
from .loxone_api.structure_parser import StructureParser

_LOGGER = logging.getLogger(__name__)


class LoxoneEnergyCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator that receives push updates from the Loxone Miniserver."""

    def __init__(
        self,
        hass: HomeAssistant,
        host: str,
        port: int,
        username: str,
        password: str,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            # No update_interval — this is push-based
        )
        session = async_get_clientsession(hass)
        self._connection = LoxoneConnection(host, port, username, password, session)
        self._structure: StructureParser | None = None
        self._state_values: dict[str, float] = {}
        self._text_values: dict[str, str] = {}

    @property
    def structure(self) -> StructureParser | None:
        return self._structure

    async def async_setup(self) -> None:
        """Connect to the Miniserver and start receiving updates."""
        self._structure = await self._connection.start(
            on_state_update=self._on_value_states,
            on_text_state_update=self._on_text_states,
            on_connection_state=self._on_connection_state,
        )
        # Set initial data so entities can initialize
        self.async_set_updated_data(dict(self._state_values))

    @callback
    def _on_value_states(self, states: dict[str, float]) -> None:
        """Handle incoming value state updates from the Miniserver."""
        self._state_values.update(states)
        self.async_set_updated_data(dict(self._state_values))

    @callback
    def _on_text_states(self, states: dict[str, str]) -> None:
        """Handle incoming text state updates."""
        self._text_values.update(states)

    @callback
    def _on_connection_state(self, connected: bool) -> None:
        """Handle connection state changes."""
        if connected:
            _LOGGER.info("Loxone connection restored")
        else:
            _LOGGER.warning("Loxone connection lost")

    def get_value(self, state_uuid: str) -> float | None:
        """Get the current value for a state UUID."""
        return self._state_values.get(state_uuid)

    def get_text_value(self, state_uuid: str) -> str | None:
        """Get the current text value for a state UUID."""
        return self._text_values.get(state_uuid)

    async def async_shutdown(self) -> None:
        """Disconnect from the Miniserver."""
        await self._connection.stop()
        await super().async_shutdown()

    async def _async_update_data(self) -> dict[str, Any]:
        """Not used — updates are push-based."""
        return dict(self._state_values)
