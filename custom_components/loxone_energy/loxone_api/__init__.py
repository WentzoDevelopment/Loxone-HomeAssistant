"""Loxone WebSocket API — connection facade."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import aiohttp

from .auth import LoxoneAuth
from .structure_parser import StructureParser
from .websocket_client import LoxoneWebSocket

_LOGGER = logging.getLogger(__name__)


class LoxoneConnection:
    """High-level facade combining auth, WebSocket and structure parsing."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
    ) -> None:
        self._auth = LoxoneAuth(username, password)
        self._ws = LoxoneWebSocket(host, port, self._auth, session)
        self._structure: StructureParser | None = None

    @property
    def connected(self) -> bool:
        return self._ws.connected

    @property
    def structure(self) -> StructureParser | None:
        return self._structure

    async def start(
        self,
        on_state_update: Callable[[dict[str, float]], None],
        on_text_state_update: Callable[[dict[str, str]], None] | None = None,
        on_connection_state: Callable[[bool], None] | None = None,
    ) -> StructureParser:
        """Connect, authenticate, and start receiving updates.

        Returns a StructureParser with all discovered controls.
        """
        self._ws.set_callbacks(
            on_value_states=on_state_update,
            on_text_states=on_text_state_update,
            on_connection_state=on_connection_state,
        )
        structure_data = await self._ws.start()
        self._structure = StructureParser(structure_data)
        _LOGGER.info(
            "Connected to %s — %d meters, %d EFM, %d text states",
            self._structure.miniserver_info.name if self._structure.miniserver_info else "?",
            len(self._structure.meters),
            len(self._structure.efm_controls),
            len(self._structure.text_states),
        )
        return self._structure

    async def stop(self) -> None:
        """Disconnect from the Miniserver."""
        await self._ws.stop()
