"""WebSocket client for Loxone Miniserver with reconnect and binary parsing."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

import aiohttp

from .auth import LoxoneAuth
from .binary_parser import MessageHeader, parse_header, parse_text_states, parse_value_states
from .const import (
    CMD_ENABLE_STATUS_UPDATE,
    CMD_GET_STRUCTURE,
    CMD_KEEPALIVE,
    KEEPALIVE_INTERVAL,
    MSG_TYPE_KEEPALIVE,
    MSG_TYPE_TEXT,
    MSG_TYPE_TEXT_STATES,
    MSG_TYPE_VALUE_STATES,
    RECONNECT_MAX,
    RECONNECT_MIN,
    WS_PATH,
    WS_PROTOCOL,
)
from .exceptions import LoxoneConnectionError

_LOGGER = logging.getLogger(__name__)


class LoxoneWebSocket:
    """Manages the WebSocket connection to a Loxone Miniserver."""

    def __init__(
        self,
        host: str,
        port: int,
        auth: LoxoneAuth,
        session: aiohttp.ClientSession,
    ) -> None:
        self._host = host
        self._port = port
        self._auth = auth
        self._session = session
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._listen_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._reconnect_delay = RECONNECT_MIN
        self._running = False
        self._connected = False

        # Callbacks
        self._on_value_states: Callable[[dict[str, float]], None] | None = None
        self._on_text_states: Callable[[dict[str, str]], None] | None = None
        self._on_connection_state: Callable[[bool], None] | None = None

        # Structure file data
        self.structure_data: dict[str, Any] | None = None

    @property
    def connected(self) -> bool:
        return self._connected

    def set_callbacks(
        self,
        on_value_states: Callable[[dict[str, float]], None] | None = None,
        on_text_states: Callable[[dict[str, str]], None] | None = None,
        on_connection_state: Callable[[bool], None] | None = None,
    ) -> None:
        self._on_value_states = on_value_states
        self._on_text_states = on_text_states
        self._on_connection_state = on_connection_state

    async def start(self) -> dict[str, Any]:
        """Connect, authenticate, fetch structure, and start listening.

        Returns the parsed LoxAPP3.json structure dict.
        """
        self._running = True
        await self._connect()
        if self.structure_data is None:
            raise LoxoneConnectionError("Failed to fetch structure file")
        return self.structure_data

    async def stop(self) -> None:
        """Disconnect and stop all tasks."""
        self._running = False
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
        if self._listen_task and not self._listen_task.done():
            self._listen_task.cancel()
        if self._ws and not self._ws.closed:
            await self._ws.close()
        self._set_connected(False)

    async def _connect(self) -> None:
        """Establish WebSocket connection with auth."""
        url = f"ws://{self._host}:{self._port}{WS_PATH}"
        _LOGGER.info("Connecting to Loxone at %s", url)
        try:
            self._ws = await self._session.ws_connect(
                url,
                protocols=[WS_PROTOCOL],
                heartbeat=30,
            )
        except Exception as err:
            raise LoxoneConnectionError(
                f"Cannot connect to {url}: {err}"
            ) from err

        # Authenticate (public key via HTTP, rest via WebSocket)
        await self._auth.authenticate(self._ws, self._session, self._host, self._port)

        # Fetch structure file
        await self._ws.send_str(CMD_GET_STRUCTURE)
        self.structure_data = await self._read_structure_response()

        # Enable binary status updates
        await self._ws.send_str(CMD_ENABLE_STATUS_UPDATE)
        # Read the text response acknowledging the command
        await self._read_text_until_ack()

        self._set_connected(True)
        self._reconnect_delay = RECONNECT_MIN

        # Start background tasks
        self._listen_task = asyncio.create_task(self._listen_loop())
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    async def _read_structure_response(self) -> dict[str, Any]:
        """Read the LoxAPP3.json response (text message preceded by binary header)."""
        while True:
            msg = await self._ws.receive()  # type: ignore[union-attr]
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    return json.loads(msg.data)
                except json.JSONDecodeError:
                    # Might be a command response, keep reading
                    continue
            if msg.type == aiohttp.WSMsgType.BINARY:
                # Could be binary header before the text, skip
                continue
            if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                raise LoxoneConnectionError("Connection closed while fetching structure")

    async def _read_text_until_ack(self) -> None:
        """Read messages until we get a text acknowledgment."""
        while True:
            msg = await self._ws.receive()  # type: ignore[union-attr]
            if msg.type == aiohttp.WSMsgType.TEXT:
                return
            if msg.type == aiohttp.WSMsgType.BINARY:
                continue
            if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                return

    async def _listen_loop(self) -> None:
        """Main receive loop: parse headers then payloads."""
        pending_header: MessageHeader | None = None
        try:
            while self._running and self._ws and not self._ws.closed:
                msg = await self._ws.receive()

                if msg.type == aiohttp.WSMsgType.BINARY:
                    data = msg.data
                    if pending_header is None:
                        # This should be a header
                        try:
                            pending_header = parse_header(data)
                        except Exception:
                            _LOGGER.debug("Skipping unparseable binary frame")
                            continue
                        # If the payload is in the same frame (header + payload)
                        if len(data) > 8 and pending_header.payload_length > 0:
                            payload = data[8:]
                            self._handle_payload(pending_header, payload)
                            pending_header = None
                    else:
                        # This is the payload for the pending header
                        self._handle_payload(pending_header, data)
                        pending_header = None

                elif msg.type == aiohttp.WSMsgType.TEXT:
                    # Text responses to commands — can reset header state
                    pending_header = None

                elif msg.type in (
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSING,
                ):
                    _LOGGER.warning("WebSocket connection lost")
                    break

        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.exception("Error in WebSocket listen loop")

        # Connection lost — attempt reconnect
        self._set_connected(False)
        if self._running:
            asyncio.create_task(self._reconnect())

    def _handle_payload(self, header: MessageHeader, data: bytes) -> None:
        """Process a payload based on its message type."""
        if header.msg_type == MSG_TYPE_VALUE_STATES:
            states = parse_value_states(data)
            if states and self._on_value_states:
                self._on_value_states(states)
        elif header.msg_type == MSG_TYPE_TEXT_STATES:
            states = parse_text_states(data)
            if states and self._on_text_states:
                self._on_text_states(states)
        elif header.msg_type == MSG_TYPE_KEEPALIVE:
            pass  # Expected
        elif header.msg_type == MSG_TYPE_TEXT:
            pass  # Text message payload, usually command responses

    async def _keepalive_loop(self) -> None:
        """Send keepalive messages periodically."""
        try:
            while self._running and self._ws and not self._ws.closed:
                await asyncio.sleep(KEEPALIVE_INTERVAL)
                if self._ws and not self._ws.closed:
                    await self._ws.send_str(CMD_KEEPALIVE)
        except asyncio.CancelledError:
            pass
        except Exception:
            _LOGGER.debug("Keepalive loop ended")

    async def _reconnect(self) -> None:
        """Reconnect with exponential backoff."""
        while self._running:
            _LOGGER.info(
                "Reconnecting in %d seconds...", self._reconnect_delay
            )
            await asyncio.sleep(self._reconnect_delay)
            self._reconnect_delay = min(
                self._reconnect_delay * 2, RECONNECT_MAX
            )
            try:
                if self._ws and not self._ws.closed:
                    await self._ws.close()
                await self._connect()
                return
            except Exception:
                _LOGGER.exception("Reconnect failed")

    def _set_connected(self, state: bool) -> None:
        if self._connected != state:
            self._connected = state
            if self._on_connection_state:
                self._on_connection_state(state)
