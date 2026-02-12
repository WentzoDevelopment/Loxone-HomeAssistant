"""Loxone token-based authentication via RSA/AES key exchange."""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import textwrap
import urllib.parse
from typing import Any

import aiohttp

from .const import (
    CMD_ENCRYPT,
    CMD_GET_KEY2,
    CMD_GET_PUBLIC_KEY,
    CMD_GET_TOKEN,
    CMD_KEY_EXCHANGE,
    TOKEN_INFO,
    TOKEN_PERMISSION,
    TOKEN_UUID,
)
from .exceptions import LoxoneAuthError

_LOGGER = logging.getLogger(__name__)


class LoxoneAuth:
    """Handle Loxone Miniserver authentication with token-based auth."""

    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._public_key: Any = None
        self._aes_key: bytes = b""
        self._aes_iv: bytes = b""
        self._token: str | None = None
        self._token_valid_until: float = 0

    async def authenticate(
        self,
        ws: aiohttp.ClientWebSocketResponse,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
    ) -> None:
        """Run the full authentication flow.

        The public key is fetched via HTTP (as per Loxone's official protocol),
        while the rest of the auth flow uses the WebSocket connection.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # Step 1: Get RSA public key via HTTP (not WebSocket!)
        _LOGGER.debug("Auth step 1: Fetching public key via HTTP")
        key_pem = await self._fetch_public_key_http(session, host, port)
        self._public_key = self._parse_public_key(key_pem, serialization)
        _LOGGER.debug("Auth step 1: Public key parsed OK")

        # Step 2: Generate AES-256 session key + IV, RSA-encrypt, key exchange via WS
        _LOGGER.debug("Auth step 2: Key exchange via WebSocket")
        self._aes_key = os.urandom(32)
        self._aes_iv = os.urandom(16)
        session_key = f"{self._aes_key.hex()}:{self._aes_iv.hex()}"
        encrypted_key = self._public_key.encrypt(
            session_key.encode(),
            padding.PKCS1v15(),
        )
        key_exchange_cmd = CMD_KEY_EXCHANGE.format(
            binascii.b2a_base64(encrypted_key, newline=False).decode()
        )
        await ws.send_str(key_exchange_cmd)
        resp = await self._read_text_response(ws)
        _LOGGER.debug("Auth step 2: Key exchange response: %s", resp[:100])

        # Step 3: Get salt and hash info for the user
        _LOGGER.debug("Auth step 3: getkey2 for user '%s'", self._username)
        await ws.send_str(CMD_GET_KEY2.format(self._username))
        resp = await self._read_text_response(ws)
        key_info = self._extract_value(resp)
        if isinstance(key_info, str):
            key_info = json.loads(key_info)

        # Loxone returns key and salt as hex-encoded ASCII strings.
        # IMPORTANT: Use them as-is (raw hex strings), NOT decoded!
        # PyLoxone and lxcommunicator both use the raw values directly.
        raw_key = key_info.get("key", "")
        raw_salt = key_info.get("salt", "")
        hash_alg = key_info.get("hashAlg", "SHA256")

        _LOGGER.debug("Auth step 3: hashAlg=%s, raw_key=%s..., raw_salt=%s...",
                       hash_alg, raw_key[:16], raw_salt[:16])

        # Step 4: Compute HMAC hash of credentials
        if hash_alg.upper() == "SHA1":
            digest = hashlib.sha1
        else:
            digest = hashlib.sha256

        # Password hash: SHA256("password:raw_salt") — raw hex salt, NOT decoded
        pw_hash = digest(
            f"{self._password}:{raw_salt}".encode("utf-8")
        ).hexdigest().upper()

        # HMAC: key = bytes.fromhex(raw_key) = single decode (40 ASCII bytes)
        credential = f"{self._username}:{pw_hash}"
        hash_value = hmac.new(
            bytes.fromhex(raw_key), credential.encode("utf-8"), digest
        ).hexdigest()

        # Step 5: Request JWT token (encrypted via AES)
        token_cmd = CMD_GET_TOKEN.format(
            hash_value, self._username, TOKEN_PERMISSION
        )
        token_cmd += f"/{TOKEN_UUID}/{TOKEN_INFO}"
        _LOGGER.debug("Auth step 5: Requesting token (encrypted)")

        encrypted_cmd = self._aes_encrypt(token_cmd, Cipher, algorithms, modes)
        await ws.send_str(CMD_ENCRYPT.format(encrypted_cmd))
        resp = await self._read_text_response(ws)
        _LOGGER.debug("Auth step 5: Token response: %s", resp[:200])
        token_data = self._extract_value(resp)
        if isinstance(token_data, str):
            token_data = json.loads(token_data)

        self._token = token_data.get("token", "")
        valid_until = token_data.get("validUntil", 0)
        self._token_valid_until = valid_until
        _LOGGER.info("Authentication successful, token obtained")

    @staticmethod
    async def _fetch_public_key_http(
        session: aiohttp.ClientSession, host: str, port: int
    ) -> str:
        """Fetch the Miniserver's RSA public key via HTTP."""
        url = f"http://{host}:{port}/{CMD_GET_PUBLIC_KEY}"
        async with session.get(url) as resp:
            data = await resp.json(content_type=None)
        ll = data.get("LL", {})
        code = str(ll.get("code", ll.get("Code", "200")))
        value = ll.get("value", ll.get("Value", ""))
        if not code.startswith("200"):
            raise LoxoneAuthError(f"Failed to get public key: code {code}")
        _LOGGER.debug("Got public key via HTTP (%d chars)", len(str(value)))
        return value

    @staticmethod
    def _parse_public_key(raw_key: str, serialization: Any) -> Any:
        """Parse Loxone's public key (SubjectPublicKeyInfo in PEM-like format).

        Loxone wraps a SubjectPublicKeyInfo in CERTIFICATE headers
        and returns it without PEM line breaks. We fix the formatting
        and load it as a public key.
        """
        # Extract the raw base64 content, stripping any PEM headers
        b64 = re.sub(
            r"-----(?:BEGIN|END)[^-]+-----", "", raw_key
        ).replace("\n", "").replace("\r", "").strip()

        # Re-wrap as proper PEM with 64-char lines
        wrapped = "\n".join(textwrap.wrap(b64, 64))
        pem = f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----"

        _LOGGER.debug("Parsed public key (%d base64 chars)", len(b64))
        return serialization.load_pem_public_key(pem.encode())

    def _aes_encrypt(self, plaintext: str, cipher_cls: Any, algorithms: Any, modes: Any) -> str:
        """AES-256-CBC encrypt and return URL-safe base64."""
        data = plaintext.encode("utf-8")
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)

        cipher = cipher_cls(algorithms.AES(self._aes_key), modes.CBC(self._aes_iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        b64 = binascii.b2a_base64(encrypted, newline=False).decode()
        return urllib.parse.quote(b64, safe="")

    async def _read_text_response(self, ws: aiohttp.ClientWebSocketResponse) -> str:
        """Read text messages from WebSocket, skipping binary headers."""
        while True:
            msg = await ws.receive()
            if msg.type == aiohttp.WSMsgType.TEXT:
                _LOGGER.debug("WS recv TEXT: %s", msg.data[:200])
                return msg.data
            if msg.type == aiohttp.WSMsgType.BINARY:
                _LOGGER.debug("WS recv BINARY: %d bytes", len(msg.data))
                continue
            if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                raise LoxoneAuthError(f"WebSocket closed during auth: {msg}")
            _LOGGER.debug("WS recv other: type=%s", msg.type)

    @staticmethod
    def _extract_value(response: str) -> Any:
        """Extract the value from a Loxone JSON response."""
        try:
            data = json.loads(response)
            ll = data.get("LL", {})
            value = ll.get("value", ll.get("Value", response))
            code = str(ll.get("code", ll.get("Code", "200")))
            if not code.startswith("200"):
                raise LoxoneAuthError(f"Loxone error code {code}: {value}")
            return value
        except json.JSONDecodeError:
            return response
