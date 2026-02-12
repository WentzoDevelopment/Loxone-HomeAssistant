"""Loxone token-based authentication via RSA/AES key exchange."""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
from typing import Any

import aiohttp

from .const import (
    CMD_AUTHENTICATE,
    CMD_ENCRYPT,
    CMD_GET_KEY2,
    CMD_GET_PUBLIC_KEY,
    CMD_GET_TOKEN,
    CMD_KEY_EXCHANGE,
    CMD_REFRESH_TOKEN,
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

    async def authenticate(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Run the full authentication flow over an open WebSocket."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # Step 1: Get RSA public key
        _LOGGER.debug("Auth step 1: Getting public key")
        await ws.send_str(CMD_GET_PUBLIC_KEY)
        resp = await self._read_text_response(ws)
        key_pem = self._extract_value(resp)
        self._public_key = self._parse_public_key(key_pem, serialization)
        _LOGGER.debug("Auth step 1: Public key parsed OK")

        # Step 2: Generate AES-256 session key + IV, RSA-encrypt, key exchange
        _LOGGER.debug("Auth step 2: Key exchange")
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
        _LOGGER.debug("Auth step 2: Key exchange response: %s", resp)

        # Step 3: Get salt and hash info for the user
        _LOGGER.debug("Auth step 3: getkey2 for user '%s'", self._username)
        await ws.send_str(CMD_GET_KEY2.format(self._username))
        resp = await self._read_text_response(ws)
        key_info = self._extract_value(resp)
        if isinstance(key_info, str):
            key_info = json.loads(key_info)

        # Loxone returns key and salt as hex-encoded ASCII strings
        raw_key = key_info.get("key", "")
        raw_salt = key_info.get("salt", "")
        hash_alg = key_info.get("hashAlg", "SHA256")

        # Decode hex-encoded ASCII to get the actual values
        hmac_key = bytes.fromhex(raw_key).decode("utf-8")
        pw_salt = bytes.fromhex(raw_salt).decode("utf-8")

        _LOGGER.debug("Auth step 3: hashAlg=%s, hmac_key=%s..., pw_salt=%s...",
                       hash_alg, hmac_key[:8], pw_salt[:8])

        # Step 4: Compute HMAC hash of credentials
        if hash_alg.upper() == "SHA1":
            digest = hashlib.sha1
        else:
            digest = hashlib.sha256

        pw_hash = digest(
            f"{self._password}:{pw_salt}".encode("utf-8")
        ).hexdigest().upper()

        credential = f"{self._username}:{pw_hash}"
        hash_value = hmac.new(
            bytes.fromhex(hmac_key), credential.encode("utf-8"), digest
        ).hexdigest()

        # Step 5: Request JWT token (encrypted via AES)
        token_cmd = CMD_GET_TOKEN.format(
            hash_value, self._username, TOKEN_PERMISSION
        )
        token_cmd += f"/{TOKEN_UUID}/{TOKEN_INFO}"
        _LOGGER.debug("Auth step 5: Token command (unencrypted): %s",
                       token_cmd[:60] + "...")

        encrypted_cmd = self._aes_encrypt(token_cmd, Cipher, algorithms, modes)
        await ws.send_str(CMD_ENCRYPT.format(encrypted_cmd))
        resp = await self._read_text_response(ws)
        _LOGGER.debug("Auth step 5: Token response: %s", resp)
        token_data = self._extract_value(resp)
        if isinstance(token_data, str):
            token_data = json.loads(token_data)

        self._token = token_data.get("token", "")
        valid_until = token_data.get("validUntil", 0)
        self._token_valid_until = valid_until
        _LOGGER.info("Authentication successful, token obtained")

    @staticmethod
    def _parse_public_key(raw_key: str, serialization: Any) -> Any:
        """Parse Loxone's public key (SubjectPublicKeyInfo in PEM-like format).

        Loxone wraps a SubjectPublicKeyInfo in CERTIFICATE headers
        and returns it without PEM line breaks. We fix the formatting
        and load it as a public key.
        """
        import re
        import textwrap

        # Extract the raw base64 content, stripping any PEM headers
        b64 = re.sub(
            r"-----(?:BEGIN|END)\s+\w+-----", "", raw_key
        ).replace("\n", "").replace("\r", "").strip()

        # Re-wrap as proper PEM with 64-char lines
        wrapped = "\n".join(textwrap.wrap(b64, 64))
        pem = f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----"

        _LOGGER.debug("Parsed public key (%d base64 chars)", len(b64))
        return serialization.load_pem_public_key(pem.encode())

    def _aes_encrypt(self, plaintext: str, Cipher: Any, algorithms: Any, modes: Any) -> str:
        """AES-256-CBC encrypt and return URL-safe base64."""
        # Pad to 16-byte boundary (PKCS7)
        data = plaintext.encode("utf-8")
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)

        cipher = Cipher(algorithms.AES(self._aes_key), modes.CBC(self._aes_iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        b64 = binascii.b2a_base64(encrypted, newline=False).decode()
        return urllib.parse.quote(b64, safe="")

    async def _read_text_response(self, ws: aiohttp.ClientWebSocketResponse) -> str:
        """Read text messages from WebSocket, skipping binary headers."""
        while True:
            msg = await ws.receive()
            if msg.type == aiohttp.WSMsgType.TEXT:
                return msg.data
            if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                raise LoxoneAuthError(f"WebSocket closed during auth: {msg}")
            # Skip binary messages (headers before text responses)

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
