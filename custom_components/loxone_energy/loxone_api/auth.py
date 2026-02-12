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
        await ws.send_str(CMD_GET_PUBLIC_KEY)
        resp = await self._read_text_response(ws)
        key_pem = self._extract_value(resp)
        # Loxone returns the key without proper PEM wrapping sometimes
        if "BEGIN" not in key_pem:
            key_pem = (
                "-----BEGIN CERTIFICATE-----\n"
                + key_pem
                + "\n-----END CERTIFICATE-----"
            )
        try:
            from cryptography import x509

            cert = x509.load_pem_x509_certificate(key_pem.encode())
            self._public_key = cert.public_key()
        except Exception:
            # Try loading as raw public key
            if "CERTIFICATE" in key_pem:
                key_pem = key_pem.replace("CERTIFICATE", "PUBLIC KEY")
            self._public_key = serialization.load_pem_public_key(key_pem.encode())

        # Step 2: Generate AES-256 session key + IV, RSA-encrypt, key exchange
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
        _LOGGER.debug("Key exchange response: %s", resp)

        # Step 3: Get salt and hash info for the user
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
        hmac_key = bytes.fromhex(raw_key).decode("utf-8")   # e.g. "55E76F28..."
        pw_salt = bytes.fromhex(raw_salt).decode("utf-8")   # e.g. "1d955ba3-0016-..."

        _LOGGER.debug("hashAlg=%s, hmac_key=%s..., pw_salt=%s...",
                       hash_alg, hmac_key[:8], pw_salt[:8])

        # Step 4: Compute HMAC hash of credentials
        if hash_alg.upper() == "SHA1":
            digest = hashlib.sha1
        else:
            digest = hashlib.sha256

        # Hash the password with the SALT: uppercase(hex(hash(password:salt)))
        pw_hash = digest(
            f"{self._password}:{pw_salt}".encode("utf-8")
        ).hexdigest().upper()

        # HMAC of "user:pwHash" with the KEY as HMAC key
        credential = f"{self._username}:{pw_hash}"
        hash_value = hmac.new(
            bytes.fromhex(hmac_key), credential.encode("utf-8"), digest
        ).hexdigest()

        # Step 5: Request JWT token (encrypted via AES)
        token_cmd = CMD_GET_TOKEN.format(
            hash_value, self._username, TOKEN_PERMISSION
        )
        # Add token UUID and info
        token_cmd += f"/{TOKEN_UUID}/{TOKEN_INFO}"

        # Encrypt the command
        encrypted_cmd = self._aes_encrypt(token_cmd, Cipher, algorithms, modes)
        await ws.send_str(CMD_ENCRYPT.format(encrypted_cmd))
        resp = await self._read_text_response(ws)
        token_data = self._extract_value(resp)
        if isinstance(token_data, str):
            token_data = json.loads(token_data)

        self._token = token_data.get("token", "")
        valid_until = token_data.get("validUntil", 0)
        # Loxone uses seconds since 2009-01-01
        self._token_valid_until = valid_until
        _LOGGER.info("Authentication successful, token obtained")

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
