"""Binary protocol parser for Loxone WebSocket messages."""

from __future__ import annotations

import struct
import uuid as uuid_mod
from typing import NamedTuple

from .const import (
    HEADER_LENGTH,
    HEADER_MARKER,
    INFO_FLAG_ESTIMATED,
    VALUE_STATE_ENTRY_SIZE,
)
from .exceptions import LoxoneProtocolError


class MessageHeader(NamedTuple):
    """Parsed binary message header."""

    msg_type: int
    info_flags: int
    payload_length: int

    @property
    def is_estimated(self) -> bool:
        return bool(self.info_flags & INFO_FLAG_ESTIMATED)


def parse_header(data: bytes) -> MessageHeader:
    """Parse an 8-byte Loxone binary header.

    Format: marker(1) | msg_type(1) | info_flags(1) | reserved(1) | payload_length(4 LE)
    """
    if len(data) < HEADER_LENGTH:
        raise LoxoneProtocolError(
            f"Header too short: {len(data)} bytes, expected {HEADER_LENGTH}"
        )
    marker = data[0]
    if marker != HEADER_MARKER:
        raise LoxoneProtocolError(
            f"Invalid header marker: 0x{marker:02x}, expected 0x{HEADER_MARKER:02x}"
        )
    msg_type = data[1]
    info_flags = data[2]
    payload_length = struct.unpack_from("<I", data, 4)[0]
    return MessageHeader(msg_type, info_flags, payload_length)


def uuid_bytes_to_string(data: bytes) -> str:
    """Convert 16 bytes (mixed-endian) to a Loxone UUID string."""
    return str(uuid_mod.UUID(bytes_le=data))


def parse_value_states(data: bytes) -> dict[str, float]:
    """Parse type 0x02 value states.

    Each entry is 24 bytes: 16-byte UUID (mixed-endian) + 8-byte float64 (LE).
    Returns {uuid_string: value}.
    """
    result: dict[str, float] = {}
    offset = 0
    while offset + VALUE_STATE_ENTRY_SIZE <= len(data):
        uid = uuid_bytes_to_string(data[offset : offset + 16])
        value = struct.unpack_from("<d", data, offset + 16)[0]
        result[uid] = value
        offset += VALUE_STATE_ENTRY_SIZE
    return result


def parse_text_states(data: bytes) -> dict[str, str]:
    """Parse type 0x03 text states.

    Each entry: 16-byte UUID | 4-byte icon_uuid_padding | 4-byte text_length |
    text_length bytes text | padding to 4-byte alignment.
    """
    result: dict[str, str] = {}
    offset = 0
    while offset + 24 <= len(data):
        uid = uuid_bytes_to_string(data[offset : offset + 16])
        offset += 16
        # Skip icon UUID reference (4 bytes padding in some implementations)
        # Actually the format is: UUID(16) + UUID_icon(16) + text_length(4) + text + pad
        icon_uuid = data[offset : offset + 16]  # noqa: F841
        offset += 16
        if offset + 4 > len(data):
            break
        text_length = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if offset + text_length > len(data):
            break
        text = data[offset : offset + text_length].decode("utf-8", errors="replace")
        # Strip null terminator if present
        text = text.rstrip("\x00")
        result[uid] = text
        offset += text_length
        # Align to 4 bytes
        remainder = offset % 4
        if remainder:
            offset += 4 - remainder
    return result
