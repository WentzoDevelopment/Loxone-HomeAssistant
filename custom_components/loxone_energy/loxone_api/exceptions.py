"""Custom exceptions for the Loxone API."""


class LoxoneError(Exception):
    """Base exception for Loxone errors."""


class LoxoneAuthError(LoxoneError):
    """Authentication failed."""


class LoxoneConnectionError(LoxoneError):
    """Connection to Miniserver failed."""


class LoxoneProtocolError(LoxoneError):
    """Unexpected data in the Loxone binary protocol."""
