"""Data models for the Loxone API."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MiniserverInfo:
    """Information about the Loxone Miniserver."""

    serial_nr: str
    name: str
    project_name: str
    local_url: str
    remote_url: str


@dataclass
class MeterControl:
    """A Loxone Meter control (energy meter)."""

    uuid: str
    name: str
    room: str
    category: str
    meter_type: str  # "unidirectional" or "bidirectional"
    actual_format: str
    total_format: str
    # State UUIDs
    state_actual: str
    state_total: str
    state_total_neg: str | None = None  # Only for bidirectional

    @property
    def is_bidirectional(self) -> bool:
        return self.meter_type == "bidirectional"


@dataclass
class EFMNode:
    """A node in the EFM energy flow tree."""

    uuid: str
    node_type: str  # "Grid", "Load", "Group"
    title: str
    actual_efm_state: str | None = None
    ctrl_uuid: str | None = None
    children: list[EFMNode] = field(default_factory=list)


@dataclass
class EFMControl:
    """A Loxone Energy Flow Monitor control."""

    uuid: str
    name: str
    room: str
    category: str
    nodes: list[EFMNode] = field(default_factory=list)
    states: dict[str, str] = field(default_factory=dict)


@dataclass
class TextStateControl:
    """A Loxone TextState control (e.g. L1/L2/L3 amperage)."""

    uuid: str
    name: str
    room: str
    category: str
    state_text_and_icon: str


@dataclass
class StateUUIDMapping:
    """Maps a state UUID back to its parent control and field name."""

    control_uuid: str
    field_name: str
