"""Parse LoxAPP3.json into typed control objects."""

from __future__ import annotations

import logging
import uuid as uuid_mod
from typing import Any

from .models import (
    EFMControl,
    EFMNode,
    MeterControl,
    MiniserverInfo,
    StateUUIDMapping,
    TextStateControl,
)

_LOGGER = logging.getLogger(__name__)


def normalize_uuid(lox_uuid: str) -> str:
    """Normalize a Loxone UUID (8-4-4-16 format) to standard UUID (8-4-4-4-12).

    Loxone uses e.g. '1fc30d63-0365-75a3-04ffcf48104d49ed'
    Standard UUID:     '1fc30d63-0365-75a3-04ff-cf48104d49ed'
    """
    # Strip dashes and reformat as standard UUID
    hex_str = lox_uuid.replace("-", "")
    if len(hex_str) != 32:
        return lox_uuid  # Not a valid UUID, return as-is
    return str(uuid_mod.UUID(hex_str))


class StructureParser:
    """Parses a LoxAPP3.json dict into control dataclasses."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        self.miniserver_info: MiniserverInfo | None = None
        self.meters: dict[str, MeterControl] = {}
        self.efm_controls: dict[str, EFMControl] = {}
        self.text_states: dict[str, TextStateControl] = {}
        self.state_to_control: dict[str, StateUUIDMapping] = {}
        self._rooms: dict[str, str] = {}
        self._cats: dict[str, str] = {}
        self._parse()

    def _parse(self) -> None:
        self._parse_miniserver_info()
        self._build_lookups()
        self._parse_controls()

    def _parse_miniserver_info(self) -> None:
        ms = self._data.get("msInfo", {})
        self.miniserver_info = MiniserverInfo(
            serial_nr=ms.get("serialNr", ""),
            name=ms.get("msName", ""),
            project_name=ms.get("projectName", ""),
            local_url=ms.get("localUrl", ""),
            remote_url=ms.get("remoteUrl", ""),
        )

    def _build_lookups(self) -> None:
        for uuid, room in self._data.get("rooms", {}).items():
            self._rooms[uuid] = room.get("name", uuid)
        for uuid, cat in self._data.get("cats", {}).items():
            self._cats[uuid] = cat.get("name", uuid)

    def _room_name(self, uuid: str) -> str:
        return self._rooms.get(uuid, "")

    def _cat_name(self, uuid: str) -> str:
        return self._cats.get(uuid, "")

    def _parse_controls(self) -> None:
        controls = self._data.get("controls", {})
        for ctrl_uuid, ctrl in controls.items():
            ctrl_type = ctrl.get("type", "")
            if ctrl_type == "Meter":
                self._parse_meter(ctrl_uuid, ctrl)
            elif ctrl_type == "EFM":
                self._parse_efm(ctrl_uuid, ctrl)
            elif ctrl_type == "TextState":
                self._parse_text_state(ctrl_uuid, ctrl)

    def _parse_meter(self, ctrl_uuid: str, ctrl: dict[str, Any]) -> None:
        details = ctrl.get("details", {})
        states = ctrl.get("states", {})
        meter_type = details.get("type", "unidirectional")

        state_actual = normalize_uuid(states["actual"]) if "actual" in states else ""
        state_total = normalize_uuid(states["total"]) if "total" in states else ""
        state_total_neg = normalize_uuid(states["totalNeg"]) if "totalNeg" in states else None

        meter = MeterControl(
            uuid=ctrl_uuid,
            name=ctrl.get("name", ""),
            room=self._room_name(ctrl.get("room", "")),
            category=self._cat_name(ctrl.get("cat", "")),
            meter_type=meter_type,
            actual_format=details.get("actualFormat", "%.3fkW"),
            total_format=details.get("totalFormat", "%.1fkWh"),
            state_actual=state_actual,
            state_total=state_total,
            state_total_neg=state_total_neg,
        )
        self.meters[ctrl_uuid] = meter

        # Build reverse mapping for the states we care about
        for field_name, norm_uuid in [
            ("actual", state_actual),
            ("total", state_total),
            ("totalNeg", state_total_neg),
        ]:
            if norm_uuid:
                self.state_to_control[norm_uuid] = StateUUIDMapping(
                    control_uuid=ctrl_uuid, field_name=field_name
                )

        _LOGGER.debug(
            "Parsed meter %s (%s, %s)", meter.name, meter.meter_type, ctrl_uuid
        )

    def _parse_efm_node(self, node_data: dict[str, Any]) -> EFMNode:
        children = [
            self._parse_efm_node(child)
            for child in node_data.get("nodes", [])
        ]
        return EFMNode(
            uuid=node_data.get("uuid", ""),
            node_type=node_data.get("nodeType", ""),
            title=node_data.get("title", ""),
            actual_efm_state=node_data.get("actualEfmState"),
            ctrl_uuid=node_data.get("ctrlUuid"),
            children=children,
        )

    def _parse_efm(self, ctrl_uuid: str, ctrl: dict[str, Any]) -> None:
        details = ctrl.get("details", {})
        nodes_data = details.get("nodes", [])
        nodes = [self._parse_efm_node(n) for n in nodes_data]

        efm = EFMControl(
            uuid=ctrl_uuid,
            name=ctrl.get("name", ""),
            room=self._room_name(ctrl.get("room", "")),
            category=self._cat_name(ctrl.get("cat", "")),
            nodes=nodes,
            states=ctrl.get("states", {}),
        )
        self.efm_controls[ctrl_uuid] = efm
        _LOGGER.debug("Parsed EFM %s (%s)", efm.name, ctrl_uuid)

    def _parse_text_state(self, ctrl_uuid: str, ctrl: dict[str, Any]) -> None:
        states = ctrl.get("states", {})
        raw_text_uuid = states.get("textAndIcon", "")
        norm_text_uuid = normalize_uuid(raw_text_uuid) if raw_text_uuid else ""

        ts = TextStateControl(
            uuid=ctrl_uuid,
            name=ctrl.get("name", ""),
            room=self._room_name(ctrl.get("room", "")),
            category=self._cat_name(ctrl.get("cat", "")),
            state_text_and_icon=norm_text_uuid,
        )
        self.text_states[ctrl_uuid] = ts

        if norm_text_uuid:
            self.state_to_control[norm_text_uuid] = StateUUIDMapping(
                control_uuid=ctrl_uuid, field_name="textAndIcon"
            )
        _LOGGER.debug("Parsed TextState %s (%s)", ts.name, ctrl_uuid)
