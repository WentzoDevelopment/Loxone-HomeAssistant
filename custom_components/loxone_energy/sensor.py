"""Sensor entities for Loxone Energy meters."""

from __future__ import annotations

import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy, UnitOfPower
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import LoxoneEnergyCoordinator
from .loxone_api.models import MeterControl

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Loxone Energy sensors from a config entry."""
    coordinator: LoxoneEnergyCoordinator = hass.data[DOMAIN][entry.entry_id]
    structure = coordinator.structure
    if not structure:
        return

    entities: list[SensorEntity] = []
    serial = structure.miniserver_info.serial_nr if structure.miniserver_info else "unknown"

    for meter in structure.meters.values():
        # Power sensor (actual × 1000 → W)
        entities.append(
            LoxonePowerSensor(coordinator, meter, serial)
        )
        # Energy total sensor (kWh)
        entities.append(
            LoxoneEnergySensor(coordinator, meter, serial, negative=False)
        )
        # Energy return sensor (kWh) — only for bidirectional meters
        if meter.is_bidirectional and meter.state_total_neg:
            entities.append(
                LoxoneEnergySensor(coordinator, meter, serial, negative=True)
            )

    _LOGGER.info("Adding %d Loxone Energy sensor entities", len(entities))
    async_add_entities(entities)


class LoxoneMeterEntity(CoordinatorEntity[LoxoneEnergyCoordinator], SensorEntity):
    """Base class for Loxone meter sensor entities."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: LoxoneEnergyCoordinator,
        meter: MeterControl,
        serial: str,
    ) -> None:
        super().__init__(coordinator)
        self._meter = meter
        self._serial = serial

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._meter.uuid)},
            name=self._meter.name,
            manufacturer="Loxone",
            model="Energy Meter",
            suggested_area=self._meter.room if self._meter.room else None,
            via_device=(DOMAIN, self._serial),
        )


class LoxonePowerSensor(LoxoneMeterEntity):
    """Current power consumption/production in Watts."""

    _attr_device_class = SensorDeviceClass.POWER
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfPower.WATT

    def __init__(
        self,
        coordinator: LoxoneEnergyCoordinator,
        meter: MeterControl,
        serial: str,
    ) -> None:
        super().__init__(coordinator, meter, serial)
        self._attr_unique_id = f"{meter.uuid}_power"
        self._attr_name = "Power"

    @callback
    def _handle_coordinator_update(self) -> None:
        value = self.coordinator.get_value(self._meter.state_actual)
        if value is not None:
            # Loxone reports kW, convert to W
            self._attr_native_value = round(value * 1000, 1)
        self.async_write_ha_state()

    @property
    def native_value(self) -> float | None:
        value = self.coordinator.get_value(self._meter.state_actual)
        if value is not None:
            return round(value * 1000, 1)
        return None


class LoxoneEnergySensor(LoxoneMeterEntity):
    """Cumulative energy consumption/return in kWh."""

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

    def __init__(
        self,
        coordinator: LoxoneEnergyCoordinator,
        meter: MeterControl,
        serial: str,
        *,
        negative: bool = False,
    ) -> None:
        super().__init__(coordinator, meter, serial)
        self._negative = negative
        if negative:
            self._state_uuid = meter.state_total_neg or ""
            self._attr_unique_id = f"{meter.uuid}_total_return"
            self._attr_name = "Total Return"
        else:
            self._state_uuid = meter.state_total
            self._attr_unique_id = f"{meter.uuid}_total"
            self._attr_name = "Total"

    @callback
    def _handle_coordinator_update(self) -> None:
        value = self.coordinator.get_value(self._state_uuid)
        if value is not None:
            self._attr_native_value = round(value, 3)
        self.async_write_ha_state()

    @property
    def native_value(self) -> float | None:
        value = self.coordinator.get_value(self._state_uuid)
        if value is not None:
            return round(value, 3)
        return None
