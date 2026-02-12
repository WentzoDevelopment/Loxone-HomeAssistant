<p align="center">
  <a href="https://github.com/WentzoDevelopment">
    <img src="https://github.com/WentzoDevelopment.png" 
         alt="Wentzo Logo" width="180" style="border-radius:50%">
  </a>
</p>

# Loxone Energy — Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

A custom Home Assistant integration that connects to a [Loxone](https://www.loxone.com/) Miniserver via WebSocket, automatically discovers all energy meters, and exposes them as realtime sensors — including full **Energy Dashboard** support.

## Features

- **Auto-discovery** — Automatically detects all Meter controls from the Miniserver's `LoxAPP3.json`
- **Realtime updates** — Push-based via WebSocket binary status updates (no polling)
- **Energy Dashboard ready** — Power (W) and Energy (kWh) sensors with correct `device_class` and `state_class`
- **Bidirectional meters** — Supports both consumption and return (feed-in) tracking
- **Automatic reconnect** — Exponential backoff reconnection on connection loss
- **Device hierarchy** — Each meter appears as a separate HA Device, grouped under the Miniserver

## Sensors

For each energy meter discovered on the Miniserver:

| Sensor | Unit | Device Class | Description |
|--------|------|--------------|-------------|
| Power | W | `power` | Current power (realtime) |
| Total | kWh | `energy` | Cumulative energy consumption |
| Total Return* | kWh | `energy` | Cumulative energy return (feed-in) |

*\* Only for bidirectional meters*

## Installation

### HACS (recommended)

1. Open **HACS** in Home Assistant
2. Click the three dots menu (top right) → **Custom repositories**
3. Add this repository URL and select **Integration** as the category
4. Click **Install**
5. Restart Home Assistant

### Manual

1. Copy the `custom_components/loxone_energy/` folder to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant

## Configuration

1. Go to **Settings** → **Devices & Services** → **Add Integration**
2. Search for **Loxone Energy**
3. Enter your Miniserver details:
   - **Host** — IP address or hostname of your Miniserver
   - **Port** — WebSocket port (default: 80)
   - **Username** — Loxone user with access rights
   - **Password** — Password for the user
4. The integration will connect, authenticate, and automatically create all sensor entities

## Energy Dashboard

The **Total** sensors (kWh, `total_increasing`) are directly compatible with the Home Assistant Energy Dashboard:

- Use the "pand Total" sensor (or your main meter) as **Grid consumption**
- Bidirectional meters with **Total Return** can be used as **Return to grid**
- Individual meter **Total** sensors can be tracked as **Individual devices**

## Requirements

This integration uses only libraries already bundled with Home Assistant (`aiohttp`, `cryptography`). No additional dependencies are required.

## Disclaimer

This integration is provided *as is* without any warranties or official support from Wentzo. It is not affiliated with or endorsed by Loxone Electronics GmbH.

For bugs and feature requests, please open a [GitHub Issue](https://github.com/WentzoDevelopment/Loxone-HomeAssistant/issues).

## License

This project is licensed under the [MIT License](LICENSE.md).
