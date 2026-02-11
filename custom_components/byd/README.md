# BYD Home Assistant Custom Component (draft)

This custom component ports the `client.js` login + realtime + GPS flow into Home Assistant using Python, backed by a local `pybyd` package in this repository.

## Implemented entities

- Sensor: battery percent
- Sensor: range (km)
- Device tracker: GPS lat/lon
- Lock: vehicle lock/unlock
- Cover: windows state (close command placeholder)
- Climate: on/off climate control
- Switch: heated seats (placeholder)
- Switch: charging toggle (placeholder)
- Siren: alarm (mapped to horn)
- Light: flash lights
- Binary sensors: bonnet, doors, windows, boot

## Config flow fields

- BYD username
- BYD password
- BYD country code
- Server URL suffix (e.g. `-eu`, `-au`)

Generated `base_url`: `https://dilinkappoversea{suffix}.byd.auto`.

## Important note

Some action endpoints/codes (windows-up, heated seats, smart-charge on/off) are exposed as entities but still require endpoint payload verification against additional app traces before command execution can be safely implemented.

## Local pybyd

A minimal `pybyd` package is included in the repo (`pybyd/`) and implements login, vehicle list, realtime, GPS and basic remote-control actions used by this integration.
