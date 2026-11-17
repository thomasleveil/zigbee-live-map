# TODO

This tool is a **Zigbee network diagnostic tool** meant to run on a home-automation LAN
(e.g. deployed as a Home Assistant app), not a public, passive-only sniffer. Passive
sniffing is one data source among several.

## Controller / hub integration

- Later: the same enrichment from other controllers (Home Assistant, deCONZ, zigbee2mqtt…).
- Use hub reachability as the "is it alive / what is it" answer for integrated devices,
  which removes the need to transmit for those (done for Hue, in the map and the issues panel;
  other controllers to follow).
- The Hue API exposes **no link quality** (no LQI, no RSSI, in CLIP v1 or v2): the bridge
  gives reachability only (`zigbee_connectivity.status`), so the map's link figures stay
  sniffer-derived.

## LAN / Home Assistant deployment

- The Home Assistant app is packaged (`homeassistant/`); what remains:
  - Test it on a real Supervisor, with the CC2531 plugged in: does `usb: true` alone let pyusb open
    `0451:16ae` (or is `udev: true`, a custom AppArmor profile or a privileged capability needed)?
  - Install it from the repository address on a real Home Assistant machine (the image is built by
    `.github/workflows/build-app.yaml`; nobody has installed the app that way yet).
  - An icon and a logo for the app card (`icon.png`, `logo.png` in the app folder).
- Native TLS is not built: on a LAN the tool speaks plain HTTP. On a network you do not trust, put a
  TLS-terminating reverse proxy in front of a loopback bind, with a password and `--allowed-host` (see README).

## Active probing (parked)

- Sending a frame to a device (ping, active role discovery) needs a **transmitting** radio;
  the CC2531 in sniffer firmware only receives. Hub reachability (above) covers most of this
  need for controller-managed devices.
