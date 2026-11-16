# TODO

This tool is a **Zigbee network diagnostic tool** meant to run on a home-automation LAN
(e.g. deployed as a Home Assistant add-on), not a public, passive-only sniffer. Passive
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

- Package as a Home Assistant add-on: container + `config.yaml` manifest, and USB sniffer
  dongle passthrough. (Add-on specifics to verify at build time.)
- Native TLS is not built: on a LAN the tool speaks plain HTTP; a TLS-terminating reverse proxy plus `--allowed-host` is the way to protect it on a network you do not trust.

## Active probing (parked)

- Sending a frame to a device (ping, active role discovery) needs a **transmitting** radio;
  the CC2531 in sniffer firmware only receives. Hub reachability (above) covers most of this
  need for controller-managed devices.
