# TODO

This tool is a **Zigbee network diagnostic tool** meant to run on a home-automation LAN
(e.g. deployed as a Home Assistant add-on), not a public, passive-only sniffer. Passive
sniffing is one data source among several.

## Controller / hub integration

- **Hue Bridge**: discover it on the LAN via mDNS (`_hue._tcp.local.`), then create an
  application key through the CLIP REST API using the physical link-button flow. Store the
  key locally like network keys (own file, `0600`). Use it to enrich the map with
  authoritative device names, models, types and rooms, per-device **reachability**, and the
  bridge's own link-quality (LQI) figures.
  _Verified 2026-11-15: the bridge answers the mDNS browse (`Hue Bridge - 0A0B0C`)._
- Later: the same enrichment from other controllers (Home Assistant, deCONZ, zigbee2mqtt…).
- Use hub reachability as the "is it alive / what is it" answer for integrated devices,
  which removes the need to transmit for those.

## LAN / Home Assistant deployment (`127.0.0.1` is too restrictive)

- Configurable bind host (`--host`, default `127.0.0.1`, `0.0.0.0` for an add-on).
- Replace the localhost-only guard: today the whole protection is "Host is `127.0.0.1`/
  `localhost` + session token + no CORS". On a LAN IP/hostname that Host check breaks, so it
  must become an expected-hosts allowlist, not a hardcoded localhost check.
- Real authentication once exposed on the LAN:
  - **Home Assistant ingress** when run as an add-on (HA authenticates and proxies — no
    password to manage), and
  - a configurable access token/password for standalone LAN use.
- Package as a Home Assistant add-on: container + `config.yaml` manifest, and USB sniffer
  dongle passthrough. (Add-on specifics to verify at build time.)

## Map / diagnostics

- Button to fill a known-devices list from decrypted identity (most useful right after a
  device re-pairs, since devices rarely announce their model unprompted).

## Active probing (parked)

- Sending a frame to a device (ping, active role discovery) needs a **transmitting** radio;
  the CC2531 in sniffer firmware only receives. Hub reachability (above) covers most of this
  need for controller-managed devices.
