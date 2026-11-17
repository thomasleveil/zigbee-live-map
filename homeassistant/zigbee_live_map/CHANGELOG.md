# Changelog

## 0.1.1

- Names your sniffed devices from Home Assistant's own device registry (ZHA), so the map shows the names you gave them. Works only inside Home Assistant; names you enter yourself still take precedence.
- Recovers the network key from a Touchlink (ZLL) commissioning join and reports it in the Security panel as its own verdict, naming the ZLL master-key transport rather than a default-link-key join.

## 0.1.0

First published version.

- The live map inside Home Assistant, behind its own sign-in (ingress), with a demo network to try it without a dongle.
- Reads a CC2531 USB dongle flashed with the TI packet sniffer firmware.
- Lists of known devices, saved network keys and an optional Hue Bridge link, kept in the app's data and its backups.
