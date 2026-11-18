# Changelog

## 0.2.0

With the network key, the tool now reads much more of what your network says about itself:

- Opens any log line as the frame itself, layer by layer, as a protocol analyser would show it: the radio and network headers, and with the key the network command or the application layers with their attribute values.
- Names every network command instead of guessing it from the frame's shape, and reports the delivery failures routers announce and the devices that keep rejoining.
- Reads routers' neighbour tables, so a battery device poorly heard by its parent shows up, and follows messages end to end: acknowledgements, and requests paired with their answers.
- Shows on a device's sheet what the rest of the mesh says about it: how its neighbours hear it, the link costs other routers measure to it, the failures reported about it.
- Shows what a Philips Hue bridge asks of its lights (on or off, brightness, colour, effect, a strip's gradient) in the frame detail.
- Recognises empty replies, inter-PAN (Touchlink) and Green Power frames instead of calling them "not decoded".

Fixes:

- A temperature below zero, or any other negative value, is no longer shown as a large positive number in the frame detail.
- A link whose cost has not been measured yet says so, instead of "0/7".
- Changing channel forgets the previous network completely, its Touchlink verdict included.
- A map page left open while the app is updated reloads itself.

## 0.1.1

- Names your sniffed devices from Home Assistant's own device registry (ZHA), so the map shows the names you gave them. Works only inside Home Assistant; names you enter yourself still take precedence.
- Recovers the network key from a Touchlink (ZLL) commissioning join and reports it in the Security panel as its own verdict, naming the ZLL master-key transport rather than a default-link-key join.

## 0.1.0

First published version.

- The live map inside Home Assistant, behind its own sign-in (ingress), with a demo network to try it without a dongle.
- Reads a CC2531 USB dongle flashed with the TI packet sniffer firmware.
- Lists of known devices, saved network keys and an optional Hue Bridge link, kept in the app's data and its backups.
