# zigbee-live-map

Watch your Zigbee network talk, live, in your browser.

A cheap USB sniffer dongle listens to the radio. Every frame becomes an animation on a map of your devices and a plain-language line in a log, so you can see who talks to whom, which router relays what, where a link is struggling, and how the mesh actually works.

![The live map on the built-in demo network](docs/screenshot.png)

## What you see

- **A living map.** The coordinator, routers and battery devices appear as they are heard, and arrange themselves. Drag nodes around, click one to focus on it.
- **One animation per frame.** A dot runs along the link for a message sent to one device, and you watch relays chain hop after hop. A broadcast is a ring that spreads from router to router.
- **A log that explains itself.** Each frame gets a colour-coded category and a sentence: *"Hallway motion wakes up and asks its parent Living room plug whether a message is waiting."*
- **The rhythm of the protocol.** A two-minute strip per category shows the patterns, such as every router announcing its links every 15 seconds.
- **Things to look at.** Links where frames keep being sent again, routers that are slow to relay or do not relay, messages never collected by a sleeping device. See [Diagnostics](#diagnostics).
- **A device sheet.** Role, chip maker, parent, children, retransmissions, relay delay, signal strength at the sniffer, and whether the router's beacons say it accepts children.
- **An optional watch on one device.** Nothing is singled out by default. Click "Watch this device" on a router and the header keeps count of its children, what it relays and what it repeats.
- English and French, light and dark themes, keyboard accessible.

## Try it in one minute, without hardware

From a clone of this repository:

```sh
uv run zigbee-live-map --demo --open
```

This runs a simulated network of twelve devices with realistic traffic, including one weak link and one slow router so the diagnostics have something to show. No dongle needed.

## Use it on your network

### Hardware

A **CC2531 USB dongle flashed with the TI packet sniffer firmware** (USB id `0451:16ae`). A CC2531 running coordinator firmware, the one Zigbee2MQTT or ZHA use, will not work: it has to be the sniffer firmware.

You also need libusb:

| System | Command |
|---|---|
| macOS | `brew install libusb` |
| Debian, Ubuntu | `sudo apt install libusb-1.0-0` |

On Linux, give your user access to the dongle with a udev rule, for example in `/etc/udev/rules.d/99-cc2531-sniffer.rules`:

```
SUBSYSTEM=="usb", ATTR{idVendor}=="0451", ATTR{idProduct}=="16ae", MODE="0660", GROUP="plugdev"
```

### Install

```sh
uv tool install .        # or: pipx install .
```

### Find your channel, then watch

```sh
zigbee-live-map --scan           # listens 2 s on each of the 16 channels
zigbee-live-map --channel 15 --open
```

```
channel  frames  best RSSI  PAN ids (frames)
     15      11    -50 dBm  0x1a62 (6)
     20       9    -71 dBm  0x7b21 (5)
```

Your hub also shows the channel in its settings. You can change channel from the page at any time: the map starts over on the new one.

## Device names

Zigbee devices do not know that they are called "Kitchen plug". That name exists only in your hub's database and is never transmitted, so a sniffer cannot discover it. What travels in clear is the short address and the factory IEEE address of each device.

Names therefore come from you. They are kept in **lists of known devices**, on your computer only (`~/.zigbee-live-map/lists/`, never in this repository). You can keep several lists, for instance one per place, and switch each one on or off; the map uses every list that is on.

- **Rename on the map**: click a device, type a name, save.
- **Manage lists** on the *Known devices* page: create, rename and delete lists, edit devices, name the devices the sniffer has heard, import and export.
- **Name devices from what they say about themselves**: once the network key is known (see *Settings*), the sniffer reads each device's model from its decrypted traffic. On the *Known devices* page, the button under *Heard on the air, not named yet* adds every such device that no list has yet to the list shown, named after its model, and puts the model in the Model column. It never touches a device that already has an entry, in any list, and it says why when there is nothing to add. Two devices of the same model get the last bytes of their IEEE address appended ("Smart plug 5956"), so they can be told apart and keep that name. This is most useful right after a device re-pairs, since devices rarely announce their model unprompted: it only works for devices heard announcing it since the tool started. Rename them afterwards to what they do.
- **Import a list from your hub**: export or copy your device table to a CSV or tab-separated file with a header row, on the page or from the command line:

  ```sh
  zigbee-live-map --import-devices devices.csv --list Home
  ```

  It needs an IEEE column and a name column. Model and short-address (`nwk`) columns are used when present. See [`examples/devices.example.csv`](examples/devices.example.csv).

Lists export as JSON (to move them to another computer) or CSV.

### Chip maker

The first bytes of an IEEE address are a prefix that the IEEE assigns to a company, so the tool can name who made the radio chip of every device it hears. That is the chip or module maker, often not the brand on the box: sensors from different brands frequently share one chip vendor. The product model is announced inside the encrypted part of the traffic, which this tool does not read; if your hub export has a model column, it is imported with the names.

A snapshot of the [IEEE registry](https://standards-oui.ieee.org/) ships with the tool. Update it from *Settings*, or with `zigbee-live-map --update-vendors`. This downloads three public files and sends nothing about your network. It never happens on its own.

## Diagnostics

The devices keep their own measurements to themselves: link quality figures and queue states travel encrypted or not at all. What a listener can see is the consequences, and those are what the *Things to look at* panel reports.

| Sign | How it is seen | What it suggests |
|---|---|---|
| Retransmissions on a link | the very same frame sent again, because no acknowledgement came back | a poor radio link between these two devices |
| Slow relay | time between a router receiving a frame for someone else and sending it on | a busy or struggling router |
| Frame not seen relayed | a router received a frame to pass on, and never did | a router dropping traffic, or one the sniffer hears badly |
| Message never collected | a parent held a message for a sleeping child that did not come for it in time | a battery device with a weak link to its parent |
| Shared channel | frames from another network on the same channel | less air time for your network |

On the map, a link with many retransmissions is drawn in the warning colour with its percentage, and it is **stretched**: devices that hear each other badly drift apart. This gives a feel for which links are weak. It is not a floor plan: only pairs that exchange traffic are measured, and on a healthy network every link looks the same.

These are indicators, not measurements. A frame the sniffer missed looks exactly like a frame that was never sent, so place the dongle where it hears the devices you are investigating, and treat a warning as a place to look.

## Reference

```
zigbee-live-map [--channel N | --demo | --replay PCAP] [options]

  --channel N            Zigbee channel, 11 to 26
  --demo                 simulated network, no hardware needed
  --replay PCAP          replay a capture (pcap, linktype 802.15.4) with its timing
  --speed X              speed factor for --replay and --demo
  --pcap OUT             also record the live capture, readable by Wireshark
  --scan [SECONDS]       listen on each channel, print what is there, exit
  --import-devices FILE  merge a device list into a list of known devices, exit
  --list NAME            list used by --import-devices (default "My devices")
  --update-vendors       download the current IEEE registry of chip makers, exit
  --data-dir DIR         where your lists and registry updates are kept (default ~/.zigbee-live-map)
  --focus IEEE           start with this device watched (same as the Watch button)
  --port N               local port (default 8765)
  --open                 open the page in your browser
```

Language, theme and animations are set from *Settings* in the page and remembered by your browser. Language and theme default to automatic: your browser's language when a translation exists, English otherwise, and your system's light or dark setting.

## How it works

```
CC2531 sniffer ──USB──▶ sniffer.py ──frames──▶ frames.py ──events──▶ server.py ──WebSocket──▶ page
  (receive only)        (libusb)             (header decoding)       (127.0.0.1)          (canvas)
```

Two layers of a Zigbee frame are readable by anyone in radio range, and this is all the tool uses:

- the **MAC header** (IEEE 802.15.4): which device transmits this radio hop, and to whom;
- the **NWK header** (Zigbee): who wrote the message, who it is finally for, how many hops are left, a sequence number, and the IEEE address of the device that secured this hop.

Comparing the two is what reveals routing: when the radio sender is not the author, a router is relaying. Parent-child links come from data requests, since a sleeping device only ever polls its parent. The sequence number lets one message be followed from hop to hop, which is how relay delays are measured.

The header decoder has no dependency beyond the standard library. Its output was compared field by field with Wireshark's dissector (`tshark`) on a real capture and on the demo traffic.

## Scope and privacy

- **Receive only.** The sniffer firmware cannot transmit, and this tool never sends anything on the radio.
- **Headers only.** Everything after the NWK header is encrypted with your network key. The tool does not ask for the key and does not decrypt. It shows who talks to whom, when and how much, never what is said. Network commands are recognised by their shape and labelled "probable" when that is a deduction.
- **Local only.** The server listens on `127.0.0.1` and answers only requests addressed to that local address. It grants no cross-origin access, so another website cannot read anything through your browser, and it refuses any change or live connection that does not carry a token only its own page can obtain. The only outbound connection is the registry update, and only when you ask for it.
- **Your data stays out of the repository.** Device lists live in your home directory, and `*.pcap` is in `.gitignore`. A capture contains your devices' addresses: think before sharing one.
- Traffic of a neighbouring network on the same channel is recognised by its PAN id and kept off the map. Use this on networks you own or are allowed to monitor.

## Limits

- The dongle only hears what reaches it. A far-away device may be missing, and a missing frame is not proof that it was not sent.
- Signal strength (dBm) is what the sniffer received, not the link quality between two devices.
- One sniffer model is supported for now. `sniffer.py` is small and isolated: other 802.15.4 sniffers can be added there.
- Zigbee PRO only. Green Power frames and other 802.15.4 protocols show up as "not decoded".

## Translating

Every text of the pages lives in one JSON file per language, in [`src/zigbee_live_map/static/locales/`](src/zigbee_live_map/static/locales/). English (`en.json`) is the reference and the fallback for any missing text.

To add a language:

1. Copy `en.json` to `<code>.json`, where the code is the language tag browsers use (`de`, `es`, `pt-BR`…).
2. Set `"_name"` to the name of the language in that language, and translate the values. Keep the keys and the `{placeholders}` as they are.
3. Run `uv run pytest tests/test_locales.py`: it reports unknown keys and placeholders that do not match.

The language then appears in *Settings* by itself. A partial translation works: missing texts show in English. `**bold**` and `*italic*` are the only formatting, and nothing in a translation is ever treated as HTML.

## Development

```sh
uv run pytest
uv run zigbee-live-map --demo --speed 3
```

The pages have no build step: `static/index.html` is the map, `static/devices.html` the device lists, `static/common.js` and `static/common.css` what they share. The demo network in `demo.py` produces well-formed frames, so the whole pipeline can be exercised without a dongle.

To refresh the registry snapshot shipped with the package:

```sh
uv run python -m zigbee_live_map.vendors src/zigbee_live_map/data/vendors.tsv.gz
```

## License

MIT. The chip maker registry is public data published by the IEEE Registration Authority.
