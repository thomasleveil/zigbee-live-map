# zigbee-live-map

Watch your Zigbee network talk, live, in your browser.

[![Open your Home Assistant instance and show the add app repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fthomasleveil%2Fzigbee-live-map)

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
- **More with your network key.** Enter your network's key in *Settings* to understand the network in more detail: each network command is named with what it says (a route reply and its path cost, a router reporting a delivery it could not make, a device rejoining), routers' own link costs appear, and devices tell their model and battery level. See [With the network key](#with-the-network-key).
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

When the dongle cannot be read, the map page says why (no dongle found, libusb missing, the radio did not start, or the device cannot be opened) and lists these requirements. It keeps looking every two seconds, so plugging the dongle in is enough: nothing has to be restarted.

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

## Running it on your LAN

By default the page answers on `127.0.0.1`, this computer only. To reach it from a phone, a tablet or another computer, or to run it as a Home Assistant app, the same server can listen elsewhere. Its pages carry secrets (your network keys, live radio traffic), so the way you expose it matters. There are three situations. One rule decides between them: **a password means sign-in, on every bind, loopback included**; only a loopback bind with no password skips the sign-in.

**1. This computer only (the default, with no password).** Nothing to set up. Only a program on this computer can connect, a request must be addressed to `127.0.0.1` or `localhost`, and a web site you visit cannot use your browser to read or change anything (no cross-origin permission is ever given, and every change and the live connection carry a token only the tool's own page can read). This protects you from the web, not from another user of this computer.

**2. Your LAN, with a password.** Listen on an address your network can reach and set a password (the same password also protects a loopback bind, see the reverse proxy below). The password never goes on the command line, where any user could read it in the process list: it comes from the `ZLM_PASSWORD` environment variable, or from the first line of a file.

```sh
ZLM_PASSWORD='a long phrase you invented' zigbee-live-map --host 0.0.0.0 --channel 15
# or
zigbee-live-map --host 0.0.0.0 --channel 15 --password-file ~/.zigbee-live-map-password
```

`--host 0.0.0.0` listens on every network interface; give one address instead (`--host 192.168.1.20`) to listen on that one only. A non-loopback bind without a password (or `--ingress`) refuses to start, so it cannot be left open by mistake, and an empty password is refused. Every page, every call and the live connection then require signing in, except the login page, the static files and the translations. A browser signs in once and receives a random session cookie (HttpOnly, SameSite=Strict), kept in memory on the server. Its name carries the port the tool listens on (`zlm_session_8765`), which keeps two instances on one machine from overwriting each other's cookie; a browser still sends it to every other port of the same host name. A session is also tied to the address that signed in, so a copied cookie is refused from another address: that helps on a direct LAN bind, and does nothing behind a reverse proxy, where every visitor has the proxy's address. On a host name shared with services you do not trust, or behind a proxy, the protection is the cookie staying secret (HttpOnly, and Secure behind TLS). Restarting the tool signs everybody out. *Sign out* in *Settings* ends the session: its token stops working and its open live connections are closed. A session also ends after 7 days without use, or when a 65th one is opened (the least recently used goes), and its live connections are closed with it; a page left open counts as use, so it does not expire under itself. Wrong passwords are slowed down: after three misses in a row from one address, each further miss doubles the wait, up to a minute, and a wait is refused without even looking at the password; one counter over all addresses covers an attacker with many. The tool also checks that each request is addressed to the address it was reached at, which stops DNS rebinding; to reach it by a name (`zigbee.home.example`), say so with `--allowed-host zigbee.home.example` (repeatable, with or without `:port`).

**LAN traffic is plain HTTP.** The password, the session cookie, the network keys and the live traffic cross your network unencrypted: anyone who can see the traffic of your network (someone on the same Wi-Fi, a compromised device) can read them and take over the session. That is acceptable on a home network you trust. On a network you do not trust, put a reverse proxy that terminates TLS in front of the tool, and keep the tool itself on a loopback address (or a private interface). **Set a password in that set-up too**: the proxy connects from loopback, so without a password nobody would be asked to sign in and anyone who reaches the proxy would be served the keys. Native TLS is not built.

```sh
ZLM_PASSWORD='a long phrase you invented' zigbee-live-map --host 127.0.0.1 --channel 15 --allowed-host zigbee.home.example
```

`--allowed-host` is the name your browser types. It is needed in both proxy styles, and it needs the password (without one the tool refuses to start): a browser sends that name as the `Origin` of the sign-in and of every change, and the tool only accepts an `Origin` it knows. Whether the proxy rewrites the `Host` it forwards to the tool's own address (`127.0.0.1:8765`) or forwards the browser's `Host` as it came, the same command works. Have the proxy send `X-Forwarded-Proto: https` so that the session cookie is marked Secure. Both styles are tested end to end through [`tests/prefix_proxy.py`](tests/prefix_proxy.py) (`tests/test_access.py`, `test_password_a_tls_proxy_in_front_of_a_loopback_bind_is_authenticated`): without the cookie nothing is served, after signing in everything works.

**A known limit.** Someone already on your network can keep you from signing in by failing sign-ins on purpose: the wait that slows wrong passwords is shared, so a stream of wrong guesses keeps everyone waiting. They cannot get in that way, and people already signed in are not affected.

**3. Behind Home Assistant ingress.** As an app, Home Assistant signs the user in and proxies the page; the tool asks for no password. Start it with `--ingress` and `--host 0.0.0.0`: it then accepts Home Assistant's supervisor (`172.30.32.2`, the only address ingress connects from; it is a constant, nothing changes it) without a login, and answers every other peer as in situation 2. With `--ingress` and no password, every other peer is refused outright. **`--ingress` is not for use outside Home Assistant**: the address `172.30.32.2` is in a range that Docker networks and VPNs commonly use too, so the tool refuses to start with `--ingress` unless the environment carries a non-empty `SUPERVISOR_TOKEN`, the variable Home Assistant sets in every app container. Anywhere else, use a password. The tool never trusts a header such as `X-Ingress-Path` or `X-Forwarded-For`: a request is "from the supervisor" only if the connection itself is. Home Assistant shows the page in a frame, so the ingress pages can be framed; in the other two situations they cannot be framed by another site. The pages use relative URLs only, so they work under the path prefix ingress adds. The app packaging is described in [Home Assistant](#home-assistant).

## Home Assistant

The tool is packaged as a Home Assistant **app** (what used to be called an add-on) in [`homeassistant/zigbee_live_map/`](homeassistant/zigbee_live_map/). It gives you:

- the map inside Home Assistant, in its own sidebar entry, behind Home Assistant's own sign-in (ingress): no password to set, no port opened;
- the dongle passed to the app, and your lists of known devices and saved keys kept in the app's own data, included in Home Assistant backups;
- a demo switch, to look at the app before you have a dongle.

**Install it.** Add this repository to your Home Assistant, then install the app from it:

[![Open your Home Assistant instance and show the add app repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fthomasleveil%2Fzigbee-live-map)

The button opens your Home Assistant with the address filled in. By hand, it is three steps:

1. Open *Settings*, *Apps*, and select *Install app*.
2. In the top-right menu, select *Repositories*, paste `https://github.com/thomasleveil/zigbee-live-map` and select *Add*.
3. Select *Zigbee Live Map* in the list and install it.

Then set your Zigbee channel on the app's *Configuration* tab (or turn the demo on), start the app, and use *Open Web UI*. Home Assistant downloads a ready-made image, `ghcr.io/thomasleveil/zigbee-live-map`, for `amd64` and `aarch64` machines: nothing is built on yours.

**Build it on your Home Assistant machine instead**, to try a change before it is published. The Supervisor builds an app from its folder alone, so the tool has to arrive in it as a wheel, and `image` has to go, or the published image is pulled instead. From a clone of this repository:

```sh
uv build --wheel --out-dir dist/
cp dist/zigbee_live_map-*.whl homeassistant/zigbee_live_map/
```

Comment out the `image:` line of `homeassistant/zigbee_live_map/config.yaml`, then copy the folder `homeassistant/zigbee_live_map` (with the wheel inside) into the `local_apps` folder of your Home Assistant, with the Samba share or the *Terminal & SSH* app. Open *Settings*, *Apps*, *Install app*, run *Check for updates*, and install *Zigbee Live Map* from the *Local apps* section. After a change, use *Rebuild* on the app page, or `ha apps rebuild --force local_zigbee_live_map`.

**How a version gets published.** [`.github/workflows/build-app.yaml`](.github/workflows/build-app.yaml) builds the image for both architectures on every push to `main`, with Home Assistant's [builder actions](https://github.com/home-assistant/builder), and publishes it under the tag equal to `version` in `config.yaml`. A tag that exists is never pushed again, so a change reaches people only when the version is raised:

1. Raise `version` in `pyproject.toml` and in `homeassistant/zigbee_live_map/config.yaml` (a test keeps them equal), and add the version to the app's `CHANGELOG.md`.
2. Push to `main`. Until the build ends, Home Assistant offers an update that it cannot download yet.

Home Assistant pulls `ghcr.io/thomasleveil/zigbee-live-map` without signing in, so that package has to be public. Here the packages were public as soon as the workflow of this public repository created them; if Home Assistant cannot download the image, the package's visibility, in its settings on GitHub, is the first thing to check. The very first publication failed at its last step (the registry answered 403) and passed when that job was run again; the cause was not established.

**Options**, on the app's *Configuration* tab:

| Option | Meaning |
|---|---|
| Zigbee channel | 11 to 26 (default 11); ignored in demo mode |
| Demo network | simulated network, no dongle (default off) |
| Password | only for a published port, see below |
| Allowed host names | only for a published port: the names or addresses your browser types, with `:port` if it is not 8099 |

The port is not published by default. To reach the page from outside Home Assistant, enable port 8099 in the app's *Network* section and set a password and allowed host names; that is situation 2 of [Running it on your LAN](#running-it-on-your-lan), plain HTTP included.

**Try it without Home Assistant.** [`homeassistant/try-locally.sh`](homeassistant/try-locally.sh) needs Docker and `uv`. It builds the wheel and the image, creates a Docker network on Home Assistant's internal subnet (`172.30.32.0/23`), starts the app on it with a mounted data directory, and starts a small nginx at `172.30.32.2` (the Supervisor's address) that serves the app under a path prefix like ingress does, HTTP and WebSocket, without a login. The app container gets a dummy `SUPERVISOR_TOKEN`: that variable is how `--ingress` knows a Supervisor started it, and the script says on purpose that its value is not checked. It publishes one port on `127.0.0.1` and prints the URL:

```sh
homeassistant/try-locally.sh          # demo network, http://127.0.0.1:8798/api/hassio_ingress/local/
ZLM_TRY_DEMO=false homeassistant/try-locally.sh   # the real mode with no dongle: device lists you create are written to the data directory
homeassistant/try-locally.sh down     # removes the containers, the network, the image and the data directory
```

Everything it creates is named `zlm-*`; `ZLM_TRY_PORT` changes the host port.

**Try it with the dongle.** The script passes no USB device. To check that the image can open the dongle, replace the app container it started with one that sees the USB bus. Stop any other copy of the tool first: only one program can hold the dongle.

```sh
ZLM_TRY_DEMO=false homeassistant/try-locally.sh
# your channel instead of 11:
printf '{"channel": 11, "demo": false, "allowed_hosts": []}\n' > homeassistant/.try-locally/data/options.json
docker rm -f zlm-app
docker run -d --name zlm-app --network zlm-net --ip 172.30.33.10 \
    -e SUPERVISOR_TOKEN=dummy-not-a-supervisor-token \
    -v "$PWD/homeassistant/.try-locally/data:/data" \
    -v /dev/bus/usb:/dev/bus/usb --device-cgroup-rule 'c 189:* rwm' \
    zlm-zigbee-live-map:local
```

The last two options are what a container needs for raw USB: the device nodes of the USB bus, and the right to open them (character devices with major number 189). They mirror what the Supervisor does: it mounts the host's `/dev` in every app container ([`docker/app.py`](https://github.com/home-assistant/supervisor/blob/main/supervisor/docker/app.py)) and adds that same device rule for an app that declares `usb: true` ([`hardware/policy.py`](https://github.com/home-assistant/supervisor/blob/main/supervisor/hardware/policy.py)).

On macOS, Docker runs containers in a Linux virtual machine, which does not see the Mac's USB ports until the dongle is handed over to it. With [OrbStack](https://docs.orbstack.dev/features/usb) 2.2 or later:

```sh
orb usb list           # find the id of "CC2531 USB Dongle"
orb usb attach <id>    # the dongle leaves macOS and appears in Linux
orb usb detach <id>    # gives it back to macOS
```

While it is attached, a copy of the tool running directly on the Mac cannot use the dongle. On a Linux computer Docker runs without a virtual machine, so there is nothing to hand over.

**What has been tested, and what has not.**

- **The dongle from inside the container: tested on one set-up**, OrbStack 2.2.5 on an Apple-silicon Mac, with the commands above. The app opened the CC2531 (`0451:16ae`), showed live traffic through the stand-in proxy, and found the dongle again by itself after it was detached and re-attached while the container kept running. Docker on a Linux computer and Docker Desktop have not been tried.
- **A real Supervisor: tested on Home Assistant's own test bench**, the [devcontainer of its testing guide](https://contributors.home-assistant.io/apps/guides/testing/) (Supervisor 2026.11.0, Core 2026.11.2, `aarch64`, under OrbStack). The Supervisor built the app from its folder and installed it; the map opened from Home Assistant, after its sign-in and through its ingress, with no login of the app; a request that does not come through Home Assistant was refused; options from the *Configuration* tab were applied at the next restart; lists survived a restart.
- **The dongle on that Supervisor: tested.** With `usb: true` and nothing else, the app opened the CC2531 and showed live traffic. The Supervisor gave the app container `/dev` (read-only, which still lets a device be opened) and the device rules for character majors 189 and 180, no privilege and no capability. Unplugged while running, the app says so on the page and in its log, and lets go of the device.
- **Plugging the dongle back in while the app runs: not proven on a Home Assistant machine.** On the bench the app found it again by itself only when the bench was helped: the devcontainer's `/dev` is a copy made when it is created, so a newly plugged device gets no node there until one is made by hand. A real machine's `/dev` follows the hardware; nobody has watched the app recover there. Restarting the app is the fallback.
- **AppArmor: not tested.** The bench's kernel has none, so the app ran unconfined. What Home Assistant's default profile does to libusb on a machine that enforces it is unknown.
- **Installing from the repository address: tested on the same bench.** The one-click link opened Home Assistant's dialog with the address filled in; the Supervisor cloned the repository, listed the app at version 0.1.0 with its documentation, downloaded the published image without building anything, and the app ran through ingress. The image also pulls without credentials for both architectures. Nobody has yet done it on a real Home Assistant machine.
- **`amd64`: built and run under emulation only**, on an Apple-silicon Mac, where the image served the demo map through the stand-in proxy. `aarch64` is that machine's own architecture. Neither has run on a real `amd64` machine.

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

The first bytes of an IEEE address are a prefix that the IEEE assigns to a company, so the tool can name who made the radio chip of every device it hears. That is the chip or module maker, often not the brand on the box: sensors from different brands frequently share one chip vendor. The product model is announced inside the encrypted part of the traffic, which this tool reads only once the network key is known (see [Device names](#device-names)); if your hub export has a model column, it is imported with the names.

A snapshot of the [IEEE registry](https://standards-oui.ieee.org/) ships with the tool. Update it from *Settings*, or with `zigbee-live-map --update-vendors`. This downloads three public files and sends nothing about your network. It never happens on its own.

## Hue Bridge

If you have a Philips Hue Bridge, the tool can ask it what it knows. A sniffer cannot read names, models or rooms, and cannot tell a device that is gone from one that is merely quiet. The bridge can.

Once a bridge is set up, every Zigbee device it manages is matched to the map on its IEEE address, and the device sheet gets a **From the hub** group: the bridge's own name, product, model id, maker, type, room, battery level when the bridge has one, and whether the bridge can reach the device. A device the bridge reports as anything other than connected is marked on the map with a warning triangle and "⚠" before its name, and the *Things to look at* panel lists it, including devices the bridge knows and the sniffer has never heard: the bridge sees them, the radio does not, and that is the diagnostic. The bridge's own Zigbee channel is shown in *Settings*, and when the bridge's network is on a different channel than the one the sniffer listens on (live mode), *Things to look at* says so once, since none of its devices can be heard then. A name you keep in a list always wins; where a device has no name in any list, the map and the log show the bridge's name. Nothing is written into your lists.

**Set it up** from *Settings*, *Hue Bridge*:

1. *Find bridges on my network* lists the bridges that answer on the local network (mDNS). Multicast often does not reach into a container or a virtual machine; then type the address (IP, name, or `address:port`) instead.
2. Click *Pair*, then press the big button on the bridge. The tool asks for an application key every two seconds for 30 seconds. Or, if you already have a key, type it in *Use this key*.
3. The bridge is read at once, then every 30 seconds, and with *Read the bridge now*. *Forget this bridge* removes everything.

The application key is kept in `hue.json` in your data directory, readable by you only, and in memory only in `--demo` mode. It never leaves the tool's server: no page, message, log line or error shows it.

**Trust.** The bridge speaks HTTPS with a certificate that no public authority vouches for, so the tool pins it. The first time you set a bridge up, it records the SHA-256 fingerprint of the certificate the bridge presents and checks that the certificate's common name equals the bridge id the bridge announces. Every later request must present that exact certificate, checked before anything is sent; a different one is refused with a plain message, and you forget the bridge and set it up again. Only addresses on your own network (private, link-local, loopback) are ever contacted.

**What it does not give.** The Hue API exposes no link-quality figure (no LQI, no RSSI) anywhere, so none is shown. The *Diagnostics* signs below still come from the sniffer alone.

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

### With the network key

The measurements the devices keep to themselves travel inside the encrypted network layer. With your network's key (entered in *Settings*, or recovered by the default-key test below), the tool reads them, and the map and the log go from consequences to the network's own account of itself:

| Sign | How it is read | What it suggests |
|---|---|---|
| The mesh rates a link poor | a router's Link Status: the cost it measures to each neighbour, both ways, from 1 (excellent) to 7 (very poor) | a weak router-to-router link, as the routers themselves see it |
| Delivery failures reported | a router's Network Status command: it could not deliver (link failure, many-to-one route failure…), and about which device | a broken route, often to a battery device whose link to its parent is weak |
| Repeated rejoins | Rejoin Response commands for the same device | a device that keeps losing its parent |
| Weak link to an end device | a router's neighbour table (Mgmt_Lqi_rsp, which a hub such as Home Assistant requests when it scans the topology): the LQI at which it receives each neighbour, end devices included | a battery device poorly heard by its parent; Link Status does not cover these links |
| Messages not confirmed end to end | APS acknowledgements: a message sent in acknowledged mode, and the acknowledgement its final recipient sends back | a device that does not get its messages, whatever the individual hops say |
| Requests left unanswered | ZCL commands that expect a reply (read or write an attribute, a command without "no default response") and ZDO requests, paired with the answer that comes back by transaction sequence number | a device that does not get, or cannot answer, what the hub asks it; works for messages sent without an APS acknowledgement |

LQI is vendor-specific (0-255, higher is better). The thresholds the tool uses come from comparing LQI with Link Status costs on a real network: cost 1 at LQI 117 and above, cost 5 or worse at 47 and below. Delays of acknowledgements are as precise as the sniffer's USB timing, a few milliseconds.

The device sheet lists the neighbours a router reports with their LQI, and how many of a device's messages were confirmed end to end. Every network command gets its real name in the log, replacing the guess made from the frame's shape: route requests and replies (with the path cost accumulated so far), route records and their relays, network status, leave, rejoin, end-device timeout. Devices also announce their manufacturer, model, power source, firmware and battery level, which names them on the map (see [Device names](#device-names)).

A click on a log line opens the frame itself, layer by layer, as a protocol analyser would show it: the MAC and NWK headers, and with the key the NWK command or the APS, ZDO and ZCL layers, with attribute values (signed and decimal ones as numbers). One manufacturer format is read further: the light updates a Philips Hue bridge sends its lights (cluster `0xFC03` with Signify's manufacturer code) are shown as what they ask for: on or off, brightness, colour, transition, effect and, for a strip, the gradient. That format is Signify's own, reverse-engineered by Christian Iversen and read here with the [hue-zigbee-encoding](https://pypi.org/project/hue-zigbee-encoding/) library.

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
  --host HOST            address to listen on (default 127.0.0.1, this computer only; 0.0.0.0 for your network)
  --port N               port (default 8765)
  --password-file FILE   first line of FILE is the password for a network bind (or set ZLM_PASSWORD)
  --allowed-host NAME    a host name the page may be reached by, e.g. behind a reverse proxy (repeatable; needs a password)
  --ingress              accept Home Assistant's ingress proxy (172.30.32.2) without a login; only inside the Home Assistant app
  --open                 open the page in your browser
```

A bind on anything but a loopback address needs a password (`ZLM_PASSWORD` or `--password-file`) or `--ingress` (Home Assistant app only); with a password, signing in is required on every bind, loopback included; see [Running it on your LAN](#running-it-on-your-lan). With `--host 0.0.0.0` the start-up line prints the address for this computer (`http://127.0.0.1:PORT/`), and `--open` opens that one.

Language, theme and animations are set from *Settings* in the page and remembered by your browser. Language and theme default to automatic: your browser's language when a translation exists, English otherwise, and your system's light or dark setting.

## How it works

```
CC2531 sniffer ──USB──▶ sniffer.py ──frames──▶ frames.py ──events──▶ server.py ──WebSocket──▶ page
  (receive only)        (libusb)             (one event per frame)   (--host)             (canvas)
```

A frame's clear headers are read once, in `wire.py`, and everything else reads that: `frames.py` makes the map's event from them, `decode.py` decrypts what follows when a key is known and reads the layers behind it, `dissect.py` lays a frame out layer by layer for the log's detail view. `builders.py` writes frames, for the demo and the tests.

Two layers of a Zigbee frame are readable by anyone in radio range, and they are all the tool uses without a network key (see [Scope and privacy](#scope-and-privacy) for what a key adds):

- the **MAC header** (IEEE 802.15.4): which device transmits this radio hop, and to whom;
- the **NWK header** (Zigbee): who wrote the message, who it is finally for, how many hops are left, a sequence number, and the IEEE address of the device that secured this hop.

Comparing the two is what reveals routing: when the radio sender is not the author, a router is relaying. Parent-child links come from data requests, since a sleeping device only ever polls its parent. The sequence number lets one message be followed from hop to hop, which is how relay delays are measured.

The header decoder has no dependency beyond the standard library. Its output was compared field by field with Wireshark's dissector (`tshark`) on a real capture and on the demo traffic.

## Scope and privacy

- **Receive only.** The sniffer firmware cannot transmit, and this tool never sends anything on the radio.
- **What it reads.** Without a network key, only the two clear layers described above: who talks to whom, when and how much, never what is said. One exception, which is a test and not a decryption of your traffic: when a device joins a network that still uses Zigbee's well-known default link key, the key exchange of that join can be read by anyone in range, and the tool recovers the network key from it, says that the network is exposed, and keeps the key in memory. With a network key (that one, or one you enter in *Settings*; keys you save are kept in `keys.json` in your data directory, readable by you only), it decrypts the network layer to explain how the network works in more detail: what each network command says, routers' link costs, what devices say about themselves (manufacturer, model, power source, firmware, battery level); see [With the network key](#with-the-network-key). The network key opens everything that layer protects, application messages and sensor readings included, so treat the key, and access to this tool's pages, like access to the network itself. Without a key, network commands are recognised by their shape and labelled "probable" when that is a deduction.
- **Local by default.** Out of the box the server listens on `127.0.0.1` and answers only requests addressed to that local address. It grants no cross-origin access, so another website cannot read anything through your browser, and it refuses any change or live connection that does not carry a token only its own page can obtain. You can make it listen on your network (`--host`): it then requires a password and checks the address each request is meant for, or, behind Home Assistant ingress, accepts only the Home Assistant supervisor. A password on a loopback bind (behind a reverse proxy) means the same sign-in. That traffic is plain HTTP, see [Running it on your LAN](#running-it-on-your-lan). The only outbound connections are the registry update, and your Hue Bridge once you set it up (see [Hue Bridge](#hue-bridge)): the first on your request, the second only to a bridge on your own network. Without a bridge set up, and in `--demo`, the tool contacts none.
- **Your data stays out of the repository.** Device lists live in your home directory, and `*.pcap` is in `.gitignore`. A capture contains your devices' addresses: think before sharing one.
- Traffic of a neighbouring network on the same channel is recognised by its PAN id and kept off the map. Use this on networks you own or are allowed to monitor.

## Limits

- The dongle only hears what reaches it. A far-away device may be missing, and a missing frame is not proof that it was not sent.
- Signal strength (dBm) is what the sniffer received, not the link quality between two devices.
- One sniffer model is supported for now. `sniffer.py` is small and isolated: other 802.15.4 sniffers can be added there.
- Zigbee PRO, plus the headers of Green Power and inter-PAN (Touchlink) frames. Other 802.15.4 protocols, MAC-secured frames and damaged frames show up as "not decoded".

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

The Hue integration has a fake bridge too (HTTPS, self-signed, the same pairing and reads). Run it beside the demo, then set it up from *Settings* with the address `127.0.0.1:8795` and the application key it prints:

```sh
uv run python tests/fake_hue_bridge.py --port 8795 --demo
```

Its devices are those of the demo network, in a few rooms, with one that has connection problems, one that is not reachable, and one the demo network does not contain. The demo's own names win on the map; switch the *Demo network* list off on the *Known devices* page to see the bridge's names.

To refresh the registry snapshot shipped with the package:

```sh
uv run python -m zigbee_live_map.vendors src/zigbee_live_map/data/vendors.tsv.gz
```

## License

MIT. The chip maker registry is public data published by the IEEE Registration Authority.
