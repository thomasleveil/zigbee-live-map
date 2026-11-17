# Zigbee Live Map

Shows your Zigbee network talking, live, from a passive USB sniffer dongle: a map of the devices, one animation per frame, a log that explains each frame, and a panel of things to look at (weak links, slow routers, messages nobody collects). It only listens: it never transmits on the radio.

## What you need

- A **CC2531 USB dongle flashed with the TI packet sniffer firmware** (USB id `0451:16ae`), plugged into the machine that runs Home Assistant. A dongle running coordinator firmware (the kind ZHA or Zigbee2MQTT use) does not work, and the dongle your Zigbee integration uses cannot be shared: this is a second, separate dongle.
- To try the app first, turn on the *Demo network* option: it shows a simulated network and needs no dongle.

## Open it

Start the app, then use **Open Web UI** on this page, or turn on **Show in sidebar**. Home Assistant signs you in, so the app asks for no password. (The app starts the tool with `--ingress`. `--ingress` is not for use outside Home Assistant: the tool refuses to start with it unless Home Assistant started it, and anywhere else a password is the way in.) By default only Home Assistant administrators see the sidebar entry (`panel_admin`), because the page shows live radio traffic and the network keys you may enter.

## Options

| Option | Meaning |
|---|---|
| Zigbee channel | The channel your network uses, 11 to 26 (your hub's settings show it). It can also be changed from the page. Ignored when the demo is on. |
| Demo network | Simulated network instead of the dongle. |
| Password | Only needed if you also publish the port (below). Not used through Home Assistant. |
| Allowed host names | Only for a published port, and only together with a password (the app does not start with host names and no password): the names or addresses your browser types to reach it, for example `homeassistant.local` or `192.168.1.5:8099`. Add `:port` when the port you publish is not 8099. Without them the page refuses the request. |

## Where your data is kept

In the app's private `/data` directory, which survives restarts and updates and is part of the app's backups: the lists of known devices, network keys you save in *Settings*, a Hue Bridge key if you set one up, and updates of the chip maker registry. Nothing is written elsewhere. In demo mode nothing is kept.

## Reaching the page without Home Assistant (optional)

The port is **not published** by default. To open the page from a browser outside Home Assistant, enable port `8099/tcp` in the **Network** section of this page, set a **Password** and the **Allowed host names**. This traffic is plain HTTP: the password, the session cookie and the network keys cross your network unencrypted. Only do this on a network you trust. Someone already on that network can keep you from signing in by failing sign-ins on purpose (the wait after wrong passwords is shared); they cannot get in that way, and people already signed in are not affected.

## Not verified

The app was tested on Home Assistant's own test bench (the devcontainer of its testing guide, Supervisor 2026.11.0): installed, opened through Home Assistant, and reading a real CC2531 with `usb: true` alone. What that bench could not show:

- AppArmor: the bench's kernel has none. What Home Assistant's default profile does to the dongle on a machine that enforces it is unknown. If the page says the dongle was not found, look at the app's **Log** tab: it has one line each time the dongle is read, lost or not found.
- Plugging the dongle back in while the app runs: the app looks for it every two seconds, but nobody has watched it recover on a real Home Assistant machine. If the map does not come back, restart the app.
- An `amd64` machine: the image for it was only run under emulation.

## Sources for the choices in this app

Home Assistant app documentation, read on 2026-11-16:

- Keys of `config.yaml` (`ingress`, `ingress_port`, `init`, `usb`, `ports`, `panel_*`, `arch`, `options`, `schema`): <https://contributors.home-assistant.io/apps/reference/configuration/>
- Ingress (accept only `172.30.32.2`, no login, relative URLs, `X-Ingress-Path`): <https://contributors.home-assistant.io/apps/guides/ingress/>
- Raw USB with `usb: true`: <https://contributors.home-assistant.io/apps/guides/hardware/>
- Base image and tag, build arguments: <https://contributors.home-assistant.io/apps/guides/dockerfile/>
- Init system (`/init`, `init: false`) and `CMD`: <https://contributors.home-assistant.io/apps/guides/s6-overlay/>
- Options in `/data/options.json`, schema types: <https://contributors.home-assistant.io/apps/guides/options/>
- `/data` and the runtime environment: <https://contributors.home-assistant.io/apps/reference/environment/>
- Translations of the options form: <https://contributors.home-assistant.io/apps/reference/files/>
- Repository file: <https://contributors.home-assistant.io/apps/guides/repository/>
