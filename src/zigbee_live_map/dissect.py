"""A frame, layer by layer, for the log's detail view: what a protocol analyser would show.

`dissect` only presents. The headers come from wire.py and the decrypted layers from decode.py, the same
readers the map itself uses, so the detail view can never disagree with the line it was opened from. Field
names are the specifications' own; ZCL values are raw, without units or scaling.
"""

from __future__ import annotations

import struct

from hue_zigbee_encoding import HUE_LIGHT_EFFECT_CLUSTER_ID, HUE_VENDOR_ID, HueLightUpdateMessage

from . import decode, wire

PROFILES = {0x0000: "ZDO", 0x0104: "Home Automation", 0xA1E0: "Green Power", 0xC05E: "ZLL"}
CLUSTERS = {
    0x0000: "Basic", 0x0001: "Power Configuration", 0x0003: "Identify", 0x0004: "Groups", 0x0005: "Scenes",
    0x0006: "On/Off", 0x0008: "Level Control", 0x000A: "Time", 0x0019: "OTA Upgrade", 0x0020: "Poll Control",
    0x0021: "Green Power", 0x0201: "Thermostat", 0x0202: "Fan Control", 0x0204: "Thermostat UI Configuration",
    0x0300: "Color Control", 0x0400: "Illuminance Measurement", 0x0402: "Temperature Measurement",
    0x0403: "Pressure Measurement", 0x0405: "Relative Humidity Measurement", 0x0406: "Occupancy Sensing",
    0x0500: "IAS Zone", 0x0702: "Metering", 0x0B04: "Electrical Measurement", 0x0B05: "Diagnostics",
    0x1000: "Touchlink Commissioning", 0xEF00: "Tuya (manufacturer)", 0xFC11: "Sonoff (manufacturer)",
}
# The ids from 0xFC00 up belong to no one: each manufacturer uses them as it likes (0xFC03 is a light control for
# Signify and an air-quality measurement for Develco). Such a cluster has a name only with its manufacturer code,
# which travels in the ZCL header of manufacturer-specific frames.
MANUFACTURERS = {HUE_VENDOR_ID: "Signify, Philips Hue"}
MANUFACTURER_CLUSTERS = {(HUE_VENDOR_ID, HUE_LIGHT_EFFECT_CLUSTER_ID): "Philips Hue light control"}
HUE_LIGHT_UPDATE = 0x00   # the one command of the Hue light control cluster, sent to the light ("multicolor" in ZHA's quirks)
ZDO_CLUSTERS = {
    0x0000: "NWK_addr", 0x0001: "IEEE_addr", 0x0002: "Node_Desc", 0x0003: "Power_Desc", 0x0004: "Simple_Desc",
    0x0005: "Active_EP", 0x0006: "Match_Desc", 0x0013: "Device_annce", 0x0021: "Bind", 0x0022: "Unbind",
    0x0031: "Mgmt_Lqi", 0x0032: "Mgmt_Rtg", 0x0033: "Mgmt_Bind", 0x0034: "Mgmt_Leave", 0x0036: "Mgmt_Permit_Joining",
    0x0038: "Mgmt_NWK_Update",
}
ZCL_GLOBAL = {
    0x00: "Read Attributes", 0x01: "Read Attributes Response", 0x02: "Write Attributes", 0x03: "Write Attributes Undivided",
    0x04: "Write Attributes Response", 0x05: "Write Attributes No Response", 0x06: "Configure Reporting",
    0x07: "Configure Reporting Response", 0x08: "Read Reporting Configuration", 0x09: "Read Reporting Configuration Response",
    0x0A: "Report Attributes", 0x0B: "Default Response", 0x0C: "Discover Attributes", 0x0D: "Discover Attributes Response",
    0x11: "Discover Commands Received", 0x12: "Discover Commands Received Response", 0x13: "Discover Commands Generated",
    0x14: "Discover Commands Generated Response", 0x15: "Discover Attributes Extended", 0x16: "Discover Attributes Extended Response",
}
MAC_FRAME_TYPES = {0: "Beacon", 1: "Data", 2: "Acknowledgement", 3: "MAC command", 4: "Multipurpose", 5: "Fragment", 6: "Extended"}
MAC_COMMAND_NAMES = {0x01: "Association Request", 0x02: "Association Response", 0x03: "Disassociation Notification",
                     0x04: "Data Request", 0x05: "PAN ID Conflict Notification", 0x06: "Orphan Notification",
                     0x07: "Beacon Request", 0x08: "Coordinator Realignment"}
ADDR_MODES = {0: "none", 1: "reserved", 2: "short", 3: "extended"}
NWK_FRAME_TYPES = {0: "data", 1: "NWK command", 2: "reserved", 3: "inter-PAN"}
KEY_IDS = {0: "data key", 1: "network key", 2: "key-transport key", 3: "key-load key"}
APS_DELIVERY = {0: "unicast", 1: "indirect", 2: "broadcast", 3: "group"}


def _hex(data: bytes) -> str:
    return data.hex(" ")


def _named(value: int, names: dict, width: int = 4) -> str:
    name = names.get(value)
    return f"0x{value:0{width}x}" + (f" ({name})" if name else "")


def _stopped(problem: ValueError, left: bytes) -> dict:
    """The layer that says why the walk ended before the end of the headers."""
    if isinstance(problem, wire.Truncated):
        return {"layer": "Truncated", "fields": [["Bytes left", _hex(left)]]}
    return {"layer": "Not decoded", "fields": [["Reason", str(problem)], ["Bytes", _hex(left)]]}


def dissect(frame: bytes | wire.Frame, network_key: bytes | None = None) -> list[dict]:
    """The frame's layers, each {"layer", "fields": [[name, value], ...]}, as far as they can be read.

    Without the key it stops at the NWK security header; with it, it decrypts and reads the NWK command or the
    APS, ZDO and ZCL headers, and the attributes of read responses and reports. Anything unreadable ends the
    walk with the remaining bytes in hex."""
    f = wire.read(frame)
    raw = f.raw
    if len(raw) < 2:
        return [_stopped(wire.Truncated("frame too short"), raw)]
    fcf = int.from_bytes(raw[:2], "little")
    ftype, version = fcf & 7, (fcf >> 12) & 3
    fields = [["Frame type", MAC_FRAME_TYPES.get(ftype, f"reserved ({ftype})")], ["Security enabled", bool(fcf & 0x08)],
              ["Frame pending", bool(fcf & 0x10)], ["Acknowledgement request", bool(fcf & 0x20)],
              ["PAN ID compression", bool(fcf & 0x40)], ["Frame version", version],
              ["Destination addressing mode", ADDR_MODES[(fcf >> 10) & 3]], ["Source addressing mode", ADDR_MODES[(fcf >> 14) & 3]]]
    layers: list[dict] = [{"layer": "IEEE 802.15.4 MAC", "fields": fields}]
    mac = f.mac
    if mac is None:
        layers.append(_stopped(f.problem or wire.Truncated("frame too short"), raw[2:]))
        return layers
    if mac.seq is not None:
        fields.append(["Sequence number", mac.seq])
    for name, value in (("Destination PAN", mac.dst_pan), ("Destination", mac.dst), ("Source PAN", mac.src_pan), ("Source", mac.src)):
        if value is not None:
            fields.append([name, value])
    payload = raw[mac.end:]
    if mac.ftype == wire.ACK:
        return layers
    if not mac.zigbee:
        layers.append({"layer": "Not decoded", "fields": [["Bytes", _hex(payload)]]})
    elif mac.ftype == wire.MAC_COMMAND:
        if not payload:
            layers.append(_stopped(wire.Truncated("frame too short"), payload))
        else:
            command = [["Command", _named(payload[0], MAC_COMMAND_NAMES, 2)]]
            if payload[1:]:
                command.append(["Payload", _hex(payload[1:])])
            layers.append({"layer": "MAC command", "fields": command})
    elif mac.ftype == wire.BEACON:
        layers.append({"layer": "Beacon", "fields": [["Payload", _hex(payload)]]})
    elif not payload:
        layers.append({"layer": "Data", "fields": [["Payload", "empty (the parent had nothing for the device that polled it)"]]})
    elif f.problem is not None:
        layers.append(_stopped(f.problem, payload))
    else:
        _dissect_nwk(f, layers, network_key)
    return layers


def _dissect_nwk(f: wire.Frame, layers: list, network_key: bytes | None) -> None:
    raw, net = f.raw, f.net
    if isinstance(net, wire.GreenPower):
        fields = [["Frame type", "data" if net.ftype == 0 else "maintenance"], ["Protocol version", "3 (Green Power)"],
                  ["Auto-commissioning", bool(net.fc & 0x40)]]
        if net.ext is not None:
            fields += [["Application ID", net.app_id], ["Security level", (net.ext >> 3) & 3],
                       ["Direction", "to GPD" if net.to_gpd else "from GPD"]]
        if net.gpd is not None:
            fields.append(["GPD source ID", net.gpd])
        layers.append({"layer": "Green Power", "fields": fields + [["Rest", _hex(raw[net.end:])]]})
        return
    if isinstance(net, wire.InterPan):
        layers.append({"layer": "Zigbee NWK", "fields": [["Frame type", NWK_FRAME_TYPES[3]], ["Protocol version", wire.ZIGBEE_PRO]]})
        layers.append({"layer": "Inter-PAN APS and payload", "fields": [["Bytes", _hex(raw[net.end:])]]})
        return
    if net is None:   # another protocol version, or the reserved frame type
        first = raw[f.mac.end]
        layers.append({"layer": "Zigbee NWK", "fields": [["Frame type", NWK_FRAME_TYPES[first & 3]], ["Protocol version", (first >> 2) & 0x0F],
                                                         ["Rest", _hex(raw[f.mac.end + 2:])]]})
        return
    nwk = [["Frame type", NWK_FRAME_TYPES[net.ftype]], ["Protocol version", wire.ZIGBEE_PRO],
           ["Discover route", (net.fcf >> 6) & 3], ["Multicast", net.multicast is not None], ["Security", net.secured],
           ["Source route", net.relays is not None], ["End device initiator", bool(net.fcf & 0x2000)],
           ["Destination", net.dst], ["Source", net.src], ["Radius", net.radius], ["Sequence number", net.seq]]
    if net.dst64:
        nwk.append(["Destination IEEE", net.dst64])
    if net.src64:
        nwk.append(["Source IEEE", net.src64])
    if net.multicast is not None:
        nwk.append(["Multicast control", net.multicast])
    if net.relays is not None:
        nwk.append(["Relays", ", ".join(net.relays) + f" (index {net.relay_index})"])
    layers.append({"layer": "Zigbee NWK", "fields": nwk})
    if net.aux is None:
        _dissect_nwk_payload(raw[net.end:], layers, net.ftype)
        return
    aux = net.aux
    fields = [["Security level", "5 (ENC-MIC-32, sent as 0)"], ["Key identifier", KEY_IDS[aux.key_id]],
              ["Extended nonce", aux.extended_nonce], ["Frame counter", aux.counter]]
    if aux.src64 is not None:
        fields.append(["Source IEEE", wire.ieee_text(aux.src64)])
    layers.append({"layer": "NWK security", "fields": fields})
    if network_key is None:
        fields.append(["Payload", "encrypted (no network key)"])
        return
    plain = decode.decrypt_network_payload(f, network_key)
    if plain is None:
        fields.append(["Payload", "the network key does not decrypt it"])
        return
    fields.append(["Payload", "decrypted with the network key"])
    _dissect_nwk_payload(plain, layers, net.ftype)


def _dissect_nwk_payload(payload: bytes, layers: list, ntype: int) -> None:
    """What a NWK frame carries once it is in clear: a NWK command, or an APS frame."""
    if ntype == wire.NWK_COMMAND:
        cmd = decode.nwk_command(payload)
        fields = [["Command", f"0x{payload[0]:02x} ({cmd['name']})"]] if cmd else []
        for k, v in (cmd or {}).get("detail", {}).items():
            if k == "links":
                v = ", ".join(f"{r['addr']} in {r['incoming']} out {r['outgoing']}" for r in v)
            elif isinstance(v, list):
                v = ", ".join(v)
            fields.append([k, v])
        fields.append(["Bytes", _hex(payload)])
        layers.append({"layer": "NWK command", "fields": fields})
        return
    aps = decode.aps_header(payload)
    if aps is None:
        layers.append({"layer": "APS", "fields": [["Bytes", _hex(payload)]]})
        return
    fc = payload[0]
    fields = [["Frame type", aps["type"]], ["Delivery mode", APS_DELIVERY[(fc >> 2) & 3]],
              ["Acknowledgement request", aps["ack_req"]], ["Security (link key)", bool(fc & 0x20)], ["Extended header", bool(fc & 0x80)]]
    profile, cluster = aps.get("profile"), aps.get("cluster")
    body = aps.get("payload")
    zcl = decode.zcl_header(body) if body is not None and profile != decode.ZDO_PROFILE else None
    if cluster is not None:
        fields += [["Cluster", _cluster_text(profile, cluster, zcl["manufacturer"] if zcl else None)], ["Profile", _named(profile, PROFILES)]]
    fields.append(["APS counter", aps["counter"]])
    layers.append({"layer": "APS", "fields": fields})
    if body is None:
        if fc & 0x20:
            layers.append({"layer": "APS payload", "fields": [["Payload", "encrypted with a link key"]]})
        return
    if profile == decode.ZDO_PROFILE:
        z = [["Transaction sequence", body[0] if body else "?"], ["Bytes", _hex(body[1:])]]
        if cluster == decode.MGMT_LQI_RSP:
            table = decode.mgmt_lqi(body)
            if table:
                z.insert(1, ["Neighbours", "; ".join(f"{r['addr']} {r['type']} {r['rel']} LQI {r['lqi']}" for r in table["rows"])])
        layers.append({"layer": "ZDO", "fields": z})
        return
    _dissect_zcl(body, zcl, cluster, layers)


def _cluster_text(profile: int, cluster: int, manufacturer: int | None = None) -> str:
    """A cluster id with its name. A ZDO cluster is a request, or the same id with bit 15 set for its response."""
    if profile != decode.ZDO_PROFILE:
        return _named(cluster, {cluster: MANUFACTURER_CLUSTERS.get((manufacturer, cluster)) or CLUSTERS.get(cluster)})
    base = ZDO_CLUSTERS.get(cluster & 0x7FFF)
    if base and cluster != 0x0013:   # Device_annce is neither a request nor a response
        base += "_rsp" if cluster & 0x8000 else "_req"
    return f"0x{cluster:04x}" + (f" ({base})" if base else "")


def _dissect_zcl(body: bytes, zcl: dict | None, cluster: int | None, layers: list) -> None:
    if zcl is None:
        layers.append({"layer": "ZCL", "fields": [["Bytes", _hex(body)]]})
        return
    fc, command = zcl["fc"], zcl["command"]
    fields = [["Frame type", "global" if zcl["global"] else "cluster-specific"],
              ["Direction", "server to client" if fc & 0x08 else "client to server"],
              ["Disable default response", bool(fc & 0x10)]]
    if zcl["manufacturer"] is not None:
        fields.append(["Manufacturer code", _named(zcl["manufacturer"], MANUFACTURERS)])
    hue_update = (zcl["manufacturer"], cluster) == (HUE_VENDOR_ID, HUE_LIGHT_EFFECT_CLUSTER_ID) and not zcl["global"] and command == HUE_LIGHT_UPDATE
    names = ZCL_GLOBAL if zcl["global"] else {HUE_LIGHT_UPDATE: "Light update"} if hue_update else {}
    fields += [["Transaction sequence", zcl["seq"]], ["Command", _named(command, names, 2)]]
    values = decode.zcl_values(body)
    if values:
        fields.append(["Attributes", "; ".join(f"0x{k:04x} = {v}" for k, v in values.items())])
    fields.append(["Payload", _hex(zcl["body"]) or "none"])
    layers.append({"layer": "ZCL", "fields": fields})
    if hue_update:
        layers.append({"layer": "Philips Hue light update", "fields": _hue_light_update(zcl["body"])})


def _hue_light_update(data: bytes) -> list[list]:
    """What a Hue hub asks of a light in one message: any subset of on/off, brightness, colour, transition, effect
    and, for a strip, its gradient. The format is Signify's own, reverse-engineered by Christian Iversen
    (github.com/chrivers/bifrost, doc/hue-zigbee-format.md); the hue-zigbee-encoding library reads it."""
    try:
        update = HueLightUpdateMessage.from_bytes(data)
    except (ValueError, IndexError, struct.error) as exc:
        return [["Not decoded", str(exc) or "the message is cut short"]]
    xy = lambda c: f"({c.x:.4f}, {c.y:.4f})"   # noqa: E731
    fields: list[list] = []
    if update.is_on is not None:
        fields.append(["On", update.is_on])
    if update.brightness is not None:
        fields.append(["Brightness", f"{update.brightness} of 254"])
    if update.color_temp is not None:
        mired = update.color_temp.mired
        fields.append(["Colour temperature", f"{mired} mired" + (f" ({round(1_000_000 / mired)} K)" if mired else "")])
    if update.color_xy is not None:
        fields.append(["Colour (CIE xy)", xy(update.color_xy)])
    if update.transition_time is not None:
        fields.append(["Transition time", update.transition_time])
    if update.effect is not None:
        fields.append(["Effect", update.effect.name.lower()])
    if update.effect_speed is not None:
        fields.append(["Effect speed", f"{update.effect_speed} of 255"])
    if update.gradient is not None:
        fields.append(["Gradient style", update.gradient.style.name.lower()])
        fields.append(["Gradient colours (CIE xy)", ", ".join(xy(c) for c in update.gradient.colors)])
    if update.gradient_params is not None:
        fields.append(["Gradient scale", update.gradient_params.scale])
        fields.append(["Gradient offset", update.gradient_params.offset])
    return fields or [["Changes", "none"]]
