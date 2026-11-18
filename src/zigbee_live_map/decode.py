"""Decrypt and read the parts of a Zigbee frame that are encrypted, once a key is available.

What the encrypted layers give up, all on traffic the user owns:

- ``recover_network_key``: from an APS Transport-Key command secured with the default link key,
  the network key itself. If this succeeds, the network is using the well-known default key and
  anyone in radio range who catches a join can read everything. That is the vulnerability test.
- ``touchlink_scan_response`` and ``touchlink_key_transport``: the two halves of a Touchlink (ZLL)
  commissioning join, from which the network key is recovered with a publicly known key.
- ``decrypt_network_payload``: with the network key, the NWK payload. It is either a NWK command
  (``nwk_command``: a router's Link Status lists each neighbour with the link cost it measures, 1 best
  … 7 worst, the mesh's own link-quality assessment) or an APS frame (``aps_header``), which carries ZDO
  (``mgmt_lqi``: a router's neighbour table) or ZCL (``device_info``: the Basic cluster announces a
  device's manufacturer, model and power source; Power Configuration its battery level).

The clear headers, and where each ends, come from wire.py: CCM* authenticates the exact header bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import crypto, wire

ZCL_BASIC_CLUSTER = 0x0000
ATTR_MANUFACTURER, ATTR_MODEL, ATTR_POWER_SOURCE = 0x0004, 0x0005, 0x0007
ATTR_APP_VERSION, ATTR_DATE_CODE, ATTR_SW_BUILD = 0x0001, 0x0006, 0x4000
POWER_SOURCE = {0: "unknown", 1: "mains", 2: "mains", 3: "battery", 4: "rechargeable"}
POWER_CONFIG_CLUSTER = 0x0001
ATTR_BATTERY_VOLTAGE, ATTR_BATTERY_PERCENT = 0x0020, 0x0021

# ZCL simple-type byte lengths, enough to read the values we want and to skip past the ones we don't.
ZCL_STRING_TYPES = {0x41, 0x42}
ZCL_TYPE_LEN = {0x00: 0, 0x08: 1, 0x09: 2, 0x0a: 3, 0x0b: 4, 0x10: 1, 0x18: 1, 0x19: 2, 0x1a: 3, 0x1b: 4,
                0x20: 1, 0x21: 2, 0x22: 3, 0x23: 4, 0x24: 5, 0x25: 6, 0x26: 7, 0x27: 8,
                0x28: 1, 0x29: 2, 0x2a: 3, 0x2b: 4, 0x30: 1, 0x31: 2, 0x38: 2, 0x39: 4}


# --- secured payloads: what CCM* needs to open them ------------------------------------------------

@dataclass(frozen=True)
class Sealed:
    """A secured payload: its security header, the header bytes CCM* authenticates, and the ciphertext with its MIC."""

    aux: wire.Aux
    aad: bytes
    ciphertext: bytes

    def open(self, key: bytes) -> bytes | None:
        """The plaintext, or None when the key is not the one, or the frame does not name the device that secured it."""
        if self.aux.src64 is None:
            return None
        nonce = crypto.nonce(self.aux.src64, self.aux.counter, _level5(self.aux.control))
        return crypto.ccm_star_decrypt(key, nonce, self.ciphertext, self.aad)


def _level5(control: int) -> int:
    """Frames travel with a security level of 0 but are secured at level 5: restore it."""
    return (control & ~0x07) | crypto.SECURITY_LEVEL


def _sealed(raw: bytes, header_start: int, aux: wire.Aux) -> Sealed:
    """The authenticated bytes run from the start of the layer's own header to the end of its security header."""
    aad = raw[header_start:aux.start] + bytes([_level5(aux.control)]) + raw[aux.start + 1:aux.end]
    return Sealed(aux, aad, raw[aux.end:])


def network_envelope(frame: bytes | wire.Frame) -> Sealed | None:
    """The secured payload of a NWK frame, or None if the frame is not a secured Zigbee PRO one."""
    f = wire.read(frame)
    nwk = f.nwk
    if nwk is None or nwk.aux is None:
        return None
    return _sealed(f.raw, nwk.start, nwk.aux)


def decrypt_network_payload(frame: bytes | wire.Frame, network_key: bytes) -> bytes | None:
    """Return the decrypted NWK payload (an APS frame or a NWK command) of a secured frame, or None."""
    sealed = network_envelope(frame)
    return sealed.open(network_key) if sealed else None


def transport_key_envelope(frame: bytes | wire.Frame) -> Sealed | None:
    """The secured payload of an APS Transport-Key command, or None. The NWK payload is in clear here
    (the joining device has no network key yet), so only the APS layer is secured."""
    f = wire.read(frame)
    nwk = f.nwk
    if nwk is None or nwk.secured:   # a secured NWK payload here is not a cleartext transport key
        return None
    try:
        rd = wire.Reader(f.raw, nwk.end)
        fc = rd.u8()
        if fc & 0x03 != 1 or not fc & 0x20:   # APS command, secured
            return None
        rd.u8()   # APS counter
        aux = wire.read_aux(rd)
    except ValueError:
        return None
    if aux.key_id != 2:   # key-transport key
        return None
    return _sealed(f.raw, nwk.end, aux)


def recover_network_key(frame: bytes | wire.Frame, link_key: bytes = crypto.DEFAULT_TC_LINK_KEY) -> bytes | None:
    """If this frame is a Transport-Key command decryptable with link_key, return the network key."""
    sealed = transport_key_envelope(frame)
    plain = sealed.open(crypto.transport_key_key(link_key)) if sealed else None
    if plain is None or len(plain) < 1 + 1 + 16:
        return None
    if plain[0] != 0x05 or plain[1] != 0x01:   # command id Transport-Key, key type Standard Network Key
        return None
    return plain[2:18]


# --- Touchlink (ZLL) commissioning: recover the network key from an inter-PAN join ----------
#
# A separate join mechanism from the APS Transport-Key path above. Touchlink frames are inter-PAN:
# a stub NWK header (frame control only) and a stub APS header (frame control, optional group id,
# cluster id, profile id), then a ZCL command on the Touchlink commissioning cluster (0x1000). The
# network key travels in a Network Start / Network Join request, encrypted under a key the ZLL master
# key recovers (crypto.zll_decrypt_network_key). The response identifier needed for that recovery
# arrives earlier, in the Scan Response of the same transaction, so the two are parsed separately and
# the caller holds the response id between them. Field offsets follow Wireshark's touchlink dissector.

TOUCHLINK_CLUSTER = 0x1000
ZLL_CMD_SCAN_RESPONSE = 0x01
ZLL_CMD_NETWORK_START_REQUEST = 0x10
ZLL_CMD_NETWORK_JOIN_ROUTER_REQUEST = 0x12
ZLL_CMD_NETWORK_JOIN_ENDDEV_REQUEST = 0x14
_ZLL_KEY_TRANSPORT_COMMANDS = (ZLL_CMD_NETWORK_START_REQUEST, ZLL_CMD_NETWORK_JOIN_ROUTER_REQUEST,
                               ZLL_CMD_NETWORK_JOIN_ENDDEV_REQUEST)


def _touchlink_command(frame: bytes | wire.Frame) -> tuple[int, int, wire.Reader] | None:
    """Walk a Touchlink commissioning frame up to its command payload.

    Returns (ZCL command id, inter-PAN transaction id, reader positioned just after the transaction id),
    or None if the frame is not an inter-PAN frame on the Touchlink commissioning cluster."""
    f = wire.read(frame)
    if not isinstance(f.net, wire.InterPan):
        return None
    try:
        rd = wire.Reader(f.raw, f.net.end)
        aps_fcf = rd.u8()
        if aps_fcf & 0x03 != 0x03:   # APS stub: inter-PAN frame type
            return None
        if (aps_fcf >> 2) & 0x03 == 0x03:   # group delivery carries a 2-byte group address first
            rd.u16()
        cluster = rd.u16()
        rd.u16()                     # profile id
        if cluster != TOUCHLINK_CLUSTER:
            return None
        zcl_fcf = rd.u8()
        if zcl_fcf & 0x03 != 0x01:   # ZCL cluster-specific command
            return None
        rd.u8()                      # ZCL transaction sequence number
        command = rd.u8()
        if command >= 0x40:          # commissioning commands (0x00-0x3f) all begin with a transaction id
            return None
        return command, rd.u32(), rd
    except ValueError:
        return None


def touchlink_scan_response(frame: bytes | wire.Frame) -> tuple[int, int] | None:
    """(inter-PAN transaction id, response id) from a Touchlink Scan Response, or None.

    The response id is needed to recover the network key from a later join on the same transaction."""
    parsed = _touchlink_command(frame)
    if parsed is None:
        return None
    command, transaction_id, rd = parsed
    if command != ZLL_CMD_SCAN_RESPONSE:
        return None
    try:
        rd.take(3)               # rssi correction, zigbee info, zll info
        rd.u16()                 # key bitmask
        return transaction_id, rd.u32()
    except ValueError:
        return None


def touchlink_key_transport(frame: bytes | wire.Frame) -> dict | None:
    """{transaction_id, key_index, encrypted_key} from a Touchlink network start/join request, or None.

    `crypto.zll_decrypt_network_key` recovers the network key from it, with the response id seen earlier in
    the Scan Response of the same transaction and the base key the key index selects (the leaked ZLL master
    key, the public certification key, or the development key)."""
    parsed = _touchlink_command(frame)
    if parsed is None:
        return None
    command, transaction_id, rd = parsed
    if command not in _ZLL_KEY_TRANSPORT_COMMANDS:
        return None
    try:
        rd.take(8)               # extended PAN id
        return {"transaction_id": transaction_id, "key_index": rd.u8(), "encrypted_key": rd.take(16)}
    except ValueError:
        return None


# --- NWK commands ---------------------------------------------------------------------------------

# NWK command identifiers (Zigbee PRO specification, § 3.4, and the R23 commissioning pair).
NWK_COMMANDS = {
    0x01: "route_request", 0x02: "route_reply", 0x03: "network_status", 0x04: "leave", 0x05: "route_record",
    0x06: "rejoin_request", 0x07: "rejoin_response", 0x08: "link_status", 0x09: "network_report",
    0x0A: "network_update", 0x0B: "ed_timeout_request", 0x0C: "ed_timeout_response", 0x0D: "link_power_delta",
    0x0E: "commissioning_request", 0x0F: "commissioning_response",
}


def nwk_command(payload: bytes) -> dict | None:
    """Name a decrypted NWK command payload and read the fields worth showing.

    Returns {"name", "detail"}; an unknown identifier is named "0x.." with no detail. A command that is
    cut short keeps its name and loses its detail: no field is guessed."""
    if not payload:
        return None
    cid = payload[0]
    name = NWK_COMMANDS.get(cid, f"0x{cid:02x}")
    detail: dict = {}
    rd = wire.Reader(payload, 1)
    try:
        if cid == 0x01:
            options = rd.u8(); rd.u8()
            detail = {"dst": rd.short(), "cost": rd.u8(), "m2o": bool((options >> 3) & 3)}
        elif cid == 0x02:
            rd.take(2)
            detail = {"originator": rd.short(), "responder": rd.short(), "cost": rd.u8()}
        elif cid == 0x03:
            detail = {"status": rd.u8(), "addr": rd.short()}
        elif cid == 0x04:
            options = rd.u8()
            detail = {"rejoin": bool(options & 0x20), "request": bool(options & 0x40), "children": bool(options & 0x80)}
        elif cid == 0x05:
            detail = {"relays": [rd.short() for _ in range(rd.u8())]}
        elif cid == 0x07:
            detail = {"addr": rd.short(), "status": rd.u8()}
        elif cid == 0x08:
            links = []
            for _ in range(rd.u8() & 0x1F):
                addr, costs = rd.short(), rd.u8()
                links.append({"addr": addr, "incoming": costs & 0x07, "outgoing": (costs >> 4) & 0x07})
            detail = {"links": links}
        elif cid == 0x0B:
            timeout = rd.u8()
            detail = {"minutes": 10 / 60 if timeout == 0 else 2 ** timeout}
        elif cid == 0x0C:
            detail = {"status": rd.u8()}
    except ValueError:
        detail = {}
    return {"name": name, "detail": detail}


# --- APS layer: end-to-end acknowledgements, and what the frame carries -----------------------------

APS_TYPES = {0: "data", 1: "cmd", 2: "ack"}
ZDO_PROFILE, MGMT_LQI_RSP = 0x0000, 0x8031
LQI_DEVICE_TYPES = {0: "coordinator", 1: "router", 2: "end_device"}
LQI_RELATIONSHIPS = {0: "parent", 1: "child", 2: "sibling", 3: "none", 4: "previous_child"}


def aps_header(payload: bytes) -> dict | None:
    """Read the APS header of a decrypted NWK payload (Zigbee PRO § 2.2.5).

    Returns {type, ack_req, counter} plus cluster/profile when the frame carries them, and "payload" (the
    APS payload) for an unsecured, unfragmented data frame. The header is in clear even when the APS layer
    is secured with a link key; only the payload is not. None for inter-PAN or a truncated header."""
    try:
        rd = wire.Reader(payload)
        fc = rd.u8()
        ftype, mode = fc & 3, (fc >> 2) & 3
        if ftype == 3:
            return None
        out: dict = {"type": APS_TYPES[ftype], "ack_req": bool(fc & 0x40)}
        if ftype == 0:
            if mode == 3:
                rd.u16()          # group address
            else:
                rd.u8()           # destination endpoint
            out["cluster"], out["profile"] = rd.u16(), rd.u16()
            rd.u8()               # source endpoint
        elif ftype == 2 and not fc & 0x10:   # an acknowledgement of data echoes its endpoints, cluster and profile
            rd.u8()
            out["cluster"], out["profile"] = rd.u16(), rd.u16()
            rd.u8()
        out["counter"] = rd.u8()
        if ftype == 0 and not fc & 0x20 and not fc & 0x80:   # not secured with a link key, not fragmented
            out["payload"] = rd.rest()
        return out
    except ValueError:
        return None


def mgmt_lqi(zdo: bytes) -> dict | None:
    """A Mgmt_Lqi_rsp (ZDO 0x8031): one page of the responding router's neighbour table.

    Each neighbour: its short and IEEE address, device type, relationship to the responder, depth and the
    LQI (0-255) at which the responder receives it."""
    try:
        rd = wire.Reader(zdo)
        rd.u8()                   # transaction sequence number
        if rd.u8() != 0:          # status: 0 = success
            return None
        total, start, count = rd.u8(), rd.u8(), rd.u8()
        rows = []
        for _ in range(count):
            rd.take(8)            # extended PAN id
            ieee, addr, flags = rd.ieee(), rd.short(), rd.u8()
            rd.u8()               # permit joining
            rows.append({"addr": addr, "ieee": ieee,
                         "type": LQI_DEVICE_TYPES.get(flags & 3, "unknown"),
                         "rel": LQI_RELATIONSHIPS.get((flags >> 4) & 7, "unknown"),
                         "depth": rd.u8(), "lqi": rd.u8()})
        return {"total": total, "start": start, "rows": rows}
    except ValueError:
        return None


# Global ZCL commands that are themselves answers, or that never get one (Write Attributes No Response).
ZCL_GLOBAL_NO_REPLY = {0x01, 0x04, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x12, 0x14, 0x16}


def zcl_header(payload: bytes) -> dict | None:
    """The ZCL header (ZCL § 2.4.1): {fc, global, manufacturer, seq, command, body}, or None when it is cut short.

    `manufacturer` is the manufacturer code of a manufacturer-specific frame, else None; `body` is what
    follows the header."""
    try:
        rd = wire.Reader(payload)
        fc = rd.u8()
        manufacturer = rd.u16() if fc & 0x04 else None
        return {"fc": fc, "global": fc & 0x03 == 0, "manufacturer": manufacturer, "seq": rd.u8(), "command": rd.u8(),
                "body": rd.rest()}
    except ValueError:
        return None


def exchange(aps: dict) -> dict | None:
    """The request/response bookkeeping of an APS data frame: {"seq": "c12" | "d7", "expects": bool}.

    ZCL (seq prefixed "c"): a command expects a reply unless it is itself an answer or its "disable default
    response" bit is set; the reply is any ZCL frame coming back with the same transaction sequence number
    (ZCL § 2.4.1, § 2.5.12). ZDO (prefixed "d"): a request is a cluster below 0x8000 and its response is the
    same cluster with bit 15 set, carrying the same transaction sequence number."""
    payload = aps.get("payload")
    if aps.get("type") != "data" or not payload:
        return None
    if aps.get("profile") == ZDO_PROFILE:
        return {"seq": f"d{payload[0]}", "expects": aps["cluster"] < 0x8000}
    zcl = zcl_header(payload)
    if zcl is None:
        return None
    expects = not zcl["fc"] & 0x10 and not (zcl["global"] and zcl["command"] in ZCL_GLOBAL_NO_REPLY)
    return {"seq": f"c{zcl['seq']}", "expects": expects}


def zcl_values(payload: bytes) -> dict:
    """Decode a ZCL Read-Attributes-Response (0x01) or Report-Attributes (0x0a) into {attr id: int|str}.

    Integers and strings are read; other types are skipped by their length, so a wanted attribute after
    them is still reached. A truly unknown type stops the walk (its length is unknowable), and so does a
    value that is cut short: it is left out, not read from the bytes that happen to be there."""
    out: dict = {}
    zcl = zcl_header(payload)
    if zcl is None or not zcl["global"] or zcl["command"] not in (0x01, 0x0a):
        return out
    has_status = zcl["command"] == 0x01
    rd = wire.Reader(zcl["body"])
    try:
        while rd.left:
            attr = rd.u16()
            if has_status and rd.u8() != 0:
                continue    # a failed read is just attribute + status, no value
            dtype = rd.u8()
            if dtype in ZCL_STRING_TYPES:
                out[attr] = rd.take(rd.u8()).decode("utf-8", "replace").strip("\x00 ")
            elif dtype in ZCL_TYPE_LEN:
                out[attr] = rd.uint(ZCL_TYPE_LEN[dtype])
            else:
                break
    except ValueError:
        pass
    return out


def _basic_identity(attrs: dict) -> dict | None:
    out: dict = {}
    if isinstance(attrs.get(ATTR_MANUFACTURER), str): out["manufacturer"] = attrs[ATTR_MANUFACTURER]
    if isinstance(attrs.get(ATTR_MODEL), str): out["model"] = attrs[ATTR_MODEL]
    if isinstance(attrs.get(ATTR_POWER_SOURCE), int): out["power"] = POWER_SOURCE.get(attrs[ATTR_POWER_SOURCE] & 0x7F, "unknown")
    if isinstance(attrs.get(ATTR_SW_BUILD), str): out["sw"] = attrs[ATTR_SW_BUILD]
    if isinstance(attrs.get(ATTR_DATE_CODE), str): out["date"] = attrs[ATTR_DATE_CODE]
    if isinstance(attrs.get(ATTR_APP_VERSION), int): out["appVer"] = attrs[ATTR_APP_VERSION]
    return out or None


def _battery(attrs: dict) -> dict | None:
    pct = attrs.get(ATTR_BATTERY_PERCENT)
    if isinstance(pct, int) and pct != 0xFF:     # 0xFF = unknown/unsupported; reported in half-percent
        return {"percent": min(100, pct // 2)}
    volt = attrs.get(ATTR_BATTERY_VOLTAGE)
    if isinstance(volt, int) and volt not in (0, 0xFF):   # reported in units of 100 mV
        return {"volts": round(volt / 10, 1)}
    return None


def device_info(aps: dict) -> dict | None:
    """What a decrypted ZCL report says about its sender: identity (Basic) and/or battery (Power Config)."""
    if aps.get("type") != "data" or aps.get("payload") is None or aps.get("profile") == ZDO_PROFILE:
        return None
    attrs = zcl_values(aps["payload"])
    if aps["cluster"] == ZCL_BASIC_CLUSTER:
        return {"identity": _basic_identity(attrs), "battery": None}
    if aps["cluster"] == POWER_CONFIG_CLUSTER:
        return {"identity": None, "battery": _battery(attrs)}
    return None
