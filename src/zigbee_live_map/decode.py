"""Decrypt and read the parts of a Zigbee frame that are encrypted, once a key is available.

Three things the encrypted layers give up, all on traffic the user owns:

- ``recover_network_key``: from an APS Transport-Key command secured with the default link key,
  the network key itself. If this succeeds, the network is using the well-known default key and
  anyone in radio range who catches a join can read everything. That is the vulnerability test.
- ``identify``: the ZCL Basic cluster carries a device's manufacturer name, model and power source
  in clear once the network key decrypts the payload, so a device announces what it is.
- ``link_costs``: a router's Link Status command lists each neighbour with the incoming and outgoing
  link cost it measures (1 best … 7 worst). That is the mesh's own link-quality assessment, far
  better than guessing from retransmissions.

This walker tracks byte offsets so the exact header bytes can be fed to CCM* as additional data.
It is separate from frames.py (which only reads clear headers) so the clear-header path stays simple.
"""

from __future__ import annotations

from . import crypto

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


class _Walk:
    def __init__(self, data: bytes):
        self.d, self.pos = data, 0

    def u8(self) -> int:
        v = self.d[self.pos]; self.pos += 1; return v

    def u16(self) -> int:
        v = int.from_bytes(self.d[self.pos:self.pos + 2], "little"); self.pos += 2; return v

    def take(self, n: int) -> bytes:
        v = self.d[self.pos:self.pos + n]; self.pos += n; return v


def _skip_mac(w: _Walk) -> None:
    fcf = w.u16(); w.u8()  # frame control, sequence
    dst, src, pan_comp = (fcf >> 10) & 3, (fcf >> 14) & 3, bool(fcf & 0x40)
    if dst:
        w.u16(); w.take(2 if dst == 2 else 8)
    if src:
        if not pan_comp:
            w.u16()
        w.take(2 if src == 2 else 8)


def _aux_security(w: _Walk, header_start: int) -> dict:
    """Parse an auxiliary security header at the current position; return the CCM* parameters."""
    aux_start = w.pos
    sec = w.u8()
    counter = int.from_bytes(w.take(4), "little")
    src64 = int.from_bytes(w.take(8), "little") if sec & 0x20 else None
    key_id = (sec >> 3) & 3
    if key_id == 1:   # only the network key carries a 1-byte key sequence number
        w.u8()
    patched = (sec & ~0x07) | crypto.SECURITY_LEVEL
    header = w.d[header_start:aux_start] + bytes([patched]) + w.d[aux_start + 1:w.pos]
    return {"aad": header, "src64": src64, "counter": counter, "secctl": patched, "key_id": key_id, "payload_start": w.pos}


def network_envelope(frame: bytes) -> dict | None:
    """CCM* parameters for a secured NWK data frame, or None if it is not one."""
    try:
        w = _Walk(frame)
        if frame[0] & 0x07 != 1:   # MAC must be a data frame
            return None
        _skip_mac(w)
        nwk_start = w.pos
        nfcf = w.u16()
        if (nfcf >> 2) & 0x0F != 2 or not (nfcf & 0x0200):   # Zigbee PRO, security on
            return None
        w.u16(); w.u16(); w.u8(); w.u8()   # dst, src, radius, seq
        if nfcf & 0x0800: w.take(8)
        if nfcf & 0x1000: w.take(8)
        if nfcf & 0x0100: w.u8()
        if nfcf & 0x0400:
            count = w.u8(); w.u8(); w.take(2 * count)
        env = _aux_security(w, nwk_start)
        env["ciphertext"] = frame[env["payload_start"]:]
        return env
    except (IndexError, ValueError):
        return None


def transport_key_envelope(frame: bytes) -> dict | None:
    """CCM* parameters for an APS Transport-Key command, or None. The NWK payload is in clear here
    (the joining device has no network key yet), so only the APS layer is secured."""
    try:
        w = _Walk(frame)
        if frame[0] & 0x07 != 1:
            return None
        _skip_mac(w)
        nfcf = w.u16()
        if (nfcf >> 2) & 0x0F != 2:
            return None
        w.u16(); w.u16(); w.u8(); w.u8()
        if nfcf & 0x0800: w.take(8)
        if nfcf & 0x1000: w.take(8)
        if nfcf & 0x0100: w.u8()
        if nfcf & 0x0400:
            count = w.u8(); w.u8(); w.take(2 * count)
        if nfcf & 0x0200:   # a secured NWK payload here is not a cleartext transport key
            return None
        aps_start = w.pos
        afcf = w.u8()
        if afcf & 0x03 != 1 or not (afcf & 0x20):   # APS command, secured
            return None
        w.u8()   # APS counter
        env = _aux_security(w, aps_start)
        if env["key_id"] != 2:   # key-transport key
            return None
        env["ciphertext"] = frame[env["payload_start"]:]
        return env
    except (IndexError, ValueError):
        return None


def recover_network_key(frame: bytes, link_key: bytes = crypto.DEFAULT_TC_LINK_KEY) -> bytes | None:
    """If this frame is a Transport-Key command decryptable with link_key, return the network key."""
    env = transport_key_envelope(frame)
    if env is None or env["src64"] is None:
        return None
    nonce = crypto.nonce(env["src64"], env["counter"], env["secctl"])
    plain = crypto.ccm_star_decrypt(crypto.transport_key_key(link_key), nonce, env["ciphertext"], env["aad"])
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


def _touchlink_command(frame: bytes) -> tuple[int, int, _Walk] | None:
    """Walk a Touchlink commissioning frame up to its command payload.

    Returns (ZCL command id, inter-PAN transaction id, walker positioned just after the transaction id),
    or None if the frame is not an inter-PAN frame on the Touchlink commissioning cluster."""
    try:
        w = _Walk(frame)
        if frame[0] & 0x07 != 1:   # MAC must be a data frame
            return None
        _skip_mac(w)
        nwk_fcf = w.u16()
        if nwk_fcf & 0x03 != 0x03:   # NWK stub: inter-PAN frame type
            return None
        aps_fcf = w.u8()
        if aps_fcf & 0x03 != 0x03:   # APS stub: inter-PAN frame type
            return None
        if (aps_fcf >> 2) & 0x03 == 0x03:   # group delivery carries a 2-byte group address first
            w.u16()
        cluster = w.u16()
        w.u16()                      # profile id
        if cluster != TOUCHLINK_CLUSTER:
            return None
        zcl_fcf = w.u8()
        if zcl_fcf & 0x03 != 0x01:   # ZCL cluster-specific command
            return None
        w.u8()                       # ZCL transaction sequence number
        command = w.u8()
        if command >= 0x40:          # commissioning commands (0x00-0x3f) all begin with a transaction id
            return None
        transaction_id = int.from_bytes(w.take(4), "little")
        return command, transaction_id, w
    except (IndexError, ValueError):
        return None


def touchlink_scan_response(frame: bytes) -> tuple[int, int] | None:
    """(inter-PAN transaction id, response id) from a Touchlink Scan Response, or None.

    The response id is needed to recover the network key from a later join on the same transaction."""
    parsed = _touchlink_command(frame)
    if parsed is None:
        return None
    command, transaction_id, w = parsed
    if command != ZLL_CMD_SCAN_RESPONSE:
        return None
    try:
        w.u8(); w.u8(); w.u8()   # rssi correction, zigbee info, zll info
        w.u16()                  # key bitmask
        response_id = int.from_bytes(w.take(4), "little")
        return transaction_id, response_id
    except (IndexError, ValueError):
        return None


def touchlink_key_transport(frame: bytes) -> dict | None:
    """{transaction_id, key_index, encrypted_key} from a Touchlink network start/join request, or None."""
    parsed = _touchlink_command(frame)
    if parsed is None:
        return None
    command, transaction_id, w = parsed
    if command not in _ZLL_KEY_TRANSPORT_COMMANDS:
        return None
    try:
        w.take(8)                # extended PAN id
        key_index = w.u8()
        encrypted_key = w.take(16)
        if len(encrypted_key) != 16:
            return None
        return {"transaction_id": transaction_id, "key_index": key_index, "encrypted_key": encrypted_key}
    except (IndexError, ValueError):
        return None


def recover_touchlink_network_key(frame: bytes, response_id: int) -> bytes | None:
    """If this frame is a Touchlink join transporting the network key, recover it with the base key its
    key index selects (the leaked ZLL master key, the public certification key, or the development key).

    `response_id` is the one seen earlier in the Scan Response of the same transaction. Returns None if
    the frame is not such a join or its key index is unsupported."""
    env = touchlink_key_transport(frame)
    if env is None:
        return None
    return crypto.zll_decrypt_network_key(env["key_index"], env["transaction_id"], response_id, env["encrypted_key"])


def decrypt_network_payload(frame: bytes, network_key: bytes) -> bytes | None:
    """Return the decrypted NWK payload (APS layer) of a secured data frame, or None."""
    env = network_envelope(frame)
    if env is None or env["src64"] is None:
        return None
    nonce = crypto.nonce(env["src64"], env["counter"], env["secctl"])
    return crypto.ccm_star_decrypt(network_key, nonce, env["ciphertext"], env["aad"])


# --- reading the decrypted payload ----------------------------------------------------------

def _zcl_values(payload: bytes) -> dict:
    """Decode a ZCL Read-Attributes-Response (0x01) or Report-Attributes (0x0a) into {attr id: int|str}.
    Integers and strings are read; other types are skipped by their length, so a wanted attribute after
    them is still reached. A truly unknown type stops the walk (its length is unknowable)."""
    out: dict = {}
    try:
        w = _Walk(payload)
        fc = w.u8()
        if fc & 0x04:   # manufacturer-specific: skip the manufacturer code
            w.u16()
        w.u8()          # transaction sequence
        command = w.u8()
        if command not in (0x01, 0x0a):
            return out
        has_status = command == 0x01
        while w.pos < len(payload):
            attr = w.u16()
            if has_status and w.u8() != 0:
                continue    # a failed read is just attribute + status, no value
            dtype = w.u8()
            if dtype in ZCL_STRING_TYPES:
                out[attr] = w.take(w.u8()).decode("utf-8", "replace").strip("\x00 ")
            elif dtype in ZCL_TYPE_LEN:
                out[attr] = int.from_bytes(w.take(ZCL_TYPE_LEN[dtype]), "little")
            else:
                break
    except (IndexError, ValueError):
        pass
    return out


def read_cluster(frame: bytes, network_key: bytes) -> tuple[int, dict] | None:
    """Decrypt a secured data frame once and return (ZCL cluster id, decoded attributes), or None."""
    payload = decrypt_network_payload(frame, network_key)
    if payload is None:
        return None
    try:
        w = _Walk(payload)
        afcf = w.u8()
        if afcf & 0x03 != 0 or afcf & 0x01:   # APS data, not group-addressed
            return None
        w.u8()             # destination endpoint
        cluster = w.u16()
        w.u16(); w.u8(); w.u8()   # profile, source endpoint, aps counter
        return cluster, _zcl_values(payload[w.pos:])
    except (IndexError, ValueError):
        return None


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


def identify(frame: bytes, network_key: bytes) -> dict | None:
    """Device identity announced in a decrypted ZCL Basic response, keyed by the NWK source address."""
    res = read_cluster(frame, network_key)
    return _basic_identity(res[1]) if res and res[0] == ZCL_BASIC_CLUSTER else None


def battery(frame: bytes, network_key: bytes) -> dict | None:
    """Battery level a device reports on the Power Configuration cluster: {percent} or {volts}, or None."""
    res = read_cluster(frame, network_key)
    return _battery(res[1]) if res and res[0] == POWER_CONFIG_CLUSTER else None


# --- APS layer: end-to-end acknowledgements and ZDO neighbour tables ----------------------------

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
        w = _Walk(payload)
        fc = w.u8()
        ftype, mode = fc & 3, (fc >> 2) & 3
        if ftype == 3:
            return None
        out: dict = {"type": APS_TYPES[ftype], "ack_req": bool(fc & 0x40)}
        if ftype == 0:
            if mode == 3:
                w.u16()           # group address
            else:
                w.u8()            # destination endpoint
            out["cluster"], out["profile"] = w.u16(), w.u16()
            w.u8()                # source endpoint
        elif ftype == 2 and not fc & 0x10:   # an acknowledgement of data echoes its endpoints, cluster and profile
            w.u8()
            out["cluster"], out["profile"] = w.u16(), w.u16()
            w.u8()
        out["counter"] = w.u8()
        if w.pos > len(payload):
            return None
        if ftype == 0 and not fc & 0x20 and not fc & 0x80:   # not secured with a link key, not fragmented
            out["payload"] = payload[w.pos:]
        return out
    except IndexError:
        return None


def mgmt_lqi(zdo: bytes) -> dict | None:
    """A Mgmt_Lqi_rsp (ZDO 0x8031): one page of the responding router's neighbour table.

    Each neighbour: its short and IEEE address, device type, relationship to the responder, depth and the
    LQI (0-255) at which the responder receives it."""
    try:
        if len(zdo) < 5 or zdo[1] != 0:   # transaction sequence number, then status: 0 = success
            return None
        total, start, count = zdo[2], zdo[3], zdo[4]
        rows = []
        for i in range(count):
            e = zdo[5 + 22 * i: 5 + 22 * (i + 1)]
            if len(e) < 22:
                return None
            flags = e[18]
            rows.append({"addr": f"0x{int.from_bytes(e[16:18], 'little'):04x}",
                         "ieee": ":".join(f"{b:02x}" for b in reversed(e[8:16])),
                         "type": LQI_DEVICE_TYPES.get(flags & 3, "unknown"),
                         "rel": LQI_RELATIONSHIPS.get((flags >> 4) & 7, "unknown"),
                         "depth": e[20], "lqi": e[21]})
        return {"total": total, "start": start, "rows": rows}
    except IndexError:
        return None


# Global ZCL commands that are themselves answers, or that never get one (Write Attributes No Response).
ZCL_GLOBAL_NO_REPLY = {0x01, 0x04, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x12, 0x14, 0x16}


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
    fc = payload[0]
    head = 5 if fc & 0x04 else 3   # a manufacturer code sits before the sequence number
    if len(payload) < head:
        return None
    seq, command = payload[head - 2], payload[head - 1]
    is_global = fc & 0x03 == 0
    expects = not fc & 0x10 and not (is_global and command in ZCL_GLOBAL_NO_REPLY)
    return {"seq": f"c{seq}", "expects": expects}


def device_info(aps: dict) -> dict | None:
    """What a decrypted ZCL report says about its sender: identity (Basic) and/or battery (Power Config)."""
    if aps.get("type") != "data" or aps.get("payload") is None or aps.get("profile") == ZDO_PROFILE:
        return None
    attrs = _zcl_values(aps["payload"])
    if aps["cluster"] == ZCL_BASIC_CLUSTER:
        return {"identity": _basic_identity(attrs), "battery": None}
    if aps["cluster"] == POWER_CONFIG_CLUSTER:
        return {"identity": None, "battery": _battery(attrs)}
    return None


def read_device(frame: bytes, network_key: bytes) -> dict | None:
    """One decrypt: whatever this ZCL report tells us about the device (identity and/or battery)."""
    res = read_cluster(frame, network_key)
    if res is None:
        return None
    cluster, attrs = res
    if cluster == ZCL_BASIC_CLUSTER:
        return {"identity": _basic_identity(attrs), "battery": None}
    if cluster == POWER_CONFIG_CLUSTER:
        return {"identity": None, "battery": _battery(attrs)}
    return None


def link_costs(frame: bytes, network_key: bytes) -> list[dict] | None:
    """A router's Link Status: each neighbour with the costs it measures (1 best … 7 worst)."""
    payload = decrypt_network_payload(frame, network_key)
    cmd = nwk_command(payload) if payload else None
    return cmd["detail"]["links"] if cmd and cmd["name"] == "link_status" else None


# NWK command identifiers (Zigbee PRO specification, § 3.4, and the R23 commissioning pair).
NWK_COMMANDS = {
    0x01: "route_request", 0x02: "route_reply", 0x03: "network_status", 0x04: "leave", 0x05: "route_record",
    0x06: "rejoin_request", 0x07: "rejoin_response", 0x08: "link_status", 0x09: "network_report",
    0x0A: "network_update", 0x0B: "ed_timeout_request", 0x0C: "ed_timeout_response", 0x0D: "link_power_delta",
    0x0E: "commissioning_request", 0x0F: "commissioning_response",
}


def _addr(w: _Walk) -> str:
    return f"0x{w.u16():04x}"


def nwk_command(payload: bytes) -> dict | None:
    """Name a decrypted NWK command payload and read the fields worth showing.

    Returns {"name", "detail"}; an unknown identifier is named "0x.." with no detail. A field that is
    cut short is left out rather than guessed."""
    if not payload:
        return None
    cid = payload[0]
    name = NWK_COMMANDS.get(cid, f"0x{cid:02x}")
    detail: dict = {}
    w = _Walk(payload[1:])
    try:
        if cid == 0x01:
            options = w.u8(); w.u8()
            detail = {"dst": _addr(w), "cost": w.u8(), "m2o": bool((options >> 3) & 3)}
        elif cid == 0x02:
            w.u8(); w.u8()
            detail = {"originator": _addr(w), "responder": _addr(w), "cost": w.u8()}
        elif cid == 0x03:
            detail = {"status": w.u8(), "addr": _addr(w)}
        elif cid == 0x04:
            options = w.u8()
            detail = {"rejoin": bool(options & 0x20), "request": bool(options & 0x40), "children": bool(options & 0x80)}
        elif cid == 0x05:
            count = w.u8()
            detail = {"relays": [_addr(w) for _ in range(count)]}
        elif cid == 0x07:
            detail = {"addr": _addr(w), "status": w.u8()}
        elif cid == 0x08:
            count = w.u8() & 0x1F
            links = []
            for _ in range(count):
                addr = _addr(w); costs = w.u8()
                links.append({"addr": addr, "incoming": costs & 0x07, "outgoing": (costs >> 4) & 0x07})
            detail = {"links": links}
        elif cid == 0x0B:
            timeout = w.u8()
            detail = {"minutes": 10 / 60 if timeout == 0 else 2 ** timeout}
        elif cid == 0x0C:
            detail = {"status": w.u8()}
    except IndexError:
        detail = {}
    if w.pos > len(w.d):   # the walker reads past the end without raising: drop a truncated read
        detail = {}
    return {"name": name, "detail": detail}


# --- building secured frames (the demo's vulnerable join, and the tests) --------------------

def _mac_data_header(seq: int, pan: int, dst: int, src: int) -> bytes:
    return bytes([0x61, 0x88, seq & 0xFF]) + pan.to_bytes(2, "little") + dst.to_bytes(2, "little") + src.to_bytes(2, "little")


def build_secured_nwk(net_key: bytes, *, seq: int, pan: int, mac_dst: int, mac_src: int,
                      nwk_dst: int, nwk_src: int, radius: int, nwk_seq: int, src64: int,
                      counter: int, payload: bytes, key_seq: int = 0, command: bool = False) -> bytes:
    """A network-key-secured NWK frame carrying `payload`: the APS layer, or with `command` a NWK command."""
    nwk = (0x0208 | (2 << 2) | (1 if command else 0)).to_bytes(2, "little") + nwk_dst.to_bytes(2, "little") + nwk_src.to_bytes(2, "little") + bytes([radius, nwk_seq])
    nwk_start_in_mac = len(_mac_data_header(seq, pan, mac_dst, mac_src))
    secctl = 0x28 | crypto.SECURITY_LEVEL   # key id 1 (network), extended nonce, level 5
    aux = bytes([secctl]) + counter.to_bytes(4, "little") + src64.to_bytes(8, "little") + bytes([key_seq])
    mac = _mac_data_header(seq, pan, mac_dst, mac_src)
    aad = mac[nwk_start_in_mac:] + nwk + aux
    ct = crypto.ccm_star_encrypt(net_key, crypto.nonce(src64, counter, secctl), payload, aad)
    return mac + nwk + aux + ct


def build_transport_key(link_key: bytes, *, seq: int, pan: int, mac_dst: int, mac_src: int,
                        coord64: int, counter: int, network_key: bytes, key_seq: int = 0) -> bytes:
    """A join's APS Transport-Key command: the network key secured with the (default) link key."""
    nwk = (0x0008 | (2 << 2)).to_bytes(2, "little") + mac_dst.to_bytes(2, "little") + mac_src.to_bytes(2, "little") + bytes([30, seq])
    aps = bytes([0x21, seq & 0xFF])   # APS command, secured; counter
    secctl = 0x30 | crypto.SECURITY_LEVEL   # key id 2 (key-transport), extended nonce, level 5
    aux = bytes([secctl]) + counter.to_bytes(4, "little") + coord64.to_bytes(8, "little")
    command = bytes([0x05, 0x01]) + network_key + bytes([key_seq]) + (0).to_bytes(8, "little") + coord64.to_bytes(8, "little")
    mac = _mac_data_header(seq, pan, mac_dst, mac_src)
    aad = aps + aux
    ct = crypto.ccm_star_encrypt(crypto.transport_key_key(link_key), crypto.nonce(coord64, counter, secctl), command, aad)
    return mac + nwk + aps + aux + ct


def _touchlink_interpan_header(seq: int, pan: int, mac_dst: int, mac_src: int, *, command: int,
                               transaction_id: int, response: bool) -> bytes:
    """MAC data header + inter-PAN NWK/APS stubs + ZCL header, up to and including the transaction id."""
    mac = _mac_data_header(seq, pan, mac_dst, mac_src)
    nwk = bytes([0x0B, 0x00])                        # inter-PAN NWK stub (frame type 3, version 2)
    aps = bytes([0x03]) + TOUCHLINK_CLUSTER.to_bytes(2, "little") + (0xC05E).to_bytes(2, "little")  # inter-PAN APS stub
    zcl = bytes([0x09 if response else 0x01, seq & 0xFF, command])   # ZCL cluster-specific command
    return mac + nwk + aps + zcl + transaction_id.to_bytes(4, "little")


def build_touchlink_scan_response(*, seq: int, pan: int, mac_dst: int, mac_src: int,
                                  transaction_id: int, response_id: int) -> bytes:
    """A Touchlink Scan Response carrying the response identifier of this commissioning transaction."""
    head = _touchlink_interpan_header(seq, pan, mac_dst, mac_src, command=ZLL_CMD_SCAN_RESPONSE,
                                      transaction_id=transaction_id, response=True)
    body = bytes([0x00, 0x12, 0x12]) + (0x1122).to_bytes(2, "little")   # rssi correction, zigbee info, zll info, key bitmask
    body += response_id.to_bytes(4, "little")
    body += (0).to_bytes(8, "little") + bytes([0x00, 0x0b]) + (pan).to_bytes(2, "little")   # ext pan id, nwk update id, channel, pan id
    body += (mac_src).to_bytes(2, "little") + bytes([0x00, 0x00])       # nwk addr, sub-devices (0), total groups
    return head + body


def build_touchlink_network_join(key_index: int, *, seq: int, pan: int, mac_dst: int, mac_src: int,
                                 transaction_id: int, response_id: int, network_key: bytes,
                                 command: int = ZLL_CMD_NETWORK_JOIN_ROUTER_REQUEST) -> bytes:
    """A Touchlink join that transports `network_key`, encrypted under the base key `key_index` selects."""
    transport_key = crypto.zll_transport_key(key_index, transaction_id, response_id)
    if transport_key is None:
        raise ValueError(f"unknown ZLL key index {key_index}")
    encrypted_key = crypto.aes_ecb(transport_key, network_key)
    head = _touchlink_interpan_header(seq, pan, mac_dst, mac_src, command=command,
                                      transaction_id=transaction_id, response=False)
    body = (0).to_bytes(8, "little") + bytes([key_index]) + encrypted_key   # ext pan id, key index, encrypted network key
    body += bytes([0x00, 0x0b]) + (pan).to_bytes(2, "little") + (mac_dst).to_bytes(2, "little")   # nwk update id, channel, pan id, nwk addr
    return head + body


def zcl_basic_response(manufacturer: str, model: str, power: int = 3, *, sw: str = "", src_ep: int = 1, seq: int = 1) -> bytes:
    """An APS-data payload: a ZCL Read-Attributes-Response on the Basic cluster."""
    def attr(attr_id: int, dtype: int, value: bytes) -> bytes:
        return attr_id.to_bytes(2, "little") + bytes([0x00, dtype]) + value
    body = bytes([0x00, seq & 0xFF, 0x01])   # ZCL header: no manufacturer, seq, Read-Attr-Response
    body += attr(ATTR_MANUFACTURER, 0x42, bytes([len(manufacturer)]) + manufacturer.encode())
    body += attr(ATTR_MODEL, 0x42, bytes([len(model)]) + model.encode())
    body += attr(ATTR_POWER_SOURCE, 0x30, bytes([power]))
    if sw:
        body += attr(ATTR_SW_BUILD, 0x42, bytes([len(sw)]) + sw.encode())
    aps = bytes([0x00, 0x01]) + ZCL_BASIC_CLUSTER.to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([src_ep, seq & 0xFF])
    return aps + body


def power_config_report(percent: int, *, src_ep: int = 1, seq: int = 1) -> bytes:
    """An APS-data payload: a ZCL Report-Attributes on Power Configuration, carrying battery percentage."""
    body = bytes([0x00, seq & 0xFF, 0x0a])   # ZCL header: no manufacturer, seq, Report Attributes
    body += ATTR_BATTERY_PERCENT.to_bytes(2, "little") + bytes([0x20, min(200, max(0, percent) * 2)])   # uint8, half-percent
    aps = bytes([0x00, 0x01]) + POWER_CONFIG_CLUSTER.to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([src_ep, seq & 0xFF])
    return aps + body


def build_link_status(net_key: bytes, *, pan: int, src: int, src64: int, counter: int, neighbours: list, seq: int = 1) -> bytes:
    """A router's Link Status NWK command with per-neighbour incoming/outgoing costs."""
    payload = bytes([0x08, 0x40 | (len(neighbours) & 0x1F)])
    for addr, incoming, outgoing in neighbours:
        payload += addr.to_bytes(2, "little") + bytes([(incoming & 0x07) | ((outgoing & 0x07) << 4)])
    nwk = (0x0209 | (2 << 2)).to_bytes(2, "little") + (0xFFFC).to_bytes(2, "little") + src.to_bytes(2, "little") + bytes([1, seq])
    secctl = 0x28 | crypto.SECURITY_LEVEL
    aux = bytes([secctl]) + counter.to_bytes(4, "little") + src64.to_bytes(8, "little") + bytes([0])
    mac = _mac_data_header(seq, pan, 0xFFFC, src)
    aad = mac[len(mac):] + nwk + aux   # broadcast: NWK header starts right after MAC
    aad = nwk + aux
    ct = crypto.ccm_star_encrypt(net_key, crypto.nonce(src64, counter, secctl), payload, aad)
    return mac + nwk + aux + ct


# --- a frame, layer by layer, for the log's detail view ------------------------------------------

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


def _hex(data: bytes) -> str:
    return data.hex(" ")


def _named(value: int, names: dict, width: int = 4) -> str:
    name = names.get(value)
    return f"0x{value:0{width}x}" + (f" ({name})" if name else "")


def dissect(frame: bytes, network_key: bytes | None = None) -> list[dict]:
    """The frame's layers, each {"layer", "fields": [[name, value], ...]}, as far as they can be read.

    Without the key it stops at the NWK security header; with it, it decrypts and reads the NWK command or the
    APS, ZDO and ZCL headers, and the attributes of read responses and reports. Field names are the
    specifications' own; anything unreadable ends the walk with the remaining bytes in hex."""
    layers: list[dict] = []
    w = _Walk(frame)
    try:
        fcf = w.u16()
        ftype, version = fcf & 7, (fcf >> 12) & 3
        dst_mode, src_mode = (fcf >> 10) & 3, (fcf >> 14) & 3
        mac = [["Frame type", MAC_FRAME_TYPES.get(ftype, f"reserved ({ftype})")], ["Security enabled", bool(fcf & 0x08)],
               ["Frame pending", bool(fcf & 0x10)], ["Acknowledgement request", bool(fcf & 0x20)],
               ["PAN ID compression", bool(fcf & 0x40)], ["Frame version", version],
               ["Destination addressing mode", ADDR_MODES[dst_mode]], ["Source addressing mode", ADDR_MODES[src_mode]]]
        layers.append({"layer": "IEEE 802.15.4 MAC", "fields": mac})
        if not (version == 2 and fcf & 0x0100):
            mac.append(["Sequence number", w.u8()])
        if ftype == 2:
            return layers
        from .frames import _pan_ids   # the 2015 PAN ID compression table lives with the header decoder
        dst_pan, src_pan = _pan_ids(version, dst_mode, src_mode, bool(fcf & 0x40))
        addr = lambda mode: f"0x{w.u16():04x}" if mode == 2 else ":".join(f"{b:02x}" for b in reversed(w.take(8)))
        if dst_pan:
            mac.append(["Destination PAN", f"0x{w.u16():04x}"])
        if dst_mode:
            mac.append(["Destination", addr(dst_mode)])
        if src_pan:
            mac.append(["Source PAN", f"0x{w.u16():04x}"])
        if src_mode:
            mac.append(["Source", addr(src_mode)])
        if fcf & 0x08 or ftype not in (0, 1, 3):
            layers.append({"layer": "Not decoded", "fields": [["Bytes", _hex(frame[w.pos:])]]})
            return layers
        if ftype == 3:
            cmd = w.u8()
            fields = [["Command", _named(cmd, MAC_COMMAND_NAMES, 2)]]
            if w.pos < len(frame):
                fields.append(["Payload", _hex(frame[w.pos:])])
            layers.append({"layer": "MAC command", "fields": fields})
            return layers
        if ftype == 0:
            layers.append({"layer": "Beacon", "fields": [["Payload", _hex(frame[w.pos:])]]})
            return layers
        if w.pos >= len(frame):
            layers.append({"layer": "Data", "fields": [["Payload", "empty (the parent had nothing for the device that polled it)"]]})
            return layers
        _dissect_nwk(frame, w, layers, network_key)
    except (IndexError, ValueError):
        layers.append({"layer": "Truncated", "fields": [["Bytes left", _hex(frame[w.pos:])]]})
    return layers


def _dissect_nwk(frame: bytes, w: _Walk, layers: list, network_key: bytes | None) -> None:
    first = frame[w.pos]
    version = (first >> 2) & 0x0F
    if version == 3:
        w.u8()
        fields = [["Frame type", "data" if first & 3 == 0 else "maintenance"], ["Protocol version", "3 (Green Power)"],
                  ["Auto-commissioning", bool(first & 0x40)]]
        if first & 0x80:
            ext = w.u8()
            fields += [["Application ID", ext & 7], ["Security level", (ext >> 3) & 3], ["Direction", "to GPD" if ext & 0x80 else "from GPD"]]
        layers.append({"layer": "Green Power", "fields": fields + [["Rest", _hex(frame[w.pos:])]]})
        return
    nwk_start = w.pos
    nfcf = w.u16()
    ntype = nfcf & 3
    nwk = [["Frame type", {0: "data", 1: "NWK command", 2: "reserved", 3: "inter-PAN"}[ntype]], ["Protocol version", version]]
    layers.append({"layer": "Zigbee NWK", "fields": nwk})
    if version != 2 or ntype == 2:
        nwk.append(["Rest", _hex(frame[w.pos:])])
        return
    if ntype == 3:
        layers.append({"layer": "Inter-PAN APS and payload", "fields": [["Bytes", _hex(frame[w.pos:])]]})
        return
    nwk += [["Discover route", (nfcf >> 6) & 3], ["Multicast", bool(nfcf & 0x0100)], ["Security", bool(nfcf & 0x0200)],
            ["Source route", bool(nfcf & 0x0400)], ["End device initiator", bool(nfcf & 0x2000)],
            ["Destination", f"0x{w.u16():04x}"], ["Source", f"0x{w.u16():04x}"], ["Radius", w.u8()], ["Sequence number", w.u8()]]
    ieee = lambda: ":".join(f"{b:02x}" for b in reversed(w.take(8)))
    if nfcf & 0x0800:
        nwk.append(["Destination IEEE", ieee()])
    if nfcf & 0x1000:
        nwk.append(["Source IEEE", ieee()])
    if nfcf & 0x0100:
        nwk.append(["Multicast control", w.u8()])
    if nfcf & 0x0400:
        count = w.u8(); index = w.u8()
        nwk.append(["Relays", ", ".join(f"0x{w.u16():04x}" for _ in range(count)) + f" (index {index})"])
    if not nfcf & 0x0200:
        _dissect_aps(frame[w.pos:], layers, ntype)
        return
    env = network_envelope(frame)
    sec = frame[w.pos]
    fields = [["Security level", "5 (ENC-MIC-32, sent as 0)"], ["Key identifier", {0: "data key", 1: "network key", 2: "key-transport key", 3: "key-load key"}[(sec >> 3) & 3]],
              ["Extended nonce", bool(sec & 0x20)], ["Frame counter", env["counter"] if env else "?"]]
    if env and env["src64"] is not None:
        fields.append(["Source IEEE", ":".join(f"{b:02x}" for b in env["src64"].to_bytes(8, "big"))])
    layers.append({"layer": "NWK security", "fields": fields})
    if network_key is None:
        fields.append(["Payload", "encrypted (no network key)"])
        return
    plain = decrypt_network_payload(frame, network_key)
    if plain is None:
        fields.append(["Payload", "the network key does not decrypt it"])
        return
    fields.append(["Payload", "decrypted with the network key"])
    _dissect_aps(plain, layers, ntype)


def _dissect_aps(payload: bytes, layers: list, ntype: int) -> None:
    if ntype == 1:
        cmd = nwk_command(payload)
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
    aps = aps_header(payload)
    if aps is None:
        layers.append({"layer": "APS", "fields": [["Bytes", _hex(payload)]]})
        return
    fc = payload[0]
    fields = [["Frame type", aps["type"]], ["Delivery mode", {0: "unicast", 1: "indirect", 2: "broadcast", 3: "group"}[(fc >> 2) & 3]],
              ["Acknowledgement request", aps["ack_req"]], ["Security (link key)", bool(fc & 0x20)], ["Extended header", bool(fc & 0x80)]]
    profile, cluster = aps.get("profile"), aps.get("cluster")
    if cluster is not None:
        names = ZDO_CLUSTERS if profile == ZDO_PROFILE else CLUSTERS
        base = names.get(cluster & 0x7FFF if profile == ZDO_PROFILE else cluster)
        label = (base + ("_rsp" if cluster & 0x8000 else "_req") if profile == ZDO_PROFILE and base and cluster != 0x0013 else base)
        fields += [["Cluster", f"0x{cluster:04x}" + (f" ({label})" if label else "")], ["Profile", _named(profile, PROFILES)]]
    fields.append(["APS counter", aps["counter"]])
    layers.append({"layer": "APS", "fields": fields})
    body = aps.get("payload")
    if body is None:
        rest = "encrypted with a link key" if fc & 0x20 else ""
        if rest:
            layers.append({"layer": "APS payload", "fields": [["Payload", rest]]})
        return
    if profile == ZDO_PROFILE:
        z = [["Transaction sequence", body[0] if body else "?"], ["Bytes", _hex(body[1:])]]
        if cluster == MGMT_LQI_RSP:
            table = mgmt_lqi(body)
            if table:
                z.insert(1, ["Neighbours", "; ".join(f"{r['addr']} {r['type']} {r['rel']} LQI {r['lqi']}" for r in table["rows"])])
        layers.append({"layer": "ZDO", "fields": z})
        return
    _dissect_zcl(body, layers)


def _dissect_zcl(body: bytes, layers: list) -> None:
    if len(body) < 3:
        layers.append({"layer": "ZCL", "fields": [["Bytes", _hex(body)]]})
        return
    fc = body[0]
    head = 5 if fc & 0x04 else 3
    is_global = fc & 3 == 0
    command = body[head - 1]
    fields = [["Frame type", "global" if is_global else "cluster-specific"], ["Direction", "server to client" if fc & 0x08 else "client to server"],
              ["Disable default response", bool(fc & 0x10)]]
    if fc & 0x04:
        fields.append(["Manufacturer code", f"0x{int.from_bytes(body[1:3], 'little'):04x}"])
    fields += [["Transaction sequence", body[head - 2]], ["Command", _named(command, ZCL_GLOBAL, 2) if is_global else f"0x{command:02x}"]]
    if is_global and command in (0x01, 0x0A):
        values = _zcl_values(body)
        if values:
            fields.append(["Attributes", "; ".join(f"0x{k:04x} = {v}" for k, v in values.items())])
    fields.append(["Payload", _hex(body[head:]) or "none"])
    layers.append({"layer": "ZCL", "fields": fields})
