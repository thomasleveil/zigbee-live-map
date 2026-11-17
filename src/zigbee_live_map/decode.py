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
    if payload is None or not payload or payload[0] != 0x08:   # NWK command 0x08 = Link Status
        return None
    try:
        w = _Walk(payload); w.u8()
        options = w.u8(); count = options & 0x1F
        rows = []
        for _ in range(count):
            addr = w.u16(); costs = w.u8()
            rows.append({"addr": f"0x{addr:04x}", "incoming": costs & 0x07, "outgoing": (costs >> 4) & 0x07})
        return rows
    except (IndexError, ValueError):
        return None


# --- building secured frames (the demo's vulnerable join, and the tests) --------------------

def _mac_data_header(seq: int, pan: int, dst: int, src: int) -> bytes:
    return bytes([0x61, 0x88, seq & 0xFF]) + pan.to_bytes(2, "little") + dst.to_bytes(2, "little") + src.to_bytes(2, "little")


def build_secured_nwk(net_key: bytes, *, seq: int, pan: int, mac_dst: int, mac_src: int,
                      nwk_dst: int, nwk_src: int, radius: int, nwk_seq: int, src64: int,
                      counter: int, payload: bytes, key_seq: int = 0) -> bytes:
    """A network-key-secured NWK data frame carrying `payload` (the APS layer)."""
    nwk = (0x0208 | (2 << 2)).to_bytes(2, "little") + nwk_dst.to_bytes(2, "little") + nwk_src.to_bytes(2, "little") + bytes([radius, nwk_seq])
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
