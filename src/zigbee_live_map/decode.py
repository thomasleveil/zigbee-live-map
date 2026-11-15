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
POWER_SOURCE = {0: "unknown", 1: "mains", 2: "mains", 3: "battery", 4: "rechargeable"}


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


def decrypt_network_payload(frame: bytes, network_key: bytes) -> bytes | None:
    """Return the decrypted NWK payload (APS layer) of a secured data frame, or None."""
    env = network_envelope(frame)
    if env is None or env["src64"] is None:
        return None
    nonce = crypto.nonce(env["src64"], env["counter"], env["secctl"])
    return crypto.ccm_star_decrypt(network_key, nonce, env["ciphertext"], env["aad"])


# --- reading the decrypted payload ----------------------------------------------------------

def _zcl_basic_attrs(payload: bytes) -> dict:
    """Pull manufacturer / model / power source from a ZCL Read-Attributes-Response on Basic."""
    out: dict = {}
    try:
        w = _Walk(payload)
        frame_control = w.u8()
        if frame_control & 0x04:   # manufacturer-specific: skip manufacturer code
            w.u16()
        w.u8()   # transaction sequence
        command = w.u8()
        if command != 0x01:   # Read Attributes Response
            return out
        while w.pos < len(payload):
            attr = w.u16(); status = w.u8()
            if status != 0:
                continue
            dtype = w.u8()
            if dtype in (0x41, 0x42):   # octet / character string
                length = w.u8(); value = w.take(length)
                text = value.decode("utf-8", "replace").strip("\x00 ")
                if attr == ATTR_MANUFACTURER: out["manufacturer"] = text
                elif attr == ATTR_MODEL: out["model"] = text
            elif dtype in (0x20, 0x30):   # uint8 / enum8
                value = w.u8()
                if attr == ATTR_POWER_SOURCE: out["power"] = POWER_SOURCE.get(value & 0x7F, "unknown")
            else:
                break   # unknown type: cannot keep walking safely
    except (IndexError, ValueError):
        pass
    return out


def identify(frame: bytes, network_key: bytes) -> dict | None:
    """Device identity announced in a decrypted ZCL Basic response, keyed by the NWK source address."""
    payload = decrypt_network_payload(frame, network_key)
    if payload is None:
        return None
    try:
        w = _Walk(payload)
        afcf = w.u8()
        if afcf & 0x03 != 0:   # APS data
            return None
        if afcf & 0x01:   # group addressing, no destination endpoint
            return None
        w.u8()   # destination endpoint
        cluster = w.u16()
        if cluster != ZCL_BASIC_CLUSTER:
            return None
        w.u16(); w.u8(); w.u8()   # profile, source endpoint, aps counter
        attrs = _zcl_basic_attrs(payload[w.pos:])
        return attrs or None
    except (IndexError, ValueError):
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


def zcl_basic_response(manufacturer: str, model: str, power: int = 3, *, src_ep: int = 1, seq: int = 1) -> bytes:
    """An APS-data payload: a ZCL Read-Attributes-Response on the Basic cluster."""
    def attr(attr_id: int, dtype: int, value: bytes) -> bytes:
        return attr_id.to_bytes(2, "little") + bytes([0x00, dtype]) + value
    body = bytes([0x00, seq & 0xFF, 0x01])   # ZCL header: no manufacturer, seq, Read-Attr-Response
    body += attr(ATTR_MANUFACTURER, 0x42, bytes([len(manufacturer)]) + manufacturer.encode())
    body += attr(ATTR_MODEL, 0x42, bytes([len(model)]) + model.encode())
    body += attr(ATTR_POWER_SOURCE, 0x30, bytes([power]))
    aps = bytes([0x00, 0x01]) + ZCL_BASIC_CLUSTER.to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([src_ep, seq & 0xFF])
    return aps + body


def build_link_status(net_key: bytes, *, pan: int, src: int, src64: int, counter: int, neighbours: list, seq: int = 1) -> bytes:
    """A router's Link Status NWK command with per-neighbour incoming/outgoing costs."""
    payload = bytes([0x08, 0x40 | (len(neighbours) & 0x1F)])
    for addr, incoming, outgoing in neighbours:
        payload += addr.to_bytes(2, "little") + bytes([(incoming & 0x07) | ((outgoing & 0x07) << 4)])
    nwk = (0x020A | (2 << 2)).to_bytes(2, "little") + (0xFFFC).to_bytes(2, "little") + src.to_bytes(2, "little") + bytes([1, seq])
    secctl = 0x28 | crypto.SECURITY_LEVEL
    aux = bytes([secctl]) + counter.to_bytes(4, "little") + src64.to_bytes(8, "little") + bytes([0])
    mac = _mac_data_header(seq, pan, 0xFFFC, src)
    aad = mac[len(mac):] + nwk + aux   # broadcast: NWK header starts right after MAC
    aad = nwk + aux
    ct = crypto.ccm_star_encrypt(net_key, crypto.nonce(src64, counter, secctl), payload, aad)
    return mac + nwk + aux + ct
