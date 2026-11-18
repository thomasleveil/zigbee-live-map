"""Build well-formed frames, for the demo mode and the tests. The inverse of what wire.py and decode.py read.

Two families. The first writes clear headers around a random payload (addresses are the texts the rest of
the tool uses, "0x1a62"): enough for everything the map shows without a key. The second really secures its
payload with a key (addresses are integers), so that decryption, key recovery and the decoders behind them
can be exercised end to end.
"""

from __future__ import annotations

import os

from . import crypto
from .decode import (ATTR_BATTERY_PERCENT, ATTR_MANUFACTURER, ATTR_MODEL, ATTR_POWER_SOURCE, ATTR_SW_BUILD,
                     POWER_CONFIG_CLUSTER, TOUCHLINK_CLUSTER, ZCL_BASIC_CLUSTER, ZLL_CMD_NETWORK_JOIN_ROUTER_REQUEST,
                     ZLL_CMD_SCAN_RESPONSE)

HOME_AUTOMATION_PROFILE, ZLL_PROFILE = 0x0104, 0xC05E
ZCL_FROM_SERVER = 0x18   # a global command a device sends about its own attributes: server to client, no default response wanted


def short_bytes(addr: str) -> bytes:
    return int(addr, 16).to_bytes(2, "little")


def ieee_bytes(addr: str) -> bytes:
    return bytes(reversed(bytes.fromhex(addr.replace(":", ""))))


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "little")


# --- clear headers around a random payload ---------------------------------------------------------

def build_ack(seq: int, pending: bool = False) -> bytes:
    return bytes([0x12 if pending else 0x02, 0x00, seq & 0xFF])


def build_empty_data(seq: int, pan: str, parent: str, child: str) -> bytes:
    """A parent's empty data frame: it set frame pending in its acknowledgement, then had nothing to send."""
    return bytes([0x41, 0x88, seq & 0xFF]) + short_bytes(pan) + short_bytes(child) + short_bytes(parent)


def build_inter_pan(seq: int, src_pan: str, src64: str, payload: bytes = b"\x0b\x00\x00") -> bytes:
    """An inter-PAN broadcast (Touchlink scan request shape): destination PAN and address 0xffff, extended source."""
    return bytes([0x01, 0xC8, seq & 0xFF]) + b"\xff\xff\xff\xff" + short_bytes(src_pan) + ieee_bytes(src64) + b"\x0b\x00" + payload


def build_gpdf(seq: int, src_id: int, payload: bytes = b"\x00\x00\x00\x00\x20") -> bytes:
    """A Green Power data frame: broadcast, no MAC source, application id 0 so the source id travels in clear."""
    return bytes([0x01, 0x08, seq & 0xFF]) + b"\xff\xff\xff\xff" + b"\x0c" + src_id.to_bytes(4, "little") + payload


def build_poll(seq: int, pan: str, parent: str, child: str) -> bytes:
    """MAC data request: a sleeping end device asks its parent for pending messages."""
    return bytes([0x63, 0x88, seq & 0xFF]) + short_bytes(pan) + short_bytes(parent) + short_bytes(child) + b"\x04"


def build_beacon_request(seq: int) -> bytes:
    return bytes([0x03, 0x08, seq & 0xFF]) + b"\xff\xff\xff\xff\x07"


def build_beacon(seq: int, pan: str, src: str, epid: str, zr: bool, zed: bool, permit: bool, depth: int = 1) -> bytes:
    superframe = 0x4FFF | (0x8000 if permit else 0)
    caps = (0x04 if zr else 0) | ((depth & 0x0F) << 3) | (0x80 if zed else 0)
    payload = bytes([0x00, 0x22, caps]) + ieee_bytes(epid) + b"\xff\xff\xff\x00"
    return bytes([0x00, 0x80, seq & 0xFF]) + short_bytes(pan) + short_bytes(src) + _u16(superframe) + b"\x00\x00" + payload


def build_nwk(seq: int, pan: str, mac_dst: str, mac_src: str, *, command: bool, nwk_dst: str, nwk_src: str,
              radius: int, nwk_seq: int, hop_ieee: str, payload_len: int = 12, relays: list[str] | None = None) -> bytes:
    """A secured Zigbee NWK frame. hop_ieee is the device transmitting this hop (it secures the frame)."""
    to_all = mac_dst == "0xffff"
    mac = bytes([0x41 if to_all else 0x61, 0x88, seq & 0xFF]) + short_bytes(pan) + short_bytes(mac_dst) + short_bytes(mac_src)
    fcf = (1 if command else 0) | (2 << 2) | 0x0200 | (0x0400 if relays else 0)
    nwk = _u16(fcf) + short_bytes(nwk_dst) + short_bytes(nwk_src) + bytes([radius & 0xFF, nwk_seq & 0xFF])
    if relays:
        nwk += bytes([len(relays), len(relays) - 1]) + b"".join(short_bytes(r) for r in relays)
    aux = b"\x28" + os.urandom(4) + ieee_bytes(hop_ieee) + b"\x00"
    return mac + nwk + aux + os.urandom(payload_len + 4)


# --- frames really secured with a key ---------------------------------------------------------------

def _mac_data_header(seq: int, pan: int, dst: int, src: int) -> bytes:
    return bytes([0x61, 0x88, seq & 0xFF]) + _u16(pan) + _u16(dst) + _u16(src)


def _secured_nwk(net_key: bytes, nwk: bytes, src64: int, counter: int, payload: bytes, key_seq: int = 0) -> bytes:
    """A NWK header followed by its security header and the payload sealed under the network key.
    CCM* authenticates the NWK header and the security header; the MAC header is outside."""
    secctl = 0x28 | crypto.SECURITY_LEVEL   # key id 1 (network), extended nonce, level 5
    aux = bytes([secctl]) + counter.to_bytes(4, "little") + src64.to_bytes(8, "little") + bytes([key_seq])
    return nwk + aux + crypto.ccm_star_encrypt(net_key, crypto.nonce(src64, counter, secctl), payload, nwk + aux)


def build_secured_nwk(net_key: bytes, *, seq: int, pan: int, mac_dst: int, mac_src: int,
                      nwk_dst: int, nwk_src: int, radius: int, nwk_seq: int, src64: int,
                      counter: int, payload: bytes, key_seq: int = 0, command: bool = False) -> bytes:
    """A network-key-secured NWK frame carrying `payload`: the APS layer, or with `command` a NWK command."""
    nwk = _u16(0x0208 | (1 if command else 0)) + _u16(nwk_dst) + _u16(nwk_src) + bytes([radius, nwk_seq])
    return _mac_data_header(seq, pan, mac_dst, mac_src) + _secured_nwk(net_key, nwk, src64, counter, payload, key_seq)


def build_link_status(net_key: bytes, *, pan: int, src: int, src64: int, counter: int, neighbours: list, seq: int = 1) -> bytes:
    """A router's Link Status NWK command with per-neighbour incoming/outgoing costs."""
    payload = bytes([0x08, 0x40 | (len(neighbours) & 0x1F)])
    for addr, incoming, outgoing in neighbours:
        payload += _u16(addr) + bytes([(incoming & 0x07) | ((outgoing & 0x07) << 4)])
    nwk = _u16(0x0209) + _u16(0xFFFC) + _u16(src) + bytes([1, seq])
    return _mac_data_header(seq, pan, 0xFFFC, src) + _secured_nwk(net_key, nwk, src64, counter, payload)


def build_transport_key(link_key: bytes, *, seq: int, pan: int, mac_dst: int, mac_src: int,
                        coord64: int, counter: int, network_key: bytes, key_seq: int = 0) -> bytes:
    """A join's APS Transport-Key command: the network key secured with the (default) link key."""
    nwk = _u16(0x0008) + _u16(mac_dst) + _u16(mac_src) + bytes([30, seq])
    aps = bytes([0x21, seq & 0xFF])   # APS command, secured; counter
    secctl = 0x30 | crypto.SECURITY_LEVEL   # key id 2 (key-transport), extended nonce, level 5
    aux = bytes([secctl]) + counter.to_bytes(4, "little") + coord64.to_bytes(8, "little")
    command = bytes([0x05, 0x01]) + network_key + bytes([key_seq]) + (0).to_bytes(8, "little") + coord64.to_bytes(8, "little")
    ct = crypto.ccm_star_encrypt(crypto.transport_key_key(link_key), crypto.nonce(coord64, counter, secctl), command, aps + aux)
    return _mac_data_header(seq, pan, mac_dst, mac_src) + nwk + aps + aux + ct


def _touchlink_interpan_header(seq: int, pan: int, mac_dst: int, mac_src: int, *, command: int,
                               transaction_id: int, response: bool) -> bytes:
    """MAC data header + inter-PAN NWK/APS stubs + ZCL header, up to and including the transaction id."""
    mac = _mac_data_header(seq, pan, mac_dst, mac_src)
    nwk = bytes([0x0B, 0x00])                        # inter-PAN NWK stub (frame type 3, version 2)
    aps = bytes([0x03]) + _u16(TOUCHLINK_CLUSTER) + _u16(ZLL_PROFILE)   # inter-PAN APS stub
    zcl = bytes([0x09 if response else 0x01, seq & 0xFF, command])   # ZCL cluster-specific command
    return mac + nwk + aps + zcl + transaction_id.to_bytes(4, "little")


def build_touchlink_scan_response(*, seq: int, pan: int, mac_dst: int, mac_src: int,
                                  transaction_id: int, response_id: int) -> bytes:
    """A Touchlink Scan Response carrying the response identifier of this commissioning transaction."""
    head = _touchlink_interpan_header(seq, pan, mac_dst, mac_src, command=ZLL_CMD_SCAN_RESPONSE,
                                      transaction_id=transaction_id, response=True)
    body = bytes([0x00, 0x12, 0x12]) + _u16(0x1122)   # rssi correction, zigbee info, zll info, key bitmask
    body += response_id.to_bytes(4, "little")
    body += (0).to_bytes(8, "little") + bytes([0x00, 0x0b]) + _u16(pan)   # ext pan id, nwk update id, channel, pan id
    body += _u16(mac_src) + bytes([0x00, 0x00])       # nwk addr, sub-devices (0), total groups
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
    body += bytes([0x00, 0x0b]) + _u16(pan) + _u16(mac_dst)   # nwk update id, channel, pan id, nwk addr
    return head + body


# --- APS payloads to put in a secured NWK frame -----------------------------------------------------

def _aps_data(cluster: int, src_ep: int, counter: int) -> bytes:
    """An APS data header, unicast to endpoint 1, on the Home Automation profile."""
    return bytes([0x00, 0x01]) + _u16(cluster) + _u16(HOME_AUTOMATION_PROFILE) + bytes([src_ep, counter & 0xFF])


def zcl_basic_response(manufacturer: str, model: str, power: int = 3, *, sw: str = "", src_ep: int = 1, seq: int = 1) -> bytes:
    """An APS-data payload: a ZCL Read-Attributes-Response on the Basic cluster."""
    def attr(attr_id: int, dtype: int, value: bytes) -> bytes:
        return _u16(attr_id) + bytes([0x00, dtype]) + value
    body = bytes([ZCL_FROM_SERVER, seq & 0xFF, 0x01])   # ZCL header, seq, Read-Attr-Response
    body += attr(ATTR_MANUFACTURER, 0x42, bytes([len(manufacturer)]) + manufacturer.encode())
    body += attr(ATTR_MODEL, 0x42, bytes([len(model)]) + model.encode())
    body += attr(ATTR_POWER_SOURCE, 0x30, bytes([power]))
    if sw:
        body += attr(ATTR_SW_BUILD, 0x42, bytes([len(sw)]) + sw.encode())
    return _aps_data(ZCL_BASIC_CLUSTER, src_ep, seq) + body


def power_config_report(percent: int, *, src_ep: int = 1, seq: int = 1) -> bytes:
    """An APS-data payload: a ZCL Report-Attributes on Power Configuration, carrying battery percentage."""
    body = bytes([ZCL_FROM_SERVER, seq & 0xFF, 0x0a])   # ZCL header, seq, Report Attributes
    body += _u16(ATTR_BATTERY_PERCENT) + bytes([0x20, min(200, max(0, percent) * 2)])   # uint8, half-percent
    return _aps_data(POWER_CONFIG_CLUSTER, src_ep, seq) + body


def manufacturer_command(cluster: int, manufacturer: int, command: int, payload: bytes, *, src_ep: int = 1, seq: int = 1) -> bytes:
    """An APS-data payload: a manufacturer-specific command of a cluster, sent to the device (client to server)."""
    return _aps_data(cluster, src_ep, seq) + bytes([0x05]) + _u16(manufacturer) + bytes([seq & 0xFF, command]) + payload
