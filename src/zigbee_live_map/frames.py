"""Decode the clear-text headers of a Zigbee frame and turn it into one event for the map.

Input is an IEEE 802.15.4 frame without its FCS. Two layers are readable without any key:
  - MAC (802.15.4): who transmits this radio hop and who should receive it;
  - NWK (Zigbee): who created the message, who it is finally for, how many hops remain (radius),
    and the IEEE address of the device that secured this hop.
Everything after the NWK security header is encrypted and is left untouched, so NWK commands are
classified from their shape (destination, radius). The page marks those guesses as "probable".

The build_* helpers are the inverse of parse(): they produce well-formed frames with a random
payload, for the demo mode and the tests.
"""

from __future__ import annotations

import os

BROADCASTS = {"0xffff", "0xfffd", "0xfffc", "0xfffb"}
MAC_COMMANDS = {0x01: "join", 0x02: "join", 0x04: "poll", 0x07: "beacon_req"}


class _Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data, self.pos = data, pos

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("frame too short")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def short(self) -> str:
        return f"0x{int.from_bytes(self.take(2), 'little'):04x}"

    def ieee(self) -> str:
        return ":".join(f"{b:02x}" for b in reversed(self.take(8)))

    def addr(self, mode: int) -> str:
        return self.short() if mode == 2 else self.ieee()


def parse(frame: bytes) -> dict:
    """Return the readable header fields. 'kind' is ack, beacon, cmd, data or bad."""
    out: dict = {"kind": "bad"}
    if len(frame) < 3:
        return out
    fcf = int.from_bytes(frame[0:2], "little")
    ftype, ack_req, pan_comp = fcf & 7, bool(fcf & 0x20), bool(fcf & 0x40)
    dst_mode, src_mode = (fcf >> 10) & 3, (fcf >> 14) & 3
    out.update(seq=frame[2], ack_req=ack_req)
    if ftype == 2:
        out["kind"] = "ack"
        return out
    if ftype not in (0, 1, 3) or fcf & 0x08 or 1 in (dst_mode, src_mode):
        return out  # MAC-layer security or reserved modes: not Zigbee
    rd = _Reader(frame, 3)
    try:
        if dst_mode:
            out["pan"] = rd.short()
            out["mdst"] = rd.addr(dst_mode)
        if src_mode:
            if not pan_comp:
                out["pan"] = rd.short()
            out["msrc"] = rd.addr(src_mode)
        if ftype == 0:
            out["kind"] = "beacon"
            out["beacon"] = _parse_beacon(rd)
        elif ftype == 3:
            out["kind"] = "cmd"
            out["cmd"] = rd.u8()
            if out["cmd"] == 0x02:  # association response: assigned short address + status, in clear
                rd.take(2)
                out["assoc_status"] = rd.u8()
        else:
            out["kind"] = "data"
            out["nwk"] = _parse_nwk(rd)
    except ValueError:
        out["kind"] = "bad"
    return out


def _parse_beacon(rd: _Reader) -> dict:
    superframe = int.from_bytes(rd.take(2), "little")
    gts = rd.u8()
    if gts & 7:
        rd.take(1 + 3 * (gts & 7))
    pending = rd.u8()
    rd.take(2 * (pending & 7) + 8 * ((pending >> 4) & 7))
    info: dict = {"permit": bool(superframe & 0x8000)}
    if rd.u8() != 0:  # protocol id 0 = Zigbee
        return info
    rd.u8()  # stack profile + protocol version
    caps = rd.u8()
    info.update(zr=bool(caps & 0x04), zed=bool(caps & 0x80), depth=(caps >> 3) & 0x0F, epid=rd.ieee())
    return info


def _parse_nwk(rd: _Reader) -> dict | None:
    fcf = int.from_bytes(rd.take(2), "little")
    if (fcf >> 2) & 0x0F != 2:  # protocol version 2 = Zigbee PRO; 3 is Green Power
        return None
    nwk: dict = {"type": fcf & 3, "dst": rd.short(), "src": rd.short(), "radius": rd.u8(), "seq": rd.u8()}
    if fcf & 0x0800:
        nwk["dst64"] = rd.ieee()
    if fcf & 0x1000:
        nwk["src64"] = rd.ieee()
    if fcf & 0x0100:
        rd.u8()  # multicast control
    if fcf & 0x0400:  # source route: the full relay list travels in clear
        count = rd.u8()
        rd.u8()  # relay index
        nwk["relays"] = [rd.short() for _ in range(count)]
    if fcf & 0x0200:  # security header: frame counter, then the IEEE of the device that secured this hop
        control = rd.u8()
        rd.take(4)
        if control & 0x20:
            nwk["sec64"] = rd.ieee()
    return nwk


class Classifier:
    """Stateful: an acknowledgement carries no address, so it is attributed to the frame it answers."""

    def __init__(self) -> None:
        self.count = 0
        self._awaiting_ack: dict | None = None

    def event(self, frame: bytes, ts: float, rssi: int | None = None) -> dict:
        self.count += 1
        p = parse(frame)
        ev: dict = {"n": self.count, "t": round(ts, 4), "len": len(frame), "cat": "other"}
        if rssi is not None:
            ev["rssi"] = rssi
        kind = p["kind"]
        if kind == "ack":
            ev["cat"] = "ack"
            waiting = self._awaiting_ack
            if waiting and waiting["seq"] == p["seq"]:
                ev["ms"], ev["md"] = waiting["dst"], waiting["src"]
            return ev
        if kind == "bad":
            return ev
        for src_key, key in (("msrc", "ms"), ("mdst", "md"), ("pan", "pan")):
            if src_key in p:
                ev[key] = p[src_key]
        if p["ack_req"] and "msrc" in p and p.get("mdst") not in (None, "0xffff"):
            self._awaiting_ack = {"seq": p["seq"], "src": p["msrc"], "dst": p["mdst"]}
        if kind == "beacon":
            ev["cat"] = "beacon"
            ev["bcn"] = p["beacon"]
        elif kind == "cmd":
            ev["cat"] = MAC_COMMANDS.get(p["cmd"], "mac_cmd")
            ev["cmd"] = p["cmd"]
            if "assoc_status" in p:
                ev["st"] = p["assoc_status"]
        elif p["nwk"]:
            self._classify_nwk(ev, p["nwk"])
        return ev

    @staticmethod
    def _classify_nwk(ev: dict, nwk: dict) -> None:
        ev.update(ns=nwk["src"], nd=nwk["dst"], r=nwk["radius"])
        if "sec64" in nwk:
            ev["ieee"] = nwk["sec64"]
        if "relays" in nwk:
            ev["relays"] = nwk["relays"]
        if nwk["type"] == 1:  # NWK command, identifier encrypted
            if nwk["dst"] == "0xfffc":
                ev["cat"] = "link_status" if nwk["radius"] == 1 else "route_request"
            elif nwk["dst"] == "0x0000":
                ev["cat"] = "route_record"
            else:
                ev["cat"] = "nwk_cmd"
        elif nwk["type"] == 0:
            if nwk["dst"] in BROADCASTS:
                ev["cat"] = "broadcast"
            elif ev.get("ms") != nwk["src"] or ev.get("md") != nwk["dst"]:
                ev["cat"] = "data_multihop"
            else:
                ev["cat"] = "data_direct"


# ---------------------------------------------------------------------------------------------
# Frame builders (demo mode and tests)
# ---------------------------------------------------------------------------------------------

def _short(addr: str) -> bytes:
    return int(addr, 16).to_bytes(2, "little")


def _ieee(addr: str) -> bytes:
    return bytes(reversed(bytes.fromhex(addr.replace(":", ""))))


def build_ack(seq: int) -> bytes:
    return bytes([0x02, 0x00, seq & 0xFF])


def build_poll(seq: int, pan: str, parent: str, child: str) -> bytes:
    """MAC data request: a sleeping end device asks its parent for pending messages."""
    return bytes([0x63, 0x88, seq & 0xFF]) + _short(pan) + _short(parent) + _short(child) + b"\x04"


def build_beacon_request(seq: int) -> bytes:
    return bytes([0x03, 0x08, seq & 0xFF]) + b"\xff\xff\xff\xff\x07"


def build_beacon(seq: int, pan: str, src: str, epid: str, zr: bool, zed: bool, permit: bool, depth: int = 1) -> bytes:
    superframe = 0x4FFF | (0x8000 if permit else 0)
    caps = (0x04 if zr else 0) | ((depth & 0x0F) << 3) | (0x80 if zed else 0)
    payload = bytes([0x00, 0x22, caps]) + _ieee(epid) + b"\xff\xff\xff\x00"
    return bytes([0x00, 0x80, seq & 0xFF]) + _short(pan) + _short(src) + superframe.to_bytes(2, "little") + b"\x00\x00" + payload


def build_nwk(seq: int, pan: str, mac_dst: str, mac_src: str, *, command: bool, nwk_dst: str, nwk_src: str,
              radius: int, nwk_seq: int, hop_ieee: str, payload_len: int = 12, relays: list[str] | None = None) -> bytes:
    """A secured Zigbee NWK frame. hop_ieee is the device transmitting this hop (it secures the frame)."""
    to_all = mac_dst == "0xffff"
    mac = bytes([0x41 if to_all else 0x61, 0x88, seq & 0xFF]) + _short(pan) + _short(mac_dst) + _short(mac_src)
    fcf = (1 if command else 0) | (2 << 2) | 0x0200 | (0x0400 if relays else 0)
    nwk = fcf.to_bytes(2, "little") + _short(nwk_dst) + _short(nwk_src) + bytes([radius & 0xFF, nwk_seq & 0xFF])
    if relays:
        nwk += bytes([len(relays), len(relays) - 1]) + b"".join(_short(r) for r in relays)
    aux = b"\x28" + os.urandom(4) + _ieee(hop_ieee) + b"\x00"
    return mac + nwk + aux + os.urandom(payload_len + 4)


def read_pcap(path: str):
    """Yield (timestamp, frame) from a little-endian pcap with linktype 230 (802.15.4 without FCS)."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24 or header[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError(f"{path}: not a little-endian pcap")
        linktype = int.from_bytes(header[20:24], "little")
        if linktype not in (230, 195):
            raise ValueError(f"{path}: linktype {linktype} is not IEEE 802.15.4")
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec = int.from_bytes(rec[0:4], "little")
            usec = int.from_bytes(rec[4:8], "little")
            size = int.from_bytes(rec[8:12], "little")
            frame = fh.read(size)
            yield sec + usec / 1e6, frame[:-2] if linktype == 195 else frame  # 195 carries the FCS
