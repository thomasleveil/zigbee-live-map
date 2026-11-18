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
    """Return the readable header fields. 'kind' is ack, beacon, cmd, data, empty or bad.

    The MAC header follows IEEE 802.15.4-2015 § 7.2: frame versions 0 and 1 (2003/2006, what Zigbee sends)
    and 2 (2015, which may suppress the sequence number, carry information elements and compress PAN ids
    by the table of § 7.2.2.6). 'empty' is a data frame with no payload at all: § 6.7.3 lets a parent
    answer a data request that way when, after all, it has nothing for the device that polled."""
    out: dict = {"kind": "bad"}
    if len(frame) < 2:
        return out
    fcf = int.from_bytes(frame[0:2], "little")
    ftype, version = fcf & 7, (fcf >> 12) & 3
    dst_mode, src_mode = (fcf >> 10) & 3, (fcf >> 14) & 3
    out.update(ack_req=bool(fcf & 0x20), pending=bool(fcf & 0x10))
    rd = _Reader(frame, 2)
    try:
        if not (version == 2 and fcf & 0x0100):   # sequence number suppression exists from 2015 on
            out["seq"] = rd.u8()
        if ftype == 2:
            out["kind"] = "ack"
            return out
        if ftype not in (0, 1, 3) or fcf & 0x08 or version == 3 or 1 in (dst_mode, src_mode):
            return out  # MAC security, frame types and modes Zigbee never uses, reserved version: not Zigbee
        dst_pan, src_pan = _pan_ids(version, dst_mode, src_mode, bool(fcf & 0x40))
        if dst_pan:
            out["pan"] = rd.short()
        if dst_mode:
            out["mdst"] = rd.addr(dst_mode)
        if src_pan:
            out["pan"] = rd.short()
        if src_mode:
            out["msrc"] = rd.addr(src_mode)
        if version == 2 and fcf & 0x0200:
            _skip_ies(rd)
        if ftype == 0:
            out["kind"] = "beacon"
            out["beacon"] = _parse_beacon(rd)
        elif ftype == 3:
            out["kind"] = "cmd"
            out["cmd"] = rd.u8()
            if out["cmd"] == 0x02:  # association response: assigned short address + status, in clear
                rd.take(2)
                out["assoc_status"] = rd.u8()
        elif rd.pos == len(frame):
            out["kind"] = "empty"
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


def _pan_ids(version: int, dst_mode: int, src_mode: int, compressed: bool) -> tuple[bool, bool]:
    """(destination PAN id present, source PAN id present)."""
    if version < 2:   # 2003/2006: compression only drops the source PAN id when both addresses are there
        return bool(dst_mode), bool(src_mode) and not (compressed and dst_mode)
    if not dst_mode and not src_mode:
        return compressed, False
    if not src_mode:
        return not compressed, False
    if not dst_mode:
        return False, not compressed
    if dst_mode == 3 and src_mode == 3:
        return not compressed, False
    return True, not compressed


def _skip_ies(rd: _Reader) -> None:
    """Step over 802.15.4-2015 header IEs, then payload IEs if a header termination announces them."""
    while rd.pos < len(rd.data):
        desc = int.from_bytes(rd.take(2), "little")
        rd.take(desc & 0x7F)
        element = (desc >> 7) & 0xFF
        if element == 0x7F:   # header termination 2: the MAC payload follows, without payload IEs
            return
        if element == 0x7E:   # header termination 1: payload IEs follow
            break
    else:
        return
    while rd.pos < len(rd.data):
        desc = int.from_bytes(rd.take(2), "little")
        rd.take(desc & 0x07FF)
        if (desc >> 11) & 0x0F == 0x0F:   # payload termination
            return


def _parse_nwk(rd: _Reader) -> dict | None:
    first = rd.u8()
    version = (first >> 2) & 0x0F
    if version == 3:   # Green Power: a one-byte frame control and its own header
        return _parse_gpdf(rd, first)
    if version != 2:   # 2 is Zigbee 2006/PRO
        return None
    fcf = first | rd.u8() << 8
    ftype = fcf & 3
    if ftype == 3:   # inter-PAN (Touchlink commissioning, for instance): the header is this frame control alone
        return {"type": 3}
    if ftype == 2:   # reserved
        return None
    nwk: dict = {"type": ftype, "dst": rd.short(), "src": rd.short(), "radius": rd.u8(), "seq": rd.u8()}
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


def _parse_gpdf(rd: _Reader, fc: int) -> dict:
    """Green Power Device Frame header (Green Power Basic specification, A.1.4.1).

    The GPD source id is in clear whenever the application id is 0 (the common case: switches, sensors)."""
    gp: dict = {"gp": True}
    ftype, app_id = fc & 3, 0
    if fc & 0x80:
        ext = rd.u8()
        app_id = ext & 7
        gp["to_gpd"] = bool(ext & 0x80)
    if app_id == 0 and (ftype == 0 or (ftype == 1 and fc & 0x80)):
        gp["gpd"] = f"0x{int.from_bytes(rd.take(4), 'little'):08x}"
    return gp


class Classifier:
    """Stateful: an acknowledgement carries no address, so it is attributed to the frame it answers."""

    def __init__(self) -> None:
        self.count = 0
        self._awaiting_ack: dict | None = None
        self._last_sent: dict[str, tuple[bytes, float]] = {}

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
            if waiting and "seq" in p and waiting["seq"] == p["seq"]:
                ev["ms"], ev["md"] = waiting["dst"], waiting["src"]
            if p["pending"]:  # the parent has more for this child: its indirect queue is not empty
                ev["fp"] = 1
            return ev
        if kind == "bad":
            return ev
        for src_key, key in (("msrc", "ms"), ("mdst", "md"), ("pan", "pan")):
            if src_key in p:
                ev[key] = p[src_key]
        if p["ack_req"] and "msrc" in p and p.get("mdst") not in (None, "0xffff"):
            self._awaiting_ack = {"seq": p.get("seq"), "src": p["msrc"], "dst": p["mdst"]}
            # A MAC retransmission is the very same bytes again: the sender did not get its acknowledgement.
            previous = self._last_sent.get(p["msrc"])
            if previous and previous[0] == frame and 0 <= ts - previous[1] < 1.0:
                ev["rt"] = 1
            self._last_sent[p["msrc"]] = (frame, ts)
        if kind == "beacon":
            ev["cat"] = "beacon"
            ev["bcn"] = p["beacon"]
        elif kind == "cmd":
            ev["cat"] = MAC_COMMANDS.get(p["cmd"], "mac_cmd")
            ev["cmd"] = p["cmd"]
            if "assoc_status" in p:
                ev["st"] = p["assoc_status"]
        elif kind == "empty":   # the parent had nothing for the device that polled it after all
            ev["cat"] = "no_data"
        elif p["nwk"] and p["nwk"].get("gp"):
            ev["cat"] = "green_power"
            if "gpd" in p["nwk"]:
                ev["gpd"] = p["nwk"]["gpd"]
        elif p["nwk"] and p["nwk"]["type"] == 3:
            ev["cat"] = "inter_pan"
        elif p["nwk"]:
            self._classify_nwk(ev, p["nwk"])
        return ev

    @staticmethod
    def _classify_nwk(ev: dict, nwk: dict) -> None:
        ev.update(ns=nwk["src"], nd=nwk["dst"], r=nwk["radius"], q=nwk["seq"])
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


def build_ack(seq: int, pending: bool = False) -> bytes:
    return bytes([0x12 if pending else 0x02, 0x00, seq & 0xFF])


def build_empty_data(seq: int, pan: str, parent: str, child: str) -> bytes:
    """A parent's empty data frame: it set frame pending in its acknowledgement, then had nothing to send."""
    return bytes([0x41, 0x88, seq & 0xFF]) + _short(pan) + _short(child) + _short(parent)


def build_inter_pan(seq: int, src_pan: str, src64: str, payload: bytes = b"\x0b\x00\x00") -> bytes:
    """An inter-PAN broadcast (Touchlink scan request shape): destination PAN and address 0xffff, extended source."""
    return bytes([0x01, 0xC8, seq & 0xFF]) + b"\xff\xff\xff\xff" + _short(src_pan) + _ieee(src64) + b"\x0b\x00" + payload


def build_gpdf(seq: int, src_id: int, payload: bytes = b"\x00\x00\x00\x00\x20") -> bytes:
    """A Green Power data frame: broadcast, no MAC source, application id 0 so the source id travels in clear."""
    return bytes([0x01, 0x08, seq & 0xFF]) + b"\xff\xff\xff\xff" + b"\x0c" + src_id.to_bytes(4, "little") + payload


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
