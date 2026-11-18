"""Turn a frame into one event for the map, from its clear-text headers alone.

Two layers are readable without any key (wire.py reads them):
  - MAC (802.15.4): who transmits this radio hop and who should receive it;
  - NWK (Zigbee): who created the message, who it is finally for, how many hops remain (radius),
    and the IEEE address of the device that secured this hop.
Everything after the NWK security header is encrypted and is left untouched, so NWK commands are
classified from their shape (destination, radius). The page marks those guesses as "probable".
"""

from __future__ import annotations

from . import wire

BROADCASTS = {"0xffff", "0xfffd", "0xfffc", "0xfffb"}
MAC_COMMANDS = {0x01: "join", 0x02: "join", 0x04: "poll", 0x07: "beacon_req"}


def parse(frame: bytes | wire.Frame) -> dict:
    """Return the readable header fields. 'kind' is ack, beacon, cmd, data, empty or bad.

    'empty' is a data frame with no payload at all: IEEE 802.15.4-2015 § 6.7.3 lets a parent answer a data
    request that way when, after all, it has nothing for the device that polled. 'bad' is everything that is
    not Zigbee or cannot be read: MAC security, frame types and addressing modes Zigbee never uses, the
    reserved frame version, a frame cut short."""
    f = wire.read(frame)
    out: dict = {"kind": "bad"}
    if len(f.raw) < 2:
        return out
    fcf = int.from_bytes(f.raw[0:2], "little")
    out.update(ack_req=bool(fcf & 0x20), pending=bool(fcf & 0x10))
    mac = f.mac
    if mac is None:
        return out
    if mac.seq is not None:
        out["seq"] = mac.seq
    if mac.ftype == wire.ACK:
        out["kind"] = "ack"
        return out
    if not mac.zigbee:
        return out
    if mac.pan:
        out["pan"] = mac.pan
    if mac.dst:
        out["mdst"] = mac.dst
    if mac.src:
        out["msrc"] = mac.src
    try:
        rd = wire.Reader(f.raw, mac.end)
        if mac.ftype == wire.BEACON:
            out["beacon"] = wire.read_beacon(rd)
            out["kind"] = "beacon"
        elif mac.ftype == wire.MAC_COMMAND:
            out["cmd"] = rd.u8()
            if out["cmd"] == 0x02:  # association response: assigned short address + status, in clear
                rd.take(2)
                out["assoc_status"] = rd.u8()
            out["kind"] = "cmd"
        elif not rd.left:
            out["kind"] = "empty"
        elif f.problem is None:
            out["nwk"] = _nwk_fields(f.net)
            out["kind"] = "data"
    except ValueError:
        out["kind"] = "bad"
    return out


def _nwk_fields(net: wire.Nwk | wire.InterPan | wire.GreenPower | None) -> dict | None:
    if isinstance(net, wire.GreenPower):
        gp: dict = {"gp": True}
        if net.to_gpd is not None:
            gp["to_gpd"] = net.to_gpd
        if net.gpd is not None:
            gp["gpd"] = net.gpd
        return gp
    if isinstance(net, wire.InterPan):
        return {"type": 3}
    if net is None:
        return None
    nwk: dict = {"type": net.ftype, "dst": net.dst, "src": net.src, "radius": net.radius, "seq": net.seq}
    if net.dst64:
        nwk["dst64"] = net.dst64
    if net.src64:
        nwk["src64"] = net.src64
    if net.relays is not None:
        nwk["relays"] = net.relays
    if net.aux is not None and net.aux.src64 is not None:   # the IEEE of the device that secured this hop
        nwk["sec64"] = wire.ieee_text(net.aux.src64)
    return nwk


class Classifier:
    """Stateful: an acknowledgement carries no address, so it is attributed to the frame it answers."""

    def __init__(self) -> None:
        self.count = 0
        self._awaiting_ack: dict | None = None
        self._last_sent: dict[str, tuple[bytes, float]] = {}

    def event(self, frame: bytes | wire.Frame, ts: float, rssi: int | None = None) -> dict:
        self.count += 1
        read = wire.read(frame)
        p, frame = parse(read), read.raw
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
