"""Read the clear-text headers of an IEEE 802.15.4 frame carrying Zigbee: once, and in one place.

Three headers travel in clear whatever the keys: the MAC header (who transmits this radio hop, and to whom),
the Zigbee NWK header (who created the message and who it is finally for) and the auxiliary security header
(the frame counter and the IEEE address of the device that secured this hop). Every reader of a frame goes
through `read`: the map's classifier (frames.py), the decryption (decode.py) and the layer-by-layer view
(dissect.py). A header rule is therefore written once, and a frame is walked once however many of them look
at it: `read` gives back a `Frame` it is handed.

Each header keeps the offsets of its first byte and of the byte after its last: CCM* authenticates the exact
header bytes, and the next layer starts where this one ends.

A read past the end of the data raises `Truncated` (a ValueError): a cut frame is refused, never completed
with guessed bytes. Input is a frame without its FCS.
"""

from __future__ import annotations

from dataclasses import dataclass

BEACON, DATA, ACK, MAC_COMMAND = 0, 1, 2, 3   # MAC frame types
NWK_DATA, NWK_COMMAND = 0, 1                  # NWK frame types
ZIGBEE_PRO, GREEN_POWER = 2, 3                # the protocol version field of the first NWK byte


class Truncated(ValueError):
    """The data ends before the field that was being read."""


def short_text(value: int) -> str:
    """A 16-bit address or PAN id, as the rest of the tool writes it."""
    return f"0x{value:04x}"


def ieee_text(value: int) -> str:
    """A 64-bit IEEE address, most significant byte first."""
    return ":".join(f"{b:02x}" for b in value.to_bytes(8, "big"))


class Reader:
    """Walks bytes forward. Everything is little-endian, as on the air."""

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data, self.pos = data, pos

    @property
    def left(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise Truncated("frame too short")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def rest(self) -> bytes:
        return self.take(self.left)

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "little")

    def u8(self) -> int:
        return self.uint(1)

    def u16(self) -> int:
        return self.uint(2)

    def u32(self) -> int:
        return self.uint(4)

    def u64(self) -> int:
        return self.uint(8)

    def short(self) -> str:
        return short_text(self.u16())

    def ieee(self) -> str:
        return ieee_text(self.u64())

    def addr(self, mode: int) -> str:
        return self.short() if mode == 2 else self.ieee()


# --- IEEE 802.15.4 MAC header (IEEE 802.15.4-2015 § 7.2) ------------------------------------------

@dataclass(frozen=True)
class Mac:
    """The MAC header. Frame versions 0 and 1 (2003/2006, what Zigbee sends) and 2 (2015, which may suppress
    the sequence number, carry information elements and compress PAN ids by the table of § 7.2.2.6).

    An acknowledgement stops after its sequence number. `end` is where the MAC payload starts; it means
    nothing on a frame with MAC security, whose own security header is not read."""

    fcf: int
    seq: int | None
    end: int
    dst_pan: str | None = None
    dst: str | None = None
    src_pan: str | None = None
    src: str | None = None

    @property
    def ftype(self) -> int:
        return self.fcf & 7

    @property
    def version(self) -> int:
        return (self.fcf >> 12) & 3

    @property
    def security(self) -> bool:
        return bool(self.fcf & 0x08)

    @property
    def pending(self) -> bool:
        return bool(self.fcf & 0x10)

    @property
    def ack_req(self) -> bool:
        return bool(self.fcf & 0x20)

    @property
    def pan_compression(self) -> bool:
        return bool(self.fcf & 0x40)

    @property
    def dst_mode(self) -> int:
        return (self.fcf >> 10) & 3

    @property
    def src_mode(self) -> int:
        return (self.fcf >> 14) & 3

    @property
    def pan(self) -> str | None:
        """The PAN the transmitter is in: its own when the frame names it, else the destination's."""
        return self.src_pan or self.dst_pan

    @property
    def zigbee(self) -> bool:
        """Could carry Zigbee at all: MAC security, the other frame types and the reserved version never do."""
        return self.ftype in (BEACON, DATA, MAC_COMMAND) and not self.security and self.version != 3


def pan_ids(version: int, dst_mode: int, src_mode: int, compressed: bool) -> tuple[bool, bool]:
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


def _skip_ies(rd: Reader) -> None:
    """Step over 802.15.4-2015 header IEs, then payload IEs if a header termination announces them."""
    while rd.left:
        desc = rd.u16()
        rd.take(desc & 0x7F)
        element = (desc >> 7) & 0xFF
        if element == 0x7F:   # header termination 2: the MAC payload follows, without payload IEs
            return
        if element == 0x7E:   # header termination 1: payload IEs follow
            break
    else:
        return
    while rd.left:
        desc = rd.u16()
        rd.take(desc & 0x07FF)
        if (desc >> 11) & 0x0F == 0x0F:   # payload termination
            return


def read_mac(frame: bytes) -> Mac:
    rd = Reader(frame)
    fcf = rd.u16()
    ftype, version = fcf & 7, (fcf >> 12) & 3
    dst_mode, src_mode = (fcf >> 10) & 3, (fcf >> 14) & 3
    seq = None if version == 2 and fcf & 0x0100 else rd.u8()   # sequence number suppression exists from 2015 on
    if ftype == ACK:
        return Mac(fcf, seq, rd.pos)
    if 1 in (dst_mode, src_mode):
        raise ValueError("reserved addressing mode")
    has_dst_pan, has_src_pan = pan_ids(version, dst_mode, src_mode, bool(fcf & 0x40))
    dst_pan = rd.short() if has_dst_pan else None
    dst = rd.addr(dst_mode) if dst_mode else None
    src_pan = rd.short() if has_src_pan else None
    src = rd.addr(src_mode) if src_mode else None
    if version == 2 and fcf & 0x0200:
        _skip_ies(rd)
    return Mac(fcf, seq, rd.pos, dst_pan, dst, src_pan, src)


def read_beacon(rd: Reader) -> dict:
    """A beacon's payload: whether the sender accepts joins and, when it is a Zigbee beacon, what it has room for."""
    superframe = rd.u16()
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


# --- auxiliary security header (Zigbee PRO § 4.5.1), the same shape at the NWK and APS layers -------

@dataclass(frozen=True)
class Aux:
    start: int
    end: int
    control: int
    counter: int
    src64: int | None     # the device that secured the frame, when the nonce is extended
    key_seq: int | None   # only the network key carries a sequence number

    @property
    def key_id(self) -> int:
        """0 data key, 1 network key, 2 key-transport key, 3 key-load key."""
        return (self.control >> 3) & 3

    @property
    def extended_nonce(self) -> bool:
        return bool(self.control & 0x20)


def read_aux(rd: Reader) -> Aux:
    start = rd.pos
    control = rd.u8()
    counter = rd.u32()
    src64 = rd.u64() if control & 0x20 else None
    key_seq = rd.u8() if (control >> 3) & 3 == 1 else None
    return Aux(start, rd.pos, control, counter, src64, key_seq)


# --- Zigbee NWK header (Zigbee PRO § 3.3.1), and the two other things found in its place ------------

@dataclass(frozen=True)
class Nwk:
    """A Zigbee PRO NWK header, with its security header when the frame is secured. `end` is where the NWK
    payload starts: the APS frame or the NWK command, encrypted when `aux` is there."""

    start: int
    end: int
    fcf: int
    dst: str
    src: str
    radius: int
    seq: int
    dst64: str | None = None
    src64: str | None = None
    multicast: int | None = None
    relays: list[str] | None = None   # a source route: the full relay list travels in clear
    relay_index: int | None = None
    aux: Aux | None = None

    @property
    def ftype(self) -> int:
        return self.fcf & 3

    @property
    def secured(self) -> bool:
        return self.aux is not None


@dataclass(frozen=True)
class InterPan:
    """An inter-PAN frame (Touchlink commissioning, for instance): its NWK header is the frame control alone."""

    start: int
    end: int


@dataclass(frozen=True)
class GreenPower:
    """A Green Power Device Frame header (Green Power Basic specification, A.1.4.1).

    The GPD source id is in clear whenever the application id is 0 (the common case: switches, sensors)."""

    start: int
    end: int
    fc: int
    ext: int | None = None   # the extended frame control, when present
    gpd: str | None = None

    @property
    def ftype(self) -> int:
        return self.fc & 3

    @property
    def app_id(self) -> int:
        return (self.ext or 0) & 7

    @property
    def to_gpd(self) -> bool | None:
        return None if self.ext is None else bool(self.ext & 0x80)


def read_nwk(rd: Reader) -> Nwk | InterPan | GreenPower | None:
    """What starts at the reader's position in the payload of a MAC data frame. None: not Zigbee PRO or Green Power."""
    start = rd.pos
    first = rd.u8()
    version = (first >> 2) & 0x0F
    if version == GREEN_POWER:   # a one-byte frame control and its own header
        ext = rd.u8() if first & 0x80 else None
        app_id, ftype = (ext or 0) & 7, first & 3
        clear_id = app_id == 0 and (ftype == 0 or (ftype == 1 and ext is not None))
        gpd = f"0x{rd.u32():08x}" if clear_id else None
        return GreenPower(start, rd.pos, first, ext, gpd)
    if version != ZIGBEE_PRO:
        return None
    fcf = first | rd.u8() << 8
    ftype = fcf & 3
    if ftype == 3:
        return InterPan(start, rd.pos)
    if ftype == 2:   # reserved
        return None
    dst, src, radius, seq = rd.short(), rd.short(), rd.u8(), rd.u8()
    dst64 = rd.ieee() if fcf & 0x0800 else None
    src64 = rd.ieee() if fcf & 0x1000 else None
    multicast = rd.u8() if fcf & 0x0100 else None
    relays = relay_index = None
    if fcf & 0x0400:
        count, relay_index = rd.u8(), rd.u8()
        relays = [rd.short() for _ in range(count)]
    aux = read_aux(rd) if fcf & 0x0200 else None
    return Nwk(start, rd.pos, fcf, dst, src, radius, seq, dst64, src64, multicast, relays, relay_index, aux)


# --- a frame, read once ----------------------------------------------------------------------------

@dataclass(frozen=True)
class Frame:
    """A frame and what its clear headers say.

    `mac` is None when the MAC header itself cannot be read. `net` is what a MAC data frame carries, when it
    carries something and could be Zigbee. `problem` is why reading stopped, when it stopped before the end
    of the headers."""

    raw: bytes
    mac: Mac | None = None
    net: Nwk | InterPan | GreenPower | None = None
    problem: ValueError | None = None

    @property
    def nwk(self) -> Nwk | None:
        """The Zigbee PRO NWK header, when that is what the frame carries."""
        return self.net if isinstance(self.net, Nwk) else None


def read(frame: bytes | Frame) -> Frame:
    """Read a frame's clear headers. A `Frame` is returned as it is, so a frame is walked once."""
    if isinstance(frame, Frame):
        return frame
    raw = bytes(frame)
    try:
        mac = read_mac(raw)
    except ValueError as exc:
        return Frame(raw, problem=exc)
    if mac.ftype != DATA or not mac.zigbee or mac.end >= len(raw):
        return Frame(raw, mac)
    try:
        return Frame(raw, mac, read_nwk(Reader(raw, mac.end)))
    except ValueError as exc:
        return Frame(raw, mac, problem=exc)
