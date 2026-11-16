"""Receive-only driver for a CC2531 USB dongle running the TI Packet Sniffer firmware (USB 0451:16AE).

The firmware only listens: this module never transmits on the radio. The USB protocol is the one
used by whsniff and ccsniffpiper: vendor control requests to power the radio, set the channel and
start/stop, then frames arrive on bulk endpoint 0x83 as
[type u8][len u16][timestamp u32][frame_len u8][frame without FCS][rssi i8][crc_ok<<7 | lqi u8].
"""

from __future__ import annotations

import struct
import time

import usb.backend.libusb1
import usb.core
import usb.util

VID, PID, EP_IN = 0x0451, 0x16AE, 0x83
REQ_GET_IDENT, REQ_SET_POWER, REQ_GET_POWER, REQ_SET_START = 0xC0, 0xC5, 0xC6, 0xD0
REQ_SET_STOP, REQ_SET_CHAN = 0xD1, 0xD2
LINKTYPE_IEEE802_15_4_NOFCS = 230
RSSI_OFFSET_DBM = -73  # CC2531 datasheet: RSSI register value + offset = dBm
CHANNELS = range(11, 27)
# Homebrew and MacPorts install libusb where Python's loader does not look by default.
LIBUSB_CANDIDATES = ("/opt/homebrew/lib/libusb-1.0.dylib", "/usr/local/lib/libusb-1.0.dylib", "/opt/local/lib/libusb-1.0.dylib")


class SnifferError(RuntimeError):
    """Why the dongle cannot be read. `code` names what is missing, so the page can explain it in the reader's language:
    "libusb" (the library), "not_found" (no dongle with the sniffer firmware), "radio" (it did not start), "usb" (anything else)."""

    def __init__(self, message: str, code: str = "usb") -> None:
        super().__init__(message)
        self.code = code


def _backend():
    backend = usb.backend.libusb1.get_backend()
    if backend is not None:
        return backend
    for path in LIBUSB_CANDIDATES:
        backend = usb.backend.libusb1.get_backend(find_library=lambda _name, path=path: path)
        if backend is not None:
            return backend
    raise SnifferError("libusb not found (macOS: brew install libusb, Debian/Ubuntu: apt install libusb-1.0-0)", "libusb")


def open_sniffer(channel: int):
    if channel not in CHANNELS:
        raise SnifferError(f"channel {channel} is outside 11-26")
    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=_backend())
    if dev is None:
        raise SnifferError("CC2531 with the TI sniffer firmware (USB 0451:16ae) not found", "not_found")
    try:
        dev.set_configuration()
        dev.ctrl_transfer(0xC0, REQ_GET_IDENT, 0, 0, 256)
        dev.ctrl_transfer(0x40, REQ_SET_POWER, 0, 4)
        for _ in range(50):
            if dev.ctrl_transfer(0xC0, REQ_GET_POWER, 0, 0, 1)[0] == 4:
                break
            time.sleep(0.01)
        else:
            raise SnifferError("the dongle radio did not power up", "radio")
        dev.ctrl_transfer(0x40, 0xC9, 0, 0)
        dev.ctrl_transfer(0x40, REQ_SET_CHAN, 0, 0, bytes([channel]))
        dev.ctrl_transfer(0x40, REQ_SET_CHAN, 0, 1, bytes([0]))
        dev.ctrl_transfer(0x40, REQ_SET_START, 0, 0)
    except usb.core.USBError as exc:
        raise SnifferError(f"USB error while starting the dongle: {exc}") from exc
    return dev


def close_sniffer(dev) -> None:
    try:
        dev.ctrl_transfer(0x40, REQ_SET_STOP, 0, 0)
        dev.ctrl_transfer(0x40, REQ_SET_POWER, 0, 0)
        usb.util.dispose_resources(dev)
    except usb.core.USBError:
        pass  # dongle already unplugged


def read_chunk(dev, timeout_ms: int = 200) -> bytes:
    """One blocking USB read; empty bytes on timeout."""
    try:
        return bytes(dev.read(EP_IN, 4096, timeout=timeout_ms))
    except usb.core.USBTimeoutError:
        return b""


def extract_frames(buf: bytes) -> tuple[list[tuple[bytes, int, bool]], bytes]:
    """Split the USB byte stream into (frame without FCS, rssi dBm, crc_ok) and the unconsumed rest."""
    frames = []
    while len(buf) >= 3:
        pkt_type, pkt_len = buf[0], struct.unpack_from("<H", buf, 1)[0]
        if len(buf) < 3 + pkt_len:
            break
        body, buf = buf[3:3 + pkt_len], buf[3 + pkt_len:]
        if pkt_type != 0 or len(body) < 5:
            continue
        flen = body[4]
        if flen < 2 or len(body) < 5 + flen:
            continue
        frame, status = body[5:5 + flen - 2], body[5 + flen - 2:5 + flen]
        rssi = struct.unpack("b", status[:1])[0] + RSSI_OFFSET_DBM
        frames.append((frame, rssi, bool(status[1] & 0x80)))
    return frames, buf


def pcap_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_IEEE802_15_4_NOFCS)


def pcap_record(ts: float, frame: bytes) -> bytes:
    return struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame


def scan(seconds: float = 2.0, on_progress=None) -> list[dict]:
    """Listen on every channel in turn and report what is there: frame count, PAN ids, best RSSI."""
    from .frames import parse

    results = []
    for channel in CHANNELS:
        dev = open_sniffer(channel)
        count, pans, best = 0, {}, None
        buf, end = b"", time.time() + seconds
        try:
            while time.time() < end:
                buf += read_chunk(dev)
                frames, buf = extract_frames(buf)
                for frame, rssi, crc_ok in frames:
                    if not crc_ok:
                        continue
                    count += 1
                    best = rssi if best is None else max(best, rssi)
                    pan = parse(frame).get("pan")
                    if pan and pan != "0xffff":
                        pans[pan] = pans.get(pan, 0) + 1
        finally:
            close_sniffer(dev)
        row = {"channel": channel, "frames": count, "pans": pans, "best_rssi": best}
        results.append(row)
        if on_progress:
            on_progress(row)
    return results
