"""Why the dongle cannot be read: the reason travels with the status, so the page can explain what is missing."""

import asyncio

import pytest
import usb.backend.libusb1
import usb.core

from zigbee_live_map import sniffer
from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.server import Hub, pump
from zigbee_live_map.vendors import Registry


def test_sniffer_absent_dongle_says_it_was_not_found(monkeypatch):
    monkeypatch.setattr(sniffer, "_backend", lambda: object())
    monkeypatch.setattr(usb.core, "find", lambda **_kwargs: None)
    with pytest.raises(sniffer.SnifferError) as caught:
        sniffer.open_sniffer(15)
    assert caught.value.code == "not_found" and "0451:16ae" in str(caught.value)


def test_sniffer_missing_libusb_says_so(monkeypatch):
    monkeypatch.setattr(usb.backend.libusb1, "get_backend", lambda **_kwargs: None)
    with pytest.raises(sniffer.SnifferError) as caught:
        sniffer.open_sniffer(15)
    assert caught.value.code == "libusb"


def test_sniffer_a_dongle_that_cannot_be_opened_is_a_usb_problem(monkeypatch):
    class Stuck:
        def set_configuration(self):
            raise usb.core.USBError("Access denied (insufficient permissions)", errno=13)

    monkeypatch.setattr(sniffer, "_backend", lambda: object())
    monkeypatch.setattr(usb.core, "find", lambda **_kwargs: Stuck())
    with pytest.raises(sniffer.SnifferError) as caught:
        sniffer.open_sniffer(15)
    assert caught.value.code == "usb" and "Access denied" in str(caught.value)


def test_sniffer_status_tells_the_pages_the_reason(tmp_path):
    async def scenario():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), {"channel": 15, "mode": "live", "focus": None, "can_tune": True}, 100)
        assert hub.status["reason"] == ""                       # starting: nothing is wrong yet
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(pump(queue, hub))
        await queue.put(("status", 0, "absent", "CC2531 not found", "not_found"))
        await queue.put(("status", 0, "ok", ""))               # the older two-field form still works, and clears the reason
        await asyncio.sleep(0.05)
        task.cancel()
        return hub

    hub = asyncio.run(scenario())
    assert hub.status == {"type": "status", "sniffer": "ok", "detail": "", "reason": ""}

    async def absent():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), {"channel": 15, "mode": "live", "focus": None, "can_tune": True}, 100)
        await hub.set_status("absent", "CC2531 not found", "not_found")
        return hub.status

    assert asyncio.run(absent()) == {"type": "status", "sniffer": "absent", "detail": "CC2531 not found", "reason": "not_found"}


# ------------------------------------------------------------------------------------------ closing the dongle

class FakeDongle:
    def __init__(self, gone: bool) -> None:
        self.gone, self.transfers = gone, []

    def ctrl_transfer(self, *args):
        if self.gone:
            raise usb.core.USBError("No such device (it may have been disconnected)", errno=19)
        self.transfers.append(args)


def test_closing_an_unplugged_dongle_still_releases_its_handle(monkeypatch):
    released = []
    monkeypatch.setattr(usb.util, "dispose_resources", released.append)
    dongle = FakeDongle(gone=True)
    sniffer.close_sniffer(dongle)
    assert released == [dongle]   # the transfers failed, the handle (and the node it holds open) is released all the same


def test_closing_a_present_dongle_stops_and_powers_it_down_then_releases_it(monkeypatch):
    released = []
    monkeypatch.setattr(usb.util, "dispose_resources", released.append)
    dongle = FakeDongle(gone=False)
    sniffer.close_sniffer(dongle)
    assert dongle.transfers == [(0x40, sniffer.REQ_SET_STOP, 0, 0), (0x40, sniffer.REQ_SET_POWER, 0, 0)] and released == [dongle]


# ------------------------------------------------------------------------------------------ the log follows the dongle

def test_each_dongle_state_change_prints_one_line_and_a_repeat_prints_none(tmp_path, capsys):
    async def scenario():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), {"channel": 20, "mode": "live", "focus": None, "can_tune": True}, 100)
        await hub.set_status("starting")
        for _ in range(3):                                                      # retried every two seconds: one line, not three
            await hub.set_status("absent", "CC2531 with the TI sniffer firmware (USB 0451:16ae) not found", "not_found")
        await hub.set_status("ok")
        await hub.set_status("ok")
        await hub.set_status("absent", "USB error: [Errno 19] No such device (it may have been disconnected)", "usb")
        await hub.set_status("absent", "USB error: [Errno 19] No such device (it may have been disconnected)", "usb")
        await hub.set_status("absent", "CC2531 with the TI sniffer firmware (USB 0451:16ae) not found", "not_found")
        await hub.set_status("ok")
        hub.info["channel"] = 15                                                 # what a retune does, then the source reads again
        await hub.set_status("starting")
        await hub.set_status("ok")

    asyncio.run(scenario())
    assert capsys.readouterr().out.splitlines() == [
        "dongle: not found: no CC2531 with the TI sniffer firmware (USB id 0451:16ae) on the USB ports; looking again every two seconds",
        "dongle: reading on channel 20",                                         # a first read, not a return
        "dongle: lost: USB error: [Errno 19] No such device (it may have been disconnected)",
        "dongle: not found: no CC2531 with the TI sniffer firmware (USB id 0451:16ae) on the USB ports; looking again every two seconds",
        "dongle: reading again on channel 20",
        "dongle: reading on channel 15",
    ]


def test_the_demo_and_a_replay_write_no_dongle_line(tmp_path, capsys):
    async def scenario():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), {"channel": None, "mode": "demo", "focus": None, "can_tune": False}, 100)
        await hub.set_status("demo", "")
        await hub.set_status("replay", "capture.pcap")

    asyncio.run(scenario())
    assert capsys.readouterr().out == ""
