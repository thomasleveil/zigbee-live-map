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
