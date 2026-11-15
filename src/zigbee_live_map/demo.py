"""A simulated Zigbee network, so the map can be tried (and tested) without any hardware.

It emits well-formed 802.15.4 frames with the timing patterns of a real network: sleepy end
devices polling their parent, routers announcing their links every 15 seconds, reports climbing
hop by hop to the coordinator, broadcasts rippling through the routers.
"""

from __future__ import annotations

import asyncio
import random

from . import frames as zf

PAN = "0x1a62"
EPID = "02:00:00:00:00:1a:62:00"
COORDINATOR = "0x0000"
# address: (name, model, parent, typical RSSI at the sniffer)
ROUTERS = {
    "0x2b01": ("Kitchen plug", "Smart plug", COORDINATOR, -52),
    "0x2b02": ("Living room plug", "Smart plug", COORDINATOR, -47),
    "0x2b03": ("Garage plug", "Smart plug", "0x2b01", -71),
    "0x2b04": ("Energy meter", "Meter reader", COORDINATOR, -63),
}
END_DEVICES = {
    "0x7c01": ("Bedroom thermostat", "Radiator valve", "0x2b01", -66),
    "0x7c02": ("Office thermostat", "Radiator valve", "0x2b02", -58),
    "0x7c03": ("Hallway motion", "Motion sensor", "0x2b02", -61),
    "0x7c04": ("Garage door", "Contact sensor", "0x2b03", -78),
    "0x7c05": ("Garden temperature", "Weather sensor", "0x2b03", -83),
    "0x7c06": ("Bathroom humidity", "Weather sensor", "0x2b01", -69),
    "0x7c07": ("Front door", "Contact sensor", COORDINATOR, -55),
}
NO_CHILDREN = {"0x2b04"}  # this router advertises that it accepts no child


def ieee_of(addr: str) -> str:
    value = int(addr, 16)
    return f"02:00:00:ff:fe:00:{value >> 8:02x}:{value & 0xFF:02x}"


def names() -> dict:
    table = {ieee_of(COORDINATOR): {"name": "Coordinator", "model": "USB coordinator", "nwk": COORDINATOR}}
    for addr, (name, model, _parent, _rssi) in {**ROUTERS, **END_DEVICES}.items():
        table[ieee_of(addr)] = {"name": name, "model": model, "nwk": addr}
    return table


class DemoNetwork:
    def __init__(self, emit, speed: float = 1.0) -> None:
        self.emit = emit  # async callable(frame: bytes, rssi: int)
        self.speed = speed
        self.parent = {a: v[2] for a, v in {**ROUTERS, **END_DEVICES}.items()}
        self.rssi = {COORDINATOR: -41, **{a: v[3] for a, v in {**ROUTERS, **END_DEVICES}.items()}}
        self.mac_seq = {a: random.randrange(256) for a in self.rssi}
        self.nwk_seq = {a: random.randrange(256) for a in self.rssi}
        self.pending: dict[str, list] = {a: [] for a in END_DEVICES}
        self.air = asyncio.Lock()  # one frame and its acknowledgement at a time

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds / self.speed)

    def _next(self, table: dict, addr: str) -> int:
        table[addr] = (table[addr] + 1) & 0xFF
        return table[addr]

    async def _send(self, src: str, frame: bytes, seq: int, acked_by: str | None) -> None:
        async with self.air:
            await self.emit(frame, self.rssi[src] + random.randint(-3, 3))
            if acked_by:
                await asyncio.sleep(0.004)
                await self.emit(zf.build_ack(seq), self.rssi[acked_by] + random.randint(-3, 3))

    async def hop(self, src: str, dst: str, *, command: bool, nsrc: str, ndst: str, radius: int, nseq: int, size: int = 12) -> None:
        seq = self._next(self.mac_seq, src)
        frame = zf.build_nwk(seq, PAN, dst, src, command=command, nwk_dst=ndst, nwk_src=nsrc, radius=radius,
                             nwk_seq=nseq, hop_ieee=ieee_of(src), payload_len=size)
        await self._send(src, frame, seq, None if dst == "0xffff" else dst)

    def path_up(self, addr: str) -> list[str]:
        path = [addr]
        while path[-1] != COORDINATOR:
            path.append(self.parent[path[-1]])
        return path

    async def to_coordinator(self, src: str, *, command: bool = False, size: int = 12) -> None:
        path, nseq = self.path_up(src), self._next(self.nwk_seq, src)
        for i in range(len(path) - 1):
            await self.hop(path[i], path[i + 1], command=command, nsrc=src, ndst=COORDINATOR, radius=30 - i, nseq=nseq,
                           size=size + (2 * i if command else 0))
            await self.sleep(0.03)

    async def from_coordinator(self, dst: str) -> None:
        path, nseq = list(reversed(self.path_up(dst))), self._next(self.nwk_seq, COORDINATOR)
        last = len(path) - 1
        for i in range(last):
            if i == last - 1 and dst in END_DEVICES:  # the parent keeps it until the device wakes up
                self.pending[dst].append((path[i], nseq, 30 - i))
                return
            await self.hop(path[i], path[i + 1], command=False, nsrc=COORDINATOR, ndst=dst, radius=30 - i, nseq=nseq)
            await self.sleep(0.03)

    async def flood(self, *, command: bool, ndst: str, radius: int) -> None:
        """A broadcast from the coordinator, repeated once by every router, radius shrinking per hop."""
        nseq = self._next(self.nwk_seq, COORDINATOR)
        await self.hop(COORDINATOR, "0xffff", command=command, nsrc=COORDINATOR, ndst=ndst, radius=radius, nseq=nseq)
        for router in sorted(ROUTERS, key=lambda r: len(self.path_up(r))):
            await self.sleep(0.035 + random.random() * 0.03)
            depth = len(self.path_up(router)) - 1
            await self.hop(router, "0xffff", command=command, nsrc=COORDINATOR, ndst=ndst, radius=radius - depth, nseq=nseq)

    # ---- periodic behaviours ----
    async def link_status(self, addr: str) -> None:
        await self.sleep(random.random() * 15)
        while True:
            await self.hop(addr, "0xffff", command=True, nsrc=addr, ndst="0xfffc", radius=1, nseq=self._next(self.nwk_seq, addr), size=8)
            await self.sleep(15)

    async def polling(self, addr: str) -> None:
        period = random.uniform(1.6, 5.5)
        await self.sleep(random.random() * period)
        while True:
            seq = self._next(self.mac_seq, addr)
            await self._send(addr, zf.build_poll(seq, PAN, self.parent[addr], addr), seq, self.parent[addr])
            if self.pending[addr]:
                parent, nseq, radius = self.pending[addr].pop(0)
                await self.sleep(0.01)
                await self.hop(parent, addr, command=False, nsrc=COORDINATOR, ndst=addr, radius=radius, nseq=nseq)
            await self.sleep(period)

    async def reporting(self, addr: str, low: float, high: float) -> None:
        await self.sleep(random.uniform(1, high))
        while True:
            await self.to_coordinator(addr)
            if random.random() < 0.6:
                await self.sleep(0.05)
                await self.from_coordinator(addr)
            await self.sleep(random.uniform(low, high))

    async def coordinator_routines(self) -> None:
        await self.sleep(6)
        while True:
            await self.flood(command=True, ndst="0xfffc", radius=10)  # "this is the way to me"
            for router in ROUTERS:
                await self.sleep(0.4 + random.random())
                await self.to_coordinator(router, command=True)
            await self.sleep(20)
            await self.flood(command=False, ndst="0xfffd", radius=30)
            await self.sleep(25)

    async def discovery(self) -> None:
        """Now and then a device looks for a network and every router answers with a beacon."""
        await self.sleep(12)
        while True:
            async with self.air:
                await self.emit(zf.build_beacon_request(random.randrange(256)), -70)
            for addr in [COORDINATOR, *ROUTERS]:
                await self.sleep(0.02 + random.random() * 0.03)
                seq = self._next(self.mac_seq, addr)
                open_to_children = addr not in NO_CHILDREN
                beacon = zf.build_beacon(seq, PAN, addr, EPID, zr=open_to_children, zed=open_to_children, permit=False,
                                         depth=len(self.path_up(addr)) - 1)
                await self._send(addr, beacon, seq, None)
            await self.sleep(70)

    async def run(self) -> None:
        tasks = [self.coordinator_routines(), self.discovery(), self.link_status(COORDINATOR)]
        tasks += [self.link_status(r) for r in ROUTERS]
        tasks += [self.reporting(r, 8, 20) for r in ROUTERS]
        tasks += [self.polling(d) for d in END_DEVICES]
        tasks += [self.reporting(d, 15, 45) for d in END_DEVICES]
        await asyncio.gather(*tasks)
