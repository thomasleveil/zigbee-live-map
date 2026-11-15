"""Local web server: frames in, events out over a WebSocket, one page to draw them.

It listens on 127.0.0.1 only and refuses WebSocket connections whose Origin is another site,
so a web page you visit cannot read your radio traffic through your browser.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import deque
from importlib import resources
from pathlib import Path

from aiohttp import WSMsgType, web

from . import __version__, demo, names as names_store
from .frames import Classifier, read_pcap


class Hub:
    """Keeps the recent events and fans every new one out to the connected pages."""

    def __init__(self, names_path: Path | None, names: dict, info: dict, backlog: int) -> None:
        self.names_path, self.names, self.info = names_path, names, info
        self.status = {"type": "status", "sniffer": "starting", "detail": ""}
        self.events: deque = deque(maxlen=backlog)
        self.clients: set[web.WebSocketResponse] = set()
        self.classifier = Classifier()
        self.generation = 0  # bumped on every channel change, so frames from the old channel are dropped
        self.source: LiveSource | None = None

    def hello(self) -> dict:
        return {"type": "hello", "version": __version__, **self.info, "names": self.names}

    async def send_all(self, message: dict) -> None:
        text = json.dumps(message, separators=(",", ":"))
        for ws in list(self.clients):
            try:
                await ws.send_str(text)
            except (ConnectionError, RuntimeError):
                self.clients.discard(ws)

    async def publish(self, frame: bytes, ts: float, rssi: int | None) -> None:
        event = self.classifier.event(frame, ts, rssi)
        self.events.append(event)
        await self.send_all({"type": "ev", "e": event})

    async def set_status(self, sniffer: str, detail: str = "") -> None:
        self.status = {"type": "status", "sniffer": sniffer, "detail": detail}
        await self.send_all(self.status)

    async def rename(self, ieee: str, name: str) -> None:
        ieee = ieee.lower()
        if not names_store.IEEE_RE.match(ieee):
            return
        name = name.strip()[:60]
        entry = dict(self.names.get(ieee, {}))
        if name:
            entry["name"] = name
            self.names[ieee] = entry
        elif ieee in self.names:
            entry.pop("name", None)
            self.names[ieee] = entry
        if self.names_path:
            names_store.save(self.names_path, self.names)
        await self.send_all({"type": "names", "names": self.names})

    async def tune(self, channel: int) -> None:
        if self.source is None or channel not in range(11, 27) or channel == self.info["channel"]:
            return
        self.generation += 1
        self.info["channel"] = channel
        self.events.clear()
        self.classifier = Classifier()
        self.source.set_channel(channel, self.generation)
        await self.send_all(self.hello())
        await self.set_status("starting")


class LiveSource:
    """Blocking USB reads live in a thread; everything else happens on the event loop."""

    def __init__(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, channel: int, pcap_path: str | None) -> None:
        self.loop, self.queue, self.pcap_path = loop, queue, pcap_path
        self.channel, self.generation = channel, 0
        self._stop, self._retune = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def set_channel(self, channel: int, generation: int) -> None:
        self.channel, self.generation = channel, generation
        self._retune.set()

    def stop(self) -> None:
        self._stop.set()
        self._retune.set()
        self.thread.join(timeout=2)

    def _post(self, *item) -> None:
        self.loop.call_soon_threadsafe(self.queue.put_nowait, item)

    def _run(self) -> None:
        import usb.core

        from . import sniffer

        pcap = open(self.pcap_path, "wb") if self.pcap_path else None
        if pcap:
            pcap.write(sniffer.pcap_header())
        try:
            while not self._stop.is_set():
                self._retune.clear()
                channel, generation, dev = self.channel, self.generation, None
                try:
                    dev = sniffer.open_sniffer(channel)
                    self._post("status", generation, "ok", "")
                    buf = b""
                    while not self._retune.is_set():
                        buf += sniffer.read_chunk(dev)
                        found, buf = sniffer.extract_frames(buf)
                        for frame, rssi, crc_ok in found:
                            if not crc_ok:
                                continue
                            now = time.time()
                            if pcap:
                                pcap.write(sniffer.pcap_record(now, frame))
                            self._post("frame", generation, now, frame, rssi)
                except (sniffer.SnifferError, usb.core.USBError) as exc:
                    self._post("status", generation, "absent", str(exc))
                    self._retune.wait(2)
                finally:
                    if dev is not None:
                        sniffer.close_sniffer(dev)
        finally:
            if pcap:
                pcap.close()


async def replay_source(queue: asyncio.Queue, path: str, speed: float) -> None:
    """Loop over a capture, keeping the gaps between frames, stamped with the current time."""
    while True:
        await queue.put(("status", 0, "replay", Path(path).name))
        previous = None
        for ts, frame in read_pcap(path):
            if previous is not None:
                await asyncio.sleep(min(max(ts - previous, 0) / speed, 5))
            previous = ts
            await queue.put(("frame", 0, time.time(), frame, None))
        await asyncio.sleep(2)


async def demo_source(queue: asyncio.Queue, speed: float) -> None:
    await queue.put(("status", 0, "demo", ""))

    async def emit(frame: bytes, rssi: int) -> None:
        await queue.put(("frame", 0, time.time(), frame, rssi))

    await demo.DemoNetwork(emit, speed).run()


async def pump(queue: asyncio.Queue, hub: Hub) -> None:
    while True:
        kind, generation, *rest = await queue.get()
        if generation != hub.generation:
            continue
        if kind == "status":
            await hub.set_status(*rest)
        else:
            ts, frame, rssi = rest
            await hub.publish(frame, ts, rssi)


def _local_only(request: web.Request) -> bool:
    port = request.app["port"]
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origin = request.headers.get("Origin")
    return request.host in allowed and (origin is None or origin in {f"http://{h}" for h in allowed})


async def handle_index(request: web.Request) -> web.StreamResponse:
    if not _local_only(request):
        raise web.HTTPForbidden()
    page = resources.files("zigbee_live_map").joinpath("static/index.html").read_text(encoding="utf-8")
    return web.Response(text=page, content_type="text/html", headers={"Cache-Control": "no-store"})


async def handle_ws(request: web.Request) -> web.StreamResponse:
    hub: Hub = request.app["hub"]
    if not _local_only(request) or request.headers.get("Origin") is None:
        raise web.HTTPForbidden()
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    await ws.send_json(hub.hello())
    await ws.send_json(hub.status)
    await ws.send_str(json.dumps({"type": "backlog", "events": list(hub.events)}, separators=(",", ":")))
    hub.clients.add(ws)
    try:
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            try:
                data = json.loads(msg.data)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            if data.get("type") == "rename":
                await hub.rename(str(data.get("ieee", "")), str(data.get("name", "")))
            elif data.get("type") == "channel" and isinstance(data.get("channel"), int):
                await hub.tune(data["channel"])
    finally:
        hub.clients.discard(ws)
    return ws


async def serve(args) -> None:
    mode = "demo" if args.demo else "replay" if args.replay else "live"
    if mode == "demo":
        names_path, names, focus = None, demo.names(), args.focus
    else:
        names_path = Path(args.names)
        names, focus = names_store.load(names_path), args.focus
    info = {"channel": args.channel if mode == "live" else None, "mode": mode, "focus": focus, "can_tune": mode == "live"}
    hub = Hub(names_path, names, info, args.backlog)
    queue: asyncio.Queue = asyncio.Queue()
    tasks = [asyncio.create_task(pump(queue, hub))]
    if mode == "demo":
        tasks.append(asyncio.create_task(demo_source(queue, args.speed)))
    elif mode == "replay":
        tasks.append(asyncio.create_task(replay_source(queue, args.replay, args.speed)))
    else:
        hub.source = LiveSource(asyncio.get_running_loop(), queue, args.channel, args.pcap)
        hub.source.thread.start()

    app = web.Application()
    app["hub"], app["port"] = hub, args.port
    app.add_routes([web.get("/", handle_index), web.get("/ws", handle_ws)])
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", args.port).start()
    url = f"http://127.0.0.1:{args.port}/"
    print(f"zigbee-live-map {__version__}: {url}  ({mode}{f', channel {args.channel}' if mode == 'live' else ''})", flush=True)
    if args.open:
        import webbrowser

        webbrowser.open(url)
    try:
        await asyncio.Event().wait()
    finally:
        for task in tasks:
            task.cancel()
        if hub.source:
            hub.source.stop()
        await runner.cleanup()
