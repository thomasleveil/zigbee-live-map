"""A small reverse proxy (HTTP and WebSocket) that serves a running zigbee-live-map under a path prefix.

Home Assistant's ingress does this: the app answers at "/" but the browser sees it under something like
/api/hassio_ingress/<token>/, so any absolute URL in a page (href="/static/x.js", fetch("/api/...")) breaks.
Try the pages behind a prefix, with an instance running on 8793:

    .venv/bin/python tests/prefix_proxy.py --listen 8794 --target http://127.0.0.1:8793 --prefix /api/hassio_ingress/test123/

then open http://127.0.0.1:8794/api/hassio_ingress/test123/ . Anything outside the prefix is a 404.

By default the Host header is rewritten to the target's (as most reverse proxies are set up to do), which is what an
instance on a loopback bind expects. --keep-host forwards the browser's own Host instead, to see how the server
reacts to a host name it does not know. Like Home Assistant, the proxy adds X-Ingress-Path and X-Forwarded-For; the
server must not trust either.
"""
from __future__ import annotations

import argparse
import asyncio
from urllib.parse import urlsplit

import aiohttp
from aiohttp import WSMsgType, web
from multidict import CIMultiDict

SESSION = web.AppKey("session", aiohttp.ClientSession)
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade",
              "content-length", "host"}


def make_app(target: str, prefix: str, keep_host: bool = False) -> web.Application:
    prefix = "/" + prefix.strip("/") + "/"
    base = target.rstrip("/")
    authority = urlsplit(base).netloc
    ws_base = "ws" + base[len("http"):]

    def upstream_headers(request: web.Request) -> CIMultiDict:
        headers = CIMultiDict((k, v) for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP)
        headers["Host"] = request.host if keep_host else authority
        headers["X-Ingress-Path"] = prefix.rstrip("/")
        headers["X-Forwarded-For"] = request.remote or ""
        return headers

    async def forward(request: web.Request) -> web.StreamResponse:
        path = request.raw_path.split("?", 1)[0]
        if not path.startswith(prefix):
            raise web.HTTPNotFound(text=f"outside the prefix {prefix}")
        rest = "/" + path[len(prefix):]
        query = request.query_string
        suffix = rest + ("?" + query if query else "")
        session = request.app[SESSION]
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await relay_websocket(request, session, ws_base + suffix)
        async with session.request(request.method, base + suffix, headers=upstream_headers(request), data=await request.read(), allow_redirects=False) as upstream:
            headers = CIMultiDict((k, v) for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP)
            location = headers.get("Location")
            if location and location.startswith(base):   # a server that names itself absolutely: put the prefix back
                headers["Location"] = prefix.rstrip("/") + location[len(base):]
            return web.Response(status=upstream.status, headers=headers, body=await upstream.read())

    async def relay_websocket(request: web.Request, session: aiohttp.ClientSession, url: str) -> web.StreamResponse:
        headers = upstream_headers(request)
        for name in ("Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol", "Accept-Encoding"):
            headers.pop(name, None)
        try:
            upstream = await session.ws_connect(url, headers=headers)
        except aiohttp.WSServerHandshakeError as exc:   # the server refused: say so with its own status
            return web.Response(status=exc.status, text=exc.message)
        browser = web.WebSocketResponse(heartbeat=20)
        await browser.prepare(request)

        async def pump(source, sink) -> None:
            async for message in source:
                if message.type == WSMsgType.TEXT:
                    await sink.send_str(message.data)
                elif message.type == WSMsgType.BINARY:
                    await sink.send_bytes(message.data)
                else:
                    break

        tasks = [asyncio.create_task(pump(browser, upstream)), asyncio.create_task(pump(upstream, browser))]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await upstream.close()
        await browser.close()
        return browser

    async def session_context(app: web.Application):
        async with aiohttp.ClientSession(auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar()) as session:   # cookies belong to the browser
            app[SESSION] = session
            yield

    app = web.Application()
    app.cleanup_ctx.append(session_context)
    app.router.add_route("*", "/{tail:.*}", forward)
    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="Serve a running zigbee-live-map under a path prefix, as Home Assistant ingress does.")
    ap.add_argument("--listen", type=int, required=True, metavar="PORT", help="port of the proxy (on 127.0.0.1)")
    ap.add_argument("--target", required=True, metavar="URL", help="the running instance, e.g. http://127.0.0.1:8793")
    ap.add_argument("--prefix", default="/api/hassio_ingress/test123/", metavar="PATH", help="path the pages are served under")
    ap.add_argument("--keep-host", action="store_true", help="forward the browser's Host header instead of the target's")
    args = ap.parse_args()
    prefix = "/" + args.prefix.strip("/") + "/"
    print(f"open http://127.0.0.1:{args.listen}{prefix}", flush=True)
    web.run_app(make_app(args.target, prefix, args.keep_host), host="127.0.0.1", port=args.listen, print=None)


if __name__ == "__main__":
    main()
