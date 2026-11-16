"""The pages behind a path prefix, as Home Assistant ingress serves them: every URL they request must resolve under it.

Run through tests/prefix_proxy.py, in process. The URLs are read out of the page and out of the scripts it loads,
template literals included, then resolved against the page's own address the way a browser does.
Select with -k prefix or -k urls.
"""
import asyncio
import re
from importlib import resources
from urllib.parse import urljoin, urlsplit

import aiohttp
import pytest
from aiohttp.test_utils import TestServer
from prefix_proxy import make_app

from zigbee_live_map.access import Access
from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.server import Hub, build_app
from zigbee_live_map.vendors import Registry

PREFIX = "/api/hassio_ingress/test123/"
PASSWORD = "synthetic passphrase 7 of 9"
INFO = {"channel": None, "mode": "replay", "focus": None, "can_tune": False}
STATIC = resources.files("zigbee_live_map").joinpath("static")
TEXTS = ("index.html", "devices.html", "common.js", "login.html")

# What a page asks the network for: attributes, then the call sites that take a URL (a string, or a template literal).
ATTRIBUTE = re.compile(r'\b(?:href|src|action)="([^"]*)"')
CALLS = [re.compile(p) for p in (
    r'\bfetch\(\s*[`"]([^`"]+)[`"]',
    r'\bgetJson\(\s*[`"]([^`"]+)[`"]',
    r'\bcall\(\s*"[A-Z]+",\s*[`"]([^`"]+)[`"]',
    r'\bhueCall\(\s*"([^"]+)"',
    r'\bnew URL\(\s*"([^"]+)"',
    r'\blocation\.assign\(\s*"([^"]+)"',
    r'\.href\s*=\s*[`"]([^`"]+)[`"]',
)]
ABSOLUTE = re.compile(r"""["'`]/(?:api|static|locales|ws|devices|login|logout)\b|\bwss?://|\bhttps?://""")


def urls_in(text: str) -> set[str]:
    found = set(ATTRIBUTE.findall(text))
    for pattern in CALLS:
        found |= set(pattern.findall(text))
    return {re.sub(r"\$\{[^}]*\}", "x", url) for url in found if url and not url.startswith(("data:", "#"))}


def test_urls_the_pages_name_are_relative_and_the_extractor_sees_them():
    for name in TEXTS:
        text = STATIC.joinpath(name).read_text(encoding="utf-8")
        assert not ABSOLUTE.search(text), name
        for url in urls_in(text):
            assert not url.startswith("/") and "//" not in url, (name, url)
    seen = set().union(*(urls_in(STATIC.joinpath(n).read_text(encoding="utf-8")) for n in TEXTS))
    # The ones that break under a prefix if they are written with a leading slash, found in every spelling the pages use.
    for expected in ("static/common.css", "static/common.js", "devices", "./", "api/session", "locales", "locales/en.json", "locales/x.json",
                     "api/lists", "api/lists/x/export?format=json", "api/lists/x/devices/x", "api/lists/x/fill-identities", "api/keys", "api/keys/x",
                     "api/hue", "api/hue/pair", "api/vendors", "api/vendors/refresh", "ws", "login", "logout"):
        assert expected in seen, expected


async def started(hub, access=None):
    app_server = TestServer(build_app(hub, access), host="127.0.0.1")
    await app_server.start_server()
    proxy = TestServer(make_app(f"http://127.0.0.1:{app_server.port}", PREFIX), host="127.0.0.1")
    await proxy.start_server()
    return app_server, proxy


def behind_prefix(scenario, tmp_path, access=None):
    async def main():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), dict(INFO), 100)
        app_server, proxy = await started(hub, access)
        try:
            async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as http:
                await scenario(http, f"http://127.0.0.1:{proxy.port}", hub)
        finally:
            await proxy.close()
            await app_server.close()

    asyncio.run(main())


def resolves_under_prefix(base: str, page_url: str, url: str) -> str:
    resolved = urljoin(page_url, url)
    assert resolved.startswith(base + PREFIX), f"{url!r} on {page_url} resolves to {resolved}"
    return resolved


def test_prefix_both_pages_load_and_every_url_they_request_resolves_under_it(tmp_path):
    async def scenario(http, base, hub):
        requested = set()
        for page in ("", "devices"):
            page_url = f"{base}{PREFIX}{page}"
            async with http.get(page_url) as response:
                assert response.status == 200 and "<title>" in await response.text()
            texts = [await (await http.get(page_url)).text()]
            for script in ("static/common.js",):
                texts.append(await (await http.get(resolves_under_prefix(base, page_url, script))).text())
            assert not any(ABSOLUTE.search(t) for t in texts)
            for text in texts:
                for url in urls_in(text):
                    requested.add(resolves_under_prefix(base, page_url, url))
        assert len(requested) > 25
        for url in sorted(requested):   # what a plain read can fetch is really served under the prefix
            if "/x" in url or url.endswith("/x") or any(part in url for part in ("hue/", "vendors/refresh", "logout", "/ws", "/login")):   # (login: a page on a lan bind only):
                continue
            response = await http.get(url, allow_redirects=False)
            assert response.status == 200, url
        outside = await http.get(f"{base}/static/common.js")   # the proxy serves nothing outside the prefix
        assert outside.status == 404

    behind_prefix(scenario, tmp_path)


def test_prefix_changes_and_the_live_connection_work_through_it(tmp_path):
    async def scenario(http, base, hub):
        page_url = f"{base}{PREFIX}"
        session = await (await http.get(resolves_under_prefix(base, page_url, "api/session"))).json()
        origin = {"Origin": base}   # the browser's own address, not the server's
        made = await http.post(resolves_under_prefix(base, page_url, "api/lists"), json={"name": "Through the proxy"}, headers={**origin, "X-ZLM-Token": session["token"]})
        assert made.status == 200 and hub.store.describe()[0]["name"] == "Through the proxy"
        assert (await http.post(resolves_under_prefix(base, page_url, "api/lists"), json={"name": "x"}, headers=origin)).status == 403   # still no token, no change
        ws_url = urlsplit(resolves_under_prefix(base, page_url, "ws"))._replace(scheme="ws", query=f"token={session['token']}").geturl()   # what index.html builds
        async with http.ws_connect(ws_url, headers=origin) as ws:
            assert (await ws.receive_json())["type"] == "hello"
            await ws.send_json({"type": "rename", "ieee": "00:12:4b:00:00:00:00:01", "name": "Stick"})
            seen = [(await ws.receive_json()) for _ in range(3)]   # status, backlog, then the answer to the rename
            assert any(m.get("type") == "names" for m in seen)
        with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
            await http.ws_connect(ws_url.split("?")[0], headers=origin)
        assert refused.value.status == 403

    behind_prefix(scenario, tmp_path)


def test_prefix_lan_login_redirects_stay_under_it(tmp_path):
    async def scenario(http, base, hub):
        page_url = f"{base}{PREFIX}"
        first = await http.get(page_url, allow_redirects=False)
        assert first.status == 302 and first.headers["Location"] == "login"
        login_url = resolves_under_prefix(base, page_url, first.headers["Location"])
        assert login_url == f"{base}{PREFIX}login" and (await http.get(login_url)).status == 200
        failed = await http.post(login_url, data={"password": "wrong"}, allow_redirects=False)
        assert failed.status == 401
        signed = await http.post(login_url, data={"password": PASSWORD}, allow_redirects=False)
        assert signed.status == 303
        assert resolves_under_prefix(base, login_url, signed.headers["Location"]) == page_url   # back to the map, still under the prefix
        assert (await http.get(page_url)).status == 200 and (await http.get(f"{page_url}devices")).status == 200
        session = await (await http.get(resolves_under_prefix(base, page_url, "api/session"))).json()
        assert session["signOut"] is True
        ws_url = urlsplit(resolves_under_prefix(base, page_url, "ws"))._replace(scheme="ws", query=f"token={session['token']}").geturl()
        async with http.ws_connect(ws_url, headers={"Origin": base}) as ws:   # the cookie travels with it
            assert (await ws.receive_json())["type"] == "hello"
        out = await http.post(resolves_under_prefix(base, page_url, "logout"), headers={"Origin": base, "X-ZLM-Token": session["token"]})
        assert out.status == 200
        assert (await http.get(page_url, allow_redirects=False)).status == 302

    behind_prefix(scenario, tmp_path, Access(host="0.0.0.0", password=PASSWORD))


def test_prefix_ingress_needs_no_login_behind_it(tmp_path):
    async def scenario(http, base, hub):
        page_url = f"{base}{PREFIX}"
        for page in ("", "devices"):
            assert (await http.get(f"{page_url}{page}", allow_redirects=False)).status == 200
        session = await (await http.get(resolves_under_prefix(base, page_url, "api/session"))).json()
        ws_url = urlsplit(resolves_under_prefix(base, page_url, "ws"))._replace(scheme="ws", query=f"token={session['token']}").geturl()
        async with http.ws_connect(ws_url, headers={"Origin": "https://ha.example"}) as ws:   # Home Assistant's own Origin
            assert (await ws.receive_json())["type"] == "hello"

    # The proxy here connects from loopback, so the test plays the supervisor; the real address is a constant.
    behind_prefix(scenario, tmp_path, Access(host="0.0.0.0", ingress=True, supervisor="127.0.0.1"))
