import asyncio

from aiohttp.test_utils import TestClient, TestServer

from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.server import Hub, build_app
from zigbee_live_map.vendors import Registry

IEEE = "00:12:4b:00:00:00:00:01"


def run(scenario, tmp_path):
    async def main():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), {"channel": None, "mode": "replay", "focus": None, "can_tune": False}, 100)
        async with TestClient(TestServer(build_app(hub), host="127.0.0.1")) as client:
            token = (await (await client.get("/api/session")).json())["token"]
            origin = {"Origin": f"http://127.0.0.1:{client.server.port}", "X-ZLM-Token": token}
            await scenario(client, hub, origin)

    asyncio.run(main())


def test_pages_texts_and_static_files_are_served(tmp_path):
    async def scenario(client, hub, origin):
        for path in ("/", "/devices", "/static/common.js", "/static/common.css", "/locales/fr.json"):
            assert (await client.get(path)).status == 200, path
        codes = [item["code"] for item in await (await client.get("/locales")).json()]
        assert "en" in codes and "fr" in codes
        for path in ("/static/..%2Fserver.py", "/static/index.html", "/locales/..%2F..%2Fserver.json", "/locales/zz.json"):
            assert (await client.get(path)).status == 404, path

    run(scenario, tmp_path)


def test_page_resources_load_whatever_origin_header_the_browser_adds(tmp_path):
    """Some browsers and extensions attach an Origin header to plain same-page resources."""
    async def scenario(client, hub, origin):
        for header in ({"Origin": "null"}, {"Origin": "http://something.else"}, origin, {}):
            for path in ("/", "/devices", "/static/common.css", "/static/common.js", "/locales", "/locales/en.json", "/api/lists", "/api/vendors"):
                assert (await client.get(path, headers=header)).status == 200, (path, header)

    run(scenario, tmp_path)


def test_changes_work_when_the_browser_rewrites_the_origin_header(tmp_path):
    """Seen in the field: a browser sending "http://127.0.0.1" with the port dropped."""
    async def scenario(client, hub, origin):
        token = origin["X-ZLM-Token"]
        for rewritten in ("http://127.0.0.1", "http://localhost", "http://127.0.0.1:1"):
            made = await client.post("/api/lists", json={"name": rewritten}, headers={"Origin": rewritten, "X-ZLM-Token": token})
            assert made.status == 200, rewritten
        ws = await client.ws_connect(f"/ws?token={token}", headers={"Origin": "http://127.0.0.1"})
        assert (await ws.receive_json())["type"] == "hello"
        await ws.close()

    run(scenario, tmp_path)


def test_other_sites_cannot_read_or_change_anything(tmp_path):
    async def scenario(client, hub, origin):
        evil = {"Origin": "http://evil.example"}
        token = origin["X-ZLM-Token"]
        assert (await client.get("/api/lists", headers={"Host": "evil.example"})).status == 403  # DNS rebinding
        assert (await client.post("/api/lists", json={"name": "x"}, headers=evil)).status == 403
        assert (await client.post("/api/lists", json={"name": "x"}, headers={**evil, "X-ZLM-Token": token})).status == 403  # even with a token
        assert (await client.post("/api/lists", json={"name": "x"})).status == 403  # no token: not our page
        assert (await client.post("/api/lists", json={"name": "x"}, headers={"X-ZLM-Token": "guess"})).status == 403
        assert (await client.get("/ws")).status == 403
        assert (await client.get("/ws", headers=evil)).status == 403
        assert (await client.get(f"/ws?token={token}", headers=evil)).status == 403
        read = await client.get("/api/lists", headers=evil)  # sent, but the browser will not let that site see it
        assert not any(name.lower().startswith("access-control-") for name in read.headers)
        assert hub.store.describe() == []

    run(scenario, tmp_path)


def test_device_lists_api(tmp_path):
    async def scenario(client, hub, origin):
        list_id = (await (await client.post("/api/lists", json={"name": "Home"}, headers=origin)).json())["id"]
        base = f"/api/lists/{list_id}"
        assert (await client.put(f"{base}/devices/{IEEE}", json={"name": "Stick", "nwk": "0"}, headers=origin)).status == 200
        bad = await client.put(f"{base}/devices/nope", json={"name": "x"}, headers=origin)
        assert bad.status == 400 and "IEEE" in (await bad.json())["error"]
        state = await (await client.get("/api/lists")).json()
        assert state["lists"][0]["devices"] == {IEEE: {"name": "Stick", "nwk": "0x0000"}}
        assert state["vendors"] == {IEEE: "Texas Instruments"} and state["persistent"] is True
        imported = await client.post(f"{base}/import", data="name,ieee\nPlug,00:11:22:33:44:55:66:02\n", headers=origin)
        assert (await imported.json()) == {"imported": 1}
        export = await client.get(f"{base}/export?format=csv")
        assert "attachment" in export.headers["Content-Disposition"] and "Plug" in await export.text()
        assert (await client.patch(base, json={"enabled": False}, headers=origin)).status == 200
        assert hub.store.merged() == {}
        assert (await client.delete(f"{base}/devices/{IEEE}", headers=origin)).status == 200
        assert (await client.delete(base, headers=origin)).status == 200
        assert (await client.delete(base, headers=origin)).status == 400

    run(scenario, tmp_path)


def test_map_pages_learn_names_and_chip_makers_over_the_websocket(tmp_path):
    async def scenario(client, hub, origin):
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        hello = await ws.receive_json()
        assert hello["type"] == "hello" and hello["names"] == {} and hello["vendors"] == {}
        await ws.receive_json()  # status
        await ws.receive_json()  # backlog
        await ws.send_json({"type": "rename", "ieee": IEEE, "name": "Stick"})
        update = await ws.receive_json()
        assert update == {"type": "names", "names": {IEEE: {"name": "Stick"}}, "vendors": {IEEE: "Texas Instruments"}}
        assert hub.store.describe()[0]["name"] == "My devices"
        await ws.close()

    run(scenario, tmp_path)
