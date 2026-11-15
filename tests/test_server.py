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
            origin = {"Origin": f"http://127.0.0.1:{client.server.port}"}
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


def test_other_sites_cannot_read_or_change_anything(tmp_path):
    async def scenario(client, hub, origin):
        evil = {"Origin": "http://evil.example"}
        assert (await client.get("/api/lists", headers=evil)).status == 403
        assert (await client.get("/api/lists", headers={"Host": "evil.example"})).status == 403
        assert (await client.post("/api/lists", json={"name": "x"}, headers=evil)).status == 403
        assert (await client.post("/api/lists", json={"name": "x"})).status == 403  # no Origin: not our page
        assert (await client.get("/ws")).status == 403
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
        ws = await client.ws_connect("/ws", headers=origin)
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
