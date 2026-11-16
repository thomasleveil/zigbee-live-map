"""Who may use the server: the local, ingress and lan channels, the password, the host allowlist and the login.

No test here binds anything but 127.0.0.1 on a port the system picks. A test that needs "a network bind" declares it
(Access(host="0.0.0.0")) while the socket stays on loopback, and plays the Home Assistant supervisor with the
`supervisor` parameter. Passwords and addresses are invented.

Select a group with -k bind, allowed_host, "lan and auth", fail_closed, login or ingress.
"""
import asyncio
import hmac
import json
import re
from http.cookies import SimpleCookie
from importlib import resources

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

from zigbee_live_map import access as acc, cli, server
from zigbee_live_map.access import Access, AccessError, LoginGuard, Sessions, Throttle, parse_allowed_host
from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.server import Hub, build_app
from zigbee_live_map.vendors import Registry

PASSWORD = "synthetic passphrase 7 of 9"
NET = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
SECRET_LIST = "Synthetic secret list"
INFO = {"channel": None, "mode": "replay", "focus": None, "can_tune": False}
PAGES = ("/", "/devices")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def lan(**kw):
    """A server started on the network: declared non-loopback, still listening on loopback in the test."""
    return Access(host="0.0.0.0", password=PASSWORD, **kw)


def serve(scenario, tmp_path, access=None, clock=None):
    async def main():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), dict(INFO), 100)
        hub.keys.set("0x1a62", NET.hex(), "Home")
        hub.list_id = hub.store.create(SECRET_LIST)
        async with TestClient(TestServer(build_app(hub, access, **({"clock": clock} if clock else {})), host="127.0.0.1")) as client:
            await scenario(client, hub)

    asyncio.run(main())


async def sign_in(client, password=PASSWORD, **kw):
    return await client.post("/login", data={"password": password}, allow_redirects=False, **kw)


async def token_of(client):
    return (await (await client.get("/api/session")).json())["token"]


def guarded(client, token, origin=None):
    return {"Origin": origin or f"http://127.0.0.1:{client.server.port}", "X-ZLM-Token": token}


async def ws_status(client, path, **kw):
    try:
        ws = await client.ws_connect(path, **kw)
    except aiohttp.WSServerHandshakeError as exc:
        return exc.status
    await ws.close()
    return 101


def locale_keys(name):
    return json.loads(resources.files("zigbee_live_map").joinpath("static", "locales", name).read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------ bind and start-up

def test_bind_defaults_to_loopback_and_the_local_rules_are_unchanged(tmp_path):
    assert cli.parser().parse_args([]).host == "127.0.0.1"
    assert Access().loopback and Access().channel("203.0.113.9") == acc.LOCAL   # whoever the peer is: the bind decides

    async def scenario(client, hub):
        assert (await client.get("/")).status == 200
        assert (await client.get("/", headers={"Host": "evil.example"})).status == 403
        assert (await client.get("/login")).status == 404   # no login where there is nothing to log in to
        session = await (await client.get("/api/session")).json()
        assert session["token"] and session["signOut"] is False
        assert (await client.post("/api/lists", json={"name": "x"})).status == 403   # no token

    for access in (None, Access()):
        serve(scenario, tmp_path, access)


@pytest.mark.parametrize("host, expected", [("127.0.0.1", True), ("127.1.2.3", True), ("::1", True), ("localhost", True), ("::ffff:127.0.0.1", True),
                                            ("0.0.0.0", False), ("::", False), ("", False), ("192.0.2.10", False), ("10.1.2.3", False)])
def test_bind_loopback_detection(host, expected):
    assert acc.is_loopback(host) is expected


def _no_serve(monkeypatch, calls=None):
    async def fake(args, access=None):
        if calls is not None:
            calls.append((args, access))
        else:
            raise AssertionError("the server must not start")

    monkeypatch.setattr(server, "serve", fake)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10"])
def test_bind_non_loopback_without_password_or_ingress_refuses_to_start(host, monkeypatch, capsys):
    monkeypatch.delenv("ZLM_PASSWORD", raising=False)
    _no_serve(monkeypatch)
    assert cli.main(["--host", host, "--demo", "--port", "8793"]) == 2
    err = capsys.readouterr().err
    assert "ZLM_PASSWORD" in err and "--password-file" in err and "--ingress" in err and host in err


def test_bind_non_loopback_with_a_password_or_ingress_starts(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ZLM_PASSWORD", raising=False)
    calls = []
    _no_serve(monkeypatch, calls)
    secret = tmp_path / "pw"
    secret.write_text(PASSWORD + "\nsecond line is ignored\n")
    assert cli.main(["--host", "0.0.0.0", "--demo", "--ingress"]) == 0
    assert cli.main(["--host", "0.0.0.0", "--demo", "--password-file", str(secret), "--allowed-host", "zigbee.home.example:8765", "--allowed-host", "nas"]) == 0
    monkeypatch.setenv("ZLM_PASSWORD", PASSWORD)
    assert cli.main(["--host", "0.0.0.0", "--demo"]) == 0
    ingress_only, from_file, from_env = (access for _args, access in calls)
    assert ingress_only.password is None and ingress_only.ingress
    assert from_file.password == PASSWORD and from_file.allowed_hosts == (("zigbee.home.example", 8765), ("nas", None))
    assert from_env.password == PASSWORD and not from_env.ingress
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err and PASSWORD not in repr(from_file)   # never printed


def test_bind_password_comes_from_the_environment_or_a_file_never_the_command_line(monkeypatch, tmp_path, capsys):
    _no_serve(monkeypatch)
    for argv in (["--password", "hunter2"], ["--pass", "hunter2"], ["--passwd=x"]):   # not an option, and not an abbreviation of one
        with pytest.raises(SystemExit) as exit_:
            cli.parser().parse_args(argv)
        assert exit_.value.code == 2
    assert not any("password" in a.dest for a in cli.parser()._actions if a.dest != "password_file")
    env = {"ZLM_PASSWORD": "from env"}
    assert acc.read_password(env, None) == "from env" and acc.read_password({}, None) is None
    file = tmp_path / "pw"
    file.write_text("from file\r\nsecond\n")
    assert acc.read_password(env, str(file)) == "from file"   # the explicit flag wins, first line only, line end removed


@pytest.mark.parametrize("content", ["", "\n", "   \n", "\nsecond line"])
def test_bind_empty_password_is_refused(content, tmp_path, monkeypatch, capsys):
    file = tmp_path / "pw"
    file.write_text(content)
    with pytest.raises(AccessError, match="empty"):
        acc.read_password({}, str(file))
    for env in ({"ZLM_PASSWORD": ""}, {"ZLM_PASSWORD": "  "}):
        with pytest.raises(AccessError, match="empty"):
            acc.read_password(env, None)
    monkeypatch.setenv("ZLM_PASSWORD", "")
    _no_serve(monkeypatch)
    assert cli.main(["--host", "0.0.0.0", "--demo"]) == 2
    assert "empty" in capsys.readouterr().err


def test_bind_password_file_problems_do_not_echo_the_path(tmp_path):
    for bad in (str(tmp_path / "missing-name-xyz"), str(tmp_path)):
        with pytest.raises(AccessError) as error:
            acc.read_password({}, bad)
        assert "missing-name-xyz" not in str(error.value) and str(tmp_path) not in str(error.value)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(AccessError):
        acc.read_password({}, str(binary))


def test_bind_start_up_line_prints_a_url_that_matches_the_bind_and_open_opens_it(monkeypatch, capsys, tmp_path):
    assert Access(host="127.0.0.1").url(8793) == "http://127.0.0.1:8793/"
    assert Access(host="localhost").url(8793) == "http://localhost:8793/"
    assert Access(host="::1").url(8793) == "http://[::1]:8793/"
    assert Access(host="192.0.2.10", password="x").url(8793) == "http://192.0.2.10:8793/"
    assert Access(host="0.0.0.0", password="x").url(8793) == "http://127.0.0.1:8793/"   # a wildcard is not an address: this computer reaches it on loopback
    assert Access(host="::", password="x").url(8793) == "http://[::1]:8793/"
    opened = []
    monkeypatch.setattr("webbrowser.open", opened.append)

    async def run(host):
        args = cli.parser().parse_args(["--demo", "--host", host, "--port", "0", "--open", "--data-dir", str(tmp_path)])
        task = asyncio.create_task(server.serve(args, Access(host=host)))
        for _ in range(100):
            await asyncio.sleep(0.05)
            if opened:
                break
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run("127.0.0.1"))
    line = capsys.readouterr().out
    assert opened and opened[0] in line and re.fullmatch(r"http://127\.0\.0\.1:\d+/", opened[0]) and not opened[0].endswith(":0/")


# ------------------------------------------------------------------------------------------ the host allowlist

def test_allowed_host_parsing():
    assert parse_allowed_host("Zigbee.Home.Example") == ("zigbee.home.example", None)
    assert parse_allowed_host("nas.local:8765") == ("nas.local", 8765)
    assert parse_allowed_host("[::1]:80") == ("::1", 80)
    for bad in ("", "  ", "http://nas", "nas/path", "a b", "user@nas", "nas:notaport", "nas:99999", "nas?x"):
        with pytest.raises(AccessError):
            parse_allowed_host(bad)


def test_allowed_host_socket_address_and_mapped_forms():
    a = Access(host="0.0.0.0", password="x")
    assert a.host_ok("192.0.2.5:8765", "192.0.2.5", 8765)
    assert a.host_ok("192.0.2.5:8765", "::ffff:192.0.2.5", 8765)   # a dual-stack socket reports the mapped form
    assert a.host_ok("[2001:db8::5]:8765", "2001:db8::5", 8765)
    assert a.host_ok("[fe80::5]:8765", "fe80::5%en0", 8765)
    assert not a.host_ok("192.0.2.5", "192.0.2.5", 8765)       # the port is part of it
    assert not a.host_ok("192.0.2.6:8765", "192.0.2.5", 8765)  # another address of this computer is not the one asked on
    assert not a.host_ok("192.0.2.5:8765@evil.example", "192.0.2.5", 8765)
    assert not a.host_ok("evil.example@192.0.2.5:8765", "192.0.2.5", 8765)
    assert not a.host_ok("", "192.0.2.5", 8765)


def test_allowed_host_checks_every_lan_request_before_anything_else(tmp_path):
    allowed = (parse_allowed_host("zigbee.home.example"), parse_allowed_host("ha.local:8123"))

    async def scenario(client, hub):
        port = client.server.port
        ok = (f"127.0.0.1:{port}", "zigbee.home.example", f"ZIGBEE.home.example:{port}", "ha.local:8123")
        refused = ("127.0.0.1", "127.0.0.1:1", f"localhost:{port}", "evil.example", f"evil.example:{port}", "zigbee.home.example:9999",
                   "ha.local", f"ha.local:{port}", f"127.0.0.1:{port}@evil.example", f"evil.example@127.0.0.1:{port}")
        for host in ok:
            assert (await client.get("/login", headers={"Host": host})).status == 200, host
        for host in refused:
            for path in ("/login", "/", "/static/common.js", "/locales", "/api/lists", "/nope"):
                assert (await client.get(path, headers={"Host": host})).status == 403, (host, path)   # 403 even where a login would follow
            assert (await client.post("/login", data={"password": PASSWORD}, headers={"Host": host})).status == 403, host
        assert (await client.get("/api/session", headers={"Host": "evil.example"})).status == 403
        assert (await sign_in(client)).status == 303
        assert (await client.get("/api/lists")).status == 200
        assert (await client.get("/api/lists", headers={"Host": "evil.example"})).status == 403   # a valid cookie does not make a foreign Host acceptable
        assert (await client.get("/api/lists", headers={"Host": "zigbee.home.example"})).status == 200

    serve(scenario, tmp_path, lan(allowed_hosts=allowed))


def test_allowed_host_origin_must_name_an_allowed_host_when_present(tmp_path):
    async def scenario(client, hub):
        port = client.server.port
        assert (await sign_in(client)).status == 303
        token = await token_of(client)
        url = "/api/lists"
        for origin, status in ((f"http://127.0.0.1:{port}", 200), ("http://127.0.0.1", 200), ("https://zigbee.home.example", 200),
                               ("https://zigbee.home.example:8443", 200), ("http://evil.example", 403), ("null", 403), ("", 403),
                               (f"http://localhost:{port}", 403), ("http://127.0.0.1.evil.example", 403)):
            made = await client.post(url, json={"name": origin or "empty"}, headers={"Origin": origin, "X-ZLM-Token": token})
            assert made.status == status, origin
        assert (await client.post(url, json={"name": "no origin"}, headers={"X-ZLM-Token": token})).status == 200   # curl and scripts send none
        assert (await ws_status(client, f"/ws?token={token}", headers={"Origin": "http://evil.example"})) == 403
        assert (await ws_status(client, f"/ws?token={token}", headers={"Origin": f"http://127.0.0.1:{port}"})) == 101
        read = await client.get(url, headers={"Origin": "http://evil.example"})   # a read is answered as locally: the browser withholds it from that site
        assert read.status == 200 and not any(n.lower().startswith("access-control-") for n in read.headers)

    serve(scenario, tmp_path, lan(allowed_hosts=(parse_allowed_host("zigbee.home.example"),)))


# ------------------------------------------------------------------------------------------ lan: authentication

def test_lan_auth_without_the_cookie_nothing_leaks(tmp_path):
    async def scenario(client, hub):
        assert (await sign_in(client)).status == 303
        token = await token_of(client)
        client.session.cookie_jar.clear()   # the same browser, signed out; the token below is a valid one
        secrets = (NET.hex(), token, SECRET_LIST, "0x1a62", PASSWORD)
        extra = guarded(client, token)
        for path in PAGES:
            for headers in ({}, extra):
                found = await client.get(path, headers=headers, allow_redirects=False)
                body = await found.text()
                assert found.status == 302 and found.headers["Location"] == "login", path   # relative, and no page body
                assert not any(s in body for s in secrets)
        for path in ("/api/session", "/api/keys", "/api/lists", "/api/hue", "/api/vendors", f"/api/lists/{hub.list_id}/export?format=json",
                     f"/api/lists/{hub.list_id}/export?format=csv", "/api/nothing"):
            for headers in ({}, extra):
                found = await client.get(path, headers=headers, allow_redirects=False)
                body = await found.text()
                assert found.status == 401, path
                assert not any(s in body for s in secrets), path
        for method, path in (("POST", "/api/lists"), ("PUT", "/api/keys/0x1a62"), ("DELETE", "/api/hue"), ("POST", "/api/vendors/refresh"), ("POST", "/logout")):
            sent = await client.request(method, path, json={"key": NET.hex()}, headers=extra, allow_redirects=False)
            assert sent.status == 401, (method, path)
        for query in ("", f"?token={token}"):
            assert await ws_status(client, "/ws" + query, headers=extra) == 401
        assert hub.store.describe()[0]["name"] == SECRET_LIST and len(hub.store.describe()) == 1   # nothing was changed either

    serve(scenario, tmp_path, lan())


def test_lan_auth_a_forged_or_stale_cookie_is_not_a_session(tmp_path):
    async def scenario(client, hub):
        for value in ("", "x", "a" * 43, "../..", "zlm_session"):
            found = await client.get("/api/keys", headers={"Cookie": f"zlm_session={value}"})
            assert found.status == 401
        assert (await client.get("/api/keys", headers={"Cookie": f"other={PASSWORD}"})).status == 401

    serve(scenario, tmp_path, lan())


def test_lan_auth_open_routes_are_the_login_static_files_and_locales_only(tmp_path):
    async def scenario(client, hub):
        for path in ("/login", "/static/common.js", "/static/common.css", "/locales", "/locales/en.json", "/locales/fr.json"):
            assert (await client.get(path)).status == 200, path
        for path in ("/static/index.html", "/static/..%2Fserver.py", "/locales/zz.json"):
            assert (await client.get(path)).status == 404, path   # open, and still only what they were
        for method, path in (("POST", "/static/common.js"), ("POST", "/locales"), ("DELETE", "/login"), ("PUT", "/login")):
            assert (await client.request(method, path)).status == 401, (method, path)
        for path in ("/ws", "/api/session", "/nope", "/devices.html", "/login/", "/login/x"):
            assert (await client.get(path, allow_redirects=False)).status in (302, 401), path

    serve(scenario, tmp_path, lan())


def test_lan_auth_signed_in_still_needs_the_token_for_changes_and_the_live_connection(tmp_path):
    async def scenario(client, hub):
        assert (await sign_in(client)).status == 303
        for path in PAGES:
            assert (await client.get(path)).status == 200
        token = await token_of(client)
        assert (await client.post("/api/lists", json={"name": "x"})).status == 403
        assert (await client.post("/api/lists", json={"name": "x"}, headers={"X-ZLM-Token": "guess"})).status == 403
        assert (await client.post("/api/lists", json={"name": "x"}, headers={"X-ZLM-Token": token})).status == 200
        assert (await client.put("/api/keys/0x1a62", json={"key": NET.hex()})).status == 403
        assert await ws_status(client, "/ws") == 403
        assert await ws_status(client, "/ws?token=guess") == 403
        ws = await client.ws_connect(f"/ws?token={token}")
        hello = await ws.receive_json()
        assert hello["type"] == "hello"
        await ws.close()

    serve(scenario, tmp_path, lan())


def test_lan_auth_cookie_is_random_httponly_samesite_strict_and_kept_in_memory(tmp_path):
    values = []

    async def scenario(client, hub):
        for _ in range(2):
            made = await sign_in(client)
            assert made.status == 303 and made.headers["Location"] == "./"
            cookie = SimpleCookie(made.headers["Set-Cookie"])["zlm_session"]
            assert cookie["httponly"] and cookie["samesite"] == "Strict" and cookie["path"] == "/" and not cookie["secure"]
            assert int(cookie["max-age"]) == acc.SESSION_TTL and len(cookie.value) >= 40
            assert PASSWORD not in "".join(made.headers.values())
            values.append(cookie.value)
        secure = await sign_in(client, headers={"X-Forwarded-Proto": "https"})   # behind a TLS proxy the cookie says so
        assert SimpleCookie(secure.headers["Set-Cookie"])["zlm_session"]["secure"]
        assert len(set(values)) == 2

    serve(scenario, tmp_path, lan())

    async def restarted(client, hub):   # a new process: nobody is signed in
        found = await client.get("/api/keys", headers={"Cookie": f"zlm_session={values[0]}"})
        assert found.status == 401

    serve(restarted, tmp_path, lan())


def test_lan_auth_logout_ends_the_session_on_the_server(tmp_path):
    async def scenario(client, hub):
        assert (await sign_in(client)).status == 303
        session = await (await client.get("/api/session")).json()
        assert session["signOut"] is True
        sid = client.session.cookie_jar.filter_cookies(client.make_url("/"))["zlm_session"].value
        out = await client.post("/logout", headers=guarded(client, session["token"]))
        assert out.status == 200 and "zlm_session" in out.headers["Set-Cookie"]
        for _ in range(2):   # even a browser that kept the old cookie is out
            assert (await client.get("/api/keys", headers={"Cookie": f"zlm_session={sid}"})).status == 401

    serve(scenario, tmp_path, lan())


def test_lan_auth_sessions_expire_and_are_bounded():
    clock = Clock()
    sessions = Sessions(clock, ttl=100)
    sid = sessions.start()
    clock.now += 60
    assert sessions.valid(sid)
    clock.now += 60   # used 60 s ago: the lifetime counts from the last use
    assert sessions.valid(sid)
    clock.now += 101
    assert not sessions.valid(sid) and not sessions.valid(None) and not sessions.valid("")
    many = [sessions.start() for _ in range(Sessions.MAX + 5)]
    assert not sessions.valid(many[0]) and sessions.valid(many[-1]) and len(sessions._last_used) <= Sessions.MAX


# ------------------------------------------------------------------------------------------ login

def test_login_page_is_translated_accessible_and_touches_nothing_protected():
    text = resources.files("zigbee_live_map").joinpath("static", "login.html").read_text(encoding="utf-8")
    assert re.search(r'<label[^>]+for="password"', text) and re.search(r'<input[^>]+id="password"[^>]+type="password"|<input[^>]+type="password"[^>]+id="password"', text)
    assert 'autocomplete="current-password"' in text and 'method="post"' in text and 'action="login"' in text   # works without JavaScript
    assert text.count('data-state="idle"') == 1 and 'main:not([data-state="failed"]) .error' in text
    assert 'role="alert"' in text and 'data-state="idle"' in text and 'aria-invalid="false"' in text
    assert not re.search(r'(href|src|action)="/', text) and "api/" not in text   # relative, and no call that needs a session
    keys = set(re.findall(r'data-i18n(?:-aria|-placeholder)?="([\w.]+)"', text))
    assert keys, "the page is translated"
    for name in ("en.json", "fr.json"):
        assert sorted(keys - set(locale_keys(name))) == [], name
    for key in ("login.signout", "login.signout.help"):
        assert key in locale_keys("en.json") and key in locale_keys("fr.json")


def test_login_wrong_password_gets_one_plain_message_and_nothing_else(tmp_path):
    clock = Clock()

    async def scenario(client, hub):
        pages = []
        for data in ({"password": "wrong guess"}, {"password": ""}, {}, {"other": PASSWORD}, {"password": PASSWORD + " "}):
            clock.now += 1000   # far enough apart that the throttle (tested on its own) stays out of it
            found = await client.post("/login", data=data, allow_redirects=False)
            body = await found.text()
            assert found.status == 401 and "Set-Cookie" not in found.headers
            assert body.count('<main data-state="failed">') == 1 and 'main:not([data-state="failed"]) .error' in body and 'aria-invalid="true"' in body   # the element changed, the rule that hides the message did not
            assert "wrong guess" not in body and PASSWORD not in body
            pages.append(body)
        assert len(set(pages)) == 1   # whatever was wrong, the answer is the same
        clock.now += 1000
        assert (await client.post("/login", data=b"\xff\xfe", headers={"Content-Type": "application/x-www-form-urlencoded"})).status == 401
        clock.now += 1000
        assert (await client.post("/login", json={"password": PASSWORD})).status == 401   # the form is the only way in
        assert 'data-state="idle"' in await (await client.get("/login")).text()

    serve(scenario, tmp_path, lan(), clock=clock)


def test_login_right_password_signs_in_and_redirects_relatively(tmp_path):
    async def scenario(client, hub):
        made = await sign_in(client)
        assert made.status == 303 and made.headers["Location"] == "./"
        assert (await client.get("/")).status == 200
        again = await client.get("/login", allow_redirects=False)   # already in: back to the map
        assert again.status == 302 and again.headers["Location"] == "./"
        for path in PAGES:
            assert 'rel="stylesheet" href="static/common.css"' in await (await client.get(path)).text()

    serve(scenario, tmp_path, lan())


def test_login_cannot_be_forged_from_another_site_or_host(tmp_path):
    async def scenario(client, hub):
        assert (await sign_in(client, headers={"Origin": "http://evil.example"})).status == 403
        assert (await sign_in(client, headers={"Host": "evil.example"})).status == 403
        assert (await sign_in(client, headers={"Origin": f"http://127.0.0.1:{client.server.port}"})).status == 303

    serve(scenario, tmp_path, lan())


def test_login_password_is_compared_in_constant_time_on_digests(monkeypatch):
    seen = []
    real = hmac.compare_digest
    monkeypatch.setattr(hmac, "compare_digest", lambda a, b: (seen.append((a, b)), real(a, b))[1])
    access = Access(host="0.0.0.0", password="pässword ✓")
    assert access.password_ok("pässword ✓") and not access.password_ok("pässword ✗") and not access.password_ok("") and not access.password_ok("p")
    assert len(seen) == 4 and all(isinstance(a, bytes) and len(a) == len(b) == 32 for a, b in seen)   # equal length whatever the password
    assert not Access().password_ok("anything")   # no password set: nothing matches


def test_login_throttle_refuses_without_judging_and_doubles_the_wait(tmp_path):
    clock = Clock()

    async def scenario(client, hub):
        for _ in range(3):   # a few free tries
            assert (await sign_in(client, "wrong")).status == 401
        assert (await sign_in(client, "wrong")).status == 401   # judged, and now the wait is 1 s
        locked = await sign_in(client, PASSWORD)   # the right password, too early: refused, and not even compared
        assert locked.status == 429 and locked.headers["Retry-After"] == "1" and "Set-Cookie" not in locked.headers
        assert 'data-state="failed"' in await locked.text()
        assert (await client.get("/api/keys")).status == 401
        clock.now += 0.5
        assert (await sign_in(client, PASSWORD)).status == 429
        clock.now += 0.5
        assert (await sign_in(client, "wrong")).status == 401   # judged again: the wait is now 2 s
        assert (await sign_in(client, PASSWORD)).headers["Retry-After"] == "2"
        clock.now += 2
        assert (await sign_in(client, PASSWORD)).status == 303   # the right password after the wait signs in, and clears the count
        client.session.cookie_jar.clear()
        for _ in range(3):
            assert (await sign_in(client, "wrong")).status == 401

    serve(scenario, tmp_path, lan(), clock=clock)


def test_login_throttle_holds_against_attempts_made_at_the_same_time(tmp_path):
    """Headers first, bodies later: ten attempts get past a gate that is looked at before the body is read, and are all judged."""
    clock = Clock()

    async def scenario(client, hub):
        for _ in range(3):
            assert (await sign_in(client, "wrong")).status == 401   # the free tries
        body = b"password=wrong+guess"
        head = (f"POST /login HTTP/1.1\r\nHost: 127.0.0.1:{client.server.port}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        sockets = [await asyncio.open_connection("127.0.0.1", client.server.port) for _ in range(10)]
        for _reader, writer in sockets:
            writer.write(head)   # the headers alone: every handler has started and is waiting for its body
            await writer.drain()
        await asyncio.sleep(0.3)
        for _reader, writer in sockets:
            writer.write(body)
            await writer.drain()
        statuses = []
        for reader, writer in sockets:
            statuses.append(int((await reader.readline()).split()[1]))
            writer.close()
        assert statuses.count(401) <= 1 and statuses.count(429) >= 9, statuses

    serve(scenario, tmp_path, lan(), clock=clock)


def test_login_throttle_waits_double_up_to_a_cap_and_are_forgotten_after_a_while():
    clock = Clock()
    throttle = Throttle(3, clock)
    waits = []
    for _ in range(10):
        throttle.failed("peer")
        waits.append(throttle.wait("peer"))
        clock.now += throttle.wait("peer")
    assert waits == [0, 0, 0, 1, 2, 4, 8, 16, 32, 60]
    assert throttle.wait("someone else") == 0
    clock.now += Throttle.FORGET + 1
    throttle.failed("peer")
    assert throttle.wait("peer") == 0   # a long quiet spell starts the count again
    small = Throttle(0, clock)
    small.MAX_KEYS = 4
    for n in range(10):
        small.failed(f"peer{n}")
    assert len(small._state) <= 4   # an attacker cannot grow it without end


def test_login_throttle_also_counts_all_peers_together():
    clock = Clock()
    guard = LoginGuard(clock)
    for n in range(20):
        guard.failed(f"198.51.100.{n}")   # many addresses, one failure each
        assert guard.wait("203.0.113.1") == 0
    guard.failed("198.51.100.99")
    assert guard.wait("203.0.113.1") > 0 and guard.wait("198.51.100.1") > 0   # a stranger waits too
    clock.now += 1
    assert guard.wait("203.0.113.1") == 0
    guard.succeeded("198.51.100.1")


# ------------------------------------------------------------------------------------------ fail closed

@pytest.mark.parametrize("kw", [{"host": "0.0.0.0"}, {"host": "::"}, {"host": "192.0.2.10"}, {"host": "0.0.0.0", "password": ""},
                                {"host": "0.0.0.0", "password": "   "}, {"host": "127.0.0.1", "password": ""}])
def test_fail_closed_access_cannot_be_built_without_a_way_to_authenticate(kw):
    with pytest.raises(AccessError):
        Access(**kw)
    assert Access(host="0.0.0.0", ingress=True).ingress   # the one other way in: the supervisor


def test_fail_closed_ingress_alone_refuses_every_other_peer_everything(tmp_path):
    async def scenario(client, hub):
        headers = {"X-Ingress-Path": "/api/hassio_ingress/abc", "X-Remote-User-Id": "admin", "X-Forwarded-For": acc.SUPERVISOR}
        for h in ({}, headers):
            for path in ("/", "/devices", "/login", "/static/common.js", "/locales", "/locales/en.json", "/api/session", "/api/keys", "/ws", "/nope"):
                found = await client.get(path, headers=h, allow_redirects=False)
                assert found.status == 403, path
                assert NET.hex() not in await found.text()
            assert (await client.post("/login", data={"password": ""}, headers=h)).status == 403
            assert (await client.post("/api/lists", json={"name": "x"}, headers=h)).status == 403
        assert hub.store.describe()[0]["name"] == SECRET_LIST and len(hub.store.describe()) == 1

    serve(scenario, tmp_path, Access(host="0.0.0.0", ingress=True))


def test_fail_closed_the_ingress_flag_on_a_loopback_bind_trusts_nobody(tmp_path):
    """Trusting a loopback peer without a Host check would reopen DNS rebinding: here the local rules still apply, to the same peer."""
    async def scenario(client, hub):
        assert (await client.get("/api/keys", headers={"Host": "evil.example"})).status == 403
        assert (await client.post("/api/lists", json={"name": "x"})).status == 403
        assert (await client.get("/api/keys")).status == 200   # the local rules, as ever

    access = Access(host="127.0.0.1", ingress=True, supervisor="127.0.0.1")
    assert access.channel("127.0.0.1") == acc.LOCAL
    serve(scenario, tmp_path, access)


# ------------------------------------------------------------------------------------------ ingress

def test_ingress_channel_is_decided_from_the_connection_alone():
    a = Access(host="0.0.0.0", ingress=True)
    assert a.channel("172.30.32.2") == acc.INGRESS and a.channel("::ffff:172.30.32.2") == acc.INGRESS
    for peer in ("172.30.32.3", "127.0.0.1", "192.0.2.7", "::1", "", None, "not an address"):
        assert a.channel(peer) == acc.LAN
    assert Access(host="0.0.0.0", password="x").channel("172.30.32.2") == acc.LAN   # without --ingress nobody is the supervisor
    assert acc.SUPERVISOR == "172.30.32.2"
    for argv in (["--supervisor", "127.0.0.1"], ["--ingress-peer=10.0.0.1"]):
        with pytest.raises(SystemExit):
            cli.parser().parse_args(argv)   # no flag changes it


def test_ingress_supervisor_peer_needs_no_login_host_or_origin_but_still_the_token(tmp_path):
    async def scenario(client, hub):
        home = {"Host": "homeassistant.example:8123", "X-Ingress-Path": "/api/hassio_ingress/abc"}
        for path in (*PAGES, "/static/common.js", "/api/lists", "/api/vendors", "/locales"):
            assert (await client.get(path, headers=home)).status == 200, path
        session = await (await client.get("/api/session", headers=home)).json()
        assert session["signOut"] is False
        assert (await client.get("/api/keys", headers=home)).status == 200
        token = session["token"]
        proxy = {**home, "Origin": "https://homeassistant.example:8123"}   # Home Assistant's values, not this server's
        assert (await client.post("/api/lists", json={"name": "x"}, headers=proxy)).status == 403   # no token
        assert (await client.post("/api/lists", json={"name": "x"}, headers={**proxy, "X-ZLM-Token": "guess"})).status == 403
        assert (await client.post("/api/lists", json={"name": "from ha"}, headers={**proxy, "X-ZLM-Token": token})).status == 200
        assert await ws_status(client, "/ws", headers=proxy) == 403
        assert await ws_status(client, f"/ws?token={token}", headers=proxy) == 101
        ws = await client.ws_connect(f"/ws?token={token}", headers=proxy)
        assert (await ws.receive_json())["type"] == "hello"
        await ws.close()
        assert any(item["name"] == "from ha" for item in hub.store.describe())

    serve(scenario, tmp_path, Access(host="0.0.0.0", ingress=True, supervisor="127.0.0.1"))
    serve(scenario, tmp_path, lan(ingress=True, supervisor="127.0.0.1"))   # a password changes nothing for the supervisor


def test_ingress_the_same_requests_from_any_other_peer_get_nothing(tmp_path):
    """The vacuity guard: with the supervisor elsewhere, the very requests above are refused."""
    async def scenario(client, hub):
        forged = {"Host": "homeassistant.example:8123", "X-Ingress-Path": "/api/hassio_ingress/abc", "X-Remote-User-Id": "admin",
                  "X-Forwarded-For": acc.SUPERVISOR, "X-Real-IP": acc.SUPERVISOR, "Forwarded": f"for={acc.SUPERVISOR}"}
        for path in (*PAGES, "/api/session", "/api/keys", "/api/lists", "/ws"):
            assert (await client.get(path, headers=forged, allow_redirects=False)).status == 403, path   # a foreign Host first
        right_host = {**forged, "Host": f"127.0.0.1:{client.server.port}"}
        for path in PAGES:
            found = await client.get(path, headers=right_host, allow_redirects=False)
            assert found.status == 302 and found.headers["Location"] == "login"
        for path in ("/api/session", "/api/keys", "/api/lists"):
            assert (await client.get(path, headers=right_host)).status == 401
        assert (await client.post("/api/lists", json={"name": "x"}, headers=right_host)).status == 401
        assert await ws_status(client, "/ws", headers=right_host) == 401
        assert len(hub.store.describe()) == 1

    serve(scenario, tmp_path, lan(ingress=True))   # the supervisor is 172.30.32.2; the test client is 127.0.0.1


def test_ingress_pages_can_be_framed_by_home_assistant_other_channels_cannot(tmp_path):
    def framable(response):
        return "X-Frame-Options" not in response.headers and "frame-ancestors" not in response.headers.get("Content-Security-Policy", "")

    def refuses_frames(response):
        return response.headers.get("X-Frame-Options") == "DENY" and "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")

    async def ingress(client, hub):
        home = {"Host": "ha.example"}
        assert framable(await client.get("/", headers=home)) and framable(await client.get("/devices", headers=home))
        assert framable(await client.post("/api/lists", json={"name": "x"}, headers=home))   # a refusal (403) is no different

    async def other_channels(client, hub):
        assert refuses_frames(await client.get("/", headers={"Host": "evil.example"}))   # 403
        assert refuses_frames(await client.get("/", allow_redirects=False))             # 302 to the login
        assert refuses_frames(await client.get("/api/keys"))                             # 401
        assert refuses_frames(await client.get("/login"))
        assert refuses_frames(await client.post("/login", data={"password": "x"}))     # 401
        assert (await sign_in(client)).status == 303
        assert refuses_frames(await client.get("/")) and refuses_frames(await client.get("/devices"))

    async def local(client, hub):
        assert refuses_frames(await client.get("/")) and refuses_frames(await client.get("/", headers={"Host": "evil.example"}))

    serve(ingress, tmp_path, Access(host="0.0.0.0", ingress=True, supervisor="127.0.0.1"))
    serve(other_channels, tmp_path, lan())
    serve(local, tmp_path)
