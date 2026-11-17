"""What can be checked about the Home Assistant app without Docker or a Supervisor: its files agree with each other and with the tool.

The YAML files of the app are read by a small reader for the subset they use (nested maps, lists of scalars, scalars): no YAML library
is a dependency of the tool, and a file that leaves the subset fails the tests here instead of being misread.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from zigbee_live_map import __version__, access, cli

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "homeassistant" / "zigbee_live_map"
START = (APP / "start.sh").read_text(encoding="utf-8")


def scalar(text: str):
    text = text.strip()
    if text in ("null", "~", ""):
        return None
    if text in ("true", "false"):
        return text == "true"
    if text == "[]":
        return []
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    assert not text.startswith(("[", "{", "|", ">", "&", "*", "!")), f"outside the YAML subset: {text!r}"
    return text


def load_yaml(path: Path):
    rows = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip() and not raw.lstrip().startswith("#"):
            assert "\t" not in raw and not re.search(r"\s#", raw), f"outside the YAML subset: {raw!r}"
            rows.append((len(raw) - len(raw.lstrip()), raw.strip()))

    def block(i: int, indent: int):
        if rows[i][1].startswith("- "):
            items = []
            while i < len(rows) and rows[i][0] == indent and rows[i][1].startswith("- "):
                items.append(scalar(rows[i][1][2:]))
                i += 1
            return items, i
        mapping = {}
        while i < len(rows) and rows[i][0] == indent:
            key, _, rest = rows[i][1].partition(":")
            key = key.strip().strip("\"'")
            i += 1
            if rest.strip():
                mapping[key] = scalar(rest)
            elif i < len(rows) and rows[i][0] > indent:
                mapping[key], i = block(i, rows[i][0])
            else:
                mapping[key] = None
        return mapping, i

    value, end = block(0, rows[0][0])
    assert end == len(rows), f"{path.name}: line {rows[end][1]!r} is outside the YAML subset"
    return value


CONFIG = load_yaml(APP / "config.yaml")


def script_options() -> set[str]:
    return set(re.findall(r"""\bopt '\.([a-z_]+)""", START))


def test_the_reader_reads_what_it_should():
    assert CONFIG["schema"]["allowed_hosts"] == ["str"]
    assert CONFIG["ports"] == {"8099/tcp": None}
    assert CONFIG["arch"] == ["aarch64", "amd64"]


def test_config_has_the_required_keys():
    for key in ("name", "version", "slug", "description", "arch"):
        assert CONFIG.get(key), f"config.yaml lacks the required key {key}"
    assert re.fullmatch(r"[A-Za-z0-9_.-]+", CONFIG["slug"])
    assert isinstance(CONFIG["version"], str), "the version must be quoted: it is an image tag"
    assert set(CONFIG["arch"]) <= {"aarch64", "amd64"}


def test_version_matches_the_package():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    assert CONFIG["version"] == declared == __version__


def test_runs_under_the_base_images_init_and_pulls_the_published_image():
    assert CONFIG["init"] is False   # S6 overlay must be process 1 (an `init: true` stops the container at once)
    # With an image key the Supervisor pulls it instead of building the folder: the multi-arch name, no tag, no {arch}.
    assert CONFIG["image"] == "ghcr.io/thomasleveil/zigbee-live-map"
    assert CONFIG["usb"] is True   # raw /dev/bus/usb: libusb is not a serial port


def test_ingress_port_matches_the_start_script():
    assert CONFIG["ingress"] is True
    declared = re.search(r"^INGRESS_PORT=(\d+)", START, re.M)
    assert declared and int(declared.group(1)) == CONFIG["ingress_port"]
    assert '--port "$INGRESS_PORT"' in START
    assert f"{CONFIG['ingress_port']}/tcp" in CONFIG["ports"]
    assert CONFIG["ports"][f"{CONFIG['ingress_port']}/tcp"] is None   # not published unless the user turns it on


def test_schema_options_and_the_names_the_script_reads_agree():
    schema = set(CONFIG["schema"])
    assert script_options() == schema
    assert set(CONFIG["options"]) <= schema
    # every required (no "?") option has a default, or the user could not start the app
    required = {k for k, v in CONFIG["schema"].items() if not (isinstance(v, str) and v.endswith("?"))}
    assert required <= set(CONFIG["options"])
    translations = load_yaml(APP / "translations" / "en.yaml")
    assert set(translations["configuration"]) == schema
    assert set(translations["network"]) == set(CONFIG["ports"])


def test_default_options_fit_their_schema():
    options = CONFIG["options"]
    assert isinstance(options["demo"], bool) and CONFIG["schema"]["demo"] == "bool"
    low, high = map(int, re.fullmatch(r"int\((\d+),(\d+)\)", CONFIG["schema"]["channel"]).groups())
    assert (low, high) == (11, 26) and low <= options["channel"] <= high
    assert CONFIG["schema"]["password"] == "password?" and "password" not in options   # optional, unset by default
    assert options["allowed_hosts"] == []


def test_start_script_runs_the_tool_for_ingress_with_data_in_data():
    assert START.startswith("#!/command/with-contenv sh\n")
    assert os.access(APP / "start.sh", os.X_OK)
    assert "--ingress" in START
    assert re.search(r"^DATA_DIR=/data\b", START, re.M) and '--data-dir "$DATA_DIR"' in START
    assert "--host 0.0.0.0" in START
    assert "/data/options.json" in START
    assert re.search(r"^exec ", START, re.M)


def test_start_script_never_puts_the_password_on_the_command_line():
    assert "--password" not in START   # neither --password-file nor anything else: it goes in the environment
    assert f"export {access.PASSWORD_ENV}=" in START


def test_every_flag_the_script_passes_exists_in_the_tool():
    known = {opt for action in cli.parser()._actions for opt in action.option_strings}
    code = "\n".join(line for line in START.splitlines() if not line.lstrip().startswith("#"))
    passed = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", code))
    assert passed and passed <= known, passed - known
    # and a command line with every option the script can add is accepted by the real parser
    args = cli.parser().parse_args(["--host", "0.0.0.0", "--port", "8099", "--ingress", "--data-dir", "/data", "--channel", "15",
                                    "--allowed-host", "homeassistant.local", "--demo"])
    assert args.ingress and args.data_dir == "/data" and args.port == CONFIG["ingress_port"]


def test_dockerfile_pins_the_base_and_keeps_its_entrypoint():
    text = (APP / "Dockerfile").read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    base = re.fullmatch(r"FROM (ghcr\.io/home-assistant/base[a-z-]*):(\S+)", lines[0])
    assert base and base.group(2) != "latest", lines[0]
    assert not any(line.startswith("ENTRYPOINT") for line in lines)   # S6 overlay's /init stays
    assert any(line.startswith("CMD") and "start.sh" in line for line in lines)
    assert any("--only-binary=:all:" in line for line in lines)   # no compiler in the image
    assert any(line.startswith("COPY zigbee_live_map-") and line.endswith(".whl /tmp/wheel/") for line in lines)


def test_the_wheel_and_the_local_test_directory_are_ignored_by_git():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "homeassistant/zigbee_live_map/*.whl" in ignored
    assert "homeassistant/.try-locally/" in ignored


def test_repository_file_names_the_repository():
    text = (ROOT / "repository.yaml").read_text(encoding="utf-8")
    repo = load_yaml(ROOT / "repository.yaml")
    assert repo["name"] and "PLACEHOLDER" not in text
    assert repo["url"] == CONFIG["url"]   # the address people add in Home Assistant is the one the app card links to
    assert repo["maintainer"] == "Thomas Leveil"   # what LICENSE already states, and nothing more
    assert "Thomas Leveil" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_try_locally_stands_in_for_the_supervisor_faithfully():
    path = ROOT / "homeassistant" / "try-locally.sh"
    script = path.read_text(encoding="utf-8")
    assert os.access(path, os.X_OK)
    assert re.search(rf"^SUPERVISOR_IP={re.escape(access.SUPERVISOR)}\b", script, re.M)   # the address the tool trusts
    assert re.search(r"^SUBNET=172\.30\.32\.0/23\b", script, re.M)
    code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    assert "--init" not in code   # init: false in config.yaml means Docker adds none
    assert '"127.0.0.1:$PORT:80"' in script   # published on this computer only
    names = re.findall(r"^(?:APP|PROXY|NET|IMAGE)=([^\s#]+)", script, re.M)
    assert len(names) == 4 and all(n.startswith("zlm-") for n in names), names


def test_try_locally_plays_the_supervisor_with_a_dummy_token_on_purpose():
    """--ingress starts only where the Supervisor set SUPERVISOR_TOKEN: the stand-in sets one, says it is a dummy, and the tool accepts it."""
    script = (ROOT / "homeassistant" / "try-locally.sh").read_text(encoding="utf-8")
    start = script.index('docker run -d --name "$APP"')
    app_container = script[start:script.index(">/dev/null", start)]
    assert re.search(rf"-e {access.SUPERVISOR_ENV}=dummy\S*", app_container)   # on the app container, not on the proxy
    comment = script[:start].rsplit("\n\n", 1)[-1]
    assert "dummy" in comment and "on purpose" in comment and "Supervisor" in comment
    args = cli.parser().parse_args(["--host", "0.0.0.0", "--ingress"])
    assert access.from_args(args, {access.SUPERVISOR_ENV: "dummy-not-a-supervisor-token"}).ingress
    assert access.SUPERVISOR_ENV == "SUPERVISOR_TOKEN"   # the name Home Assistant documents (contributors.home-assistant.io/apps/reference/environment/)


@pytest.mark.parametrize("name", ["config.yaml", "Dockerfile", "start.sh", "DOCS.md", "README.md", "translations/en.yaml", "../try-locally.sh",
                                  "../art/icon.svg", "../art/logo.svg"])
def test_no_machine_path_or_private_value_in_the_app_files(name):
    text = (APP / name).read_text(encoding="utf-8")
    assert not re.search(r"/Users/|/home/\w|/private/", text)
    # The only personal name in these files is the public address of the repository and of its image.
    public = re.sub(r"(github\.com|ghcr\.io|raw\.githubusercontent\.com)/thomasleveil/zigbee-live-map", "", text)
    assert "thomasleveil" not in public.lower()


def test_the_wheel_is_never_built_straight_into_the_app_folder():
    """uv writes a .gitignore that ignores everything into its output folder: built there, it hides the whole app from git."""
    assert not (APP / ".gitignore").exists()
    for path in (ROOT / "README.md", APP / "DOCS.md", APP.parent / "try-locally.sh"):
        for line in path.read_text(encoding="utf-8").splitlines():
            assert not ("--out-dir" in line and "homeassistant/zigbee_live_map" in line), f"{path.name}: {line.strip()}"
            assert '--out-dir "$APP_DIR' not in line, f"{path.name}: {line.strip()}"


def run_start_script(tmp_path: Path, options: dict) -> tuple[list[str], str]:
    """start.sh as it is, with the options file moved, the tool replaced by a program that prints its arguments, one per line."""
    import json

    (tmp_path / "options.json").write_text(json.dumps(options), encoding="utf-8")
    script = START.replace("#!/command/with-contenv sh", "#!/bin/sh", 1).replace("OPTIONS_FILE=/data/options.json", f"OPTIONS_FILE={tmp_path}/options.json", 1)
    assert 'exec "$@"' in script
    script = script.replace('exec "$@"', "shift; printf '%s\\0' \"$@\"", 1)   # NUL-separated: an argument may hold any other character
    (tmp_path / "start.sh").write_text(script, encoding="utf-8")
    done = subprocess.run(["/bin/sh", str(tmp_path / "start.sh")], capture_output=True, check=True, env={"PATH": os.environ["PATH"]})
    return [a.decode() for a in done.stdout.split(b"\0")[:-1]], done.stderr.decode()


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is not installed")
def test_start_script_passes_each_allowed_host_as_exactly_one_argument(tmp_path):
    hosts = ["zigbee.home.example", "two words", "", "line\nbreak", "192.168.1.5:8099", "star*"]
    args, _err = run_start_script(tmp_path, {"demo": True, "password": "synthetic", "allowed_hosts": hosts})
    passed = [args[i + 1] for i, a in enumerate(args) if a == "--allowed-host"]
    assert args.count("--allowed-host") == 5   # the empty one is skipped, no other is split
    assert passed == ["zigbee.home.example", "two words", "line\\nbreak", "192.168.1.5:8099", "star*"]   # a newline cannot be one line of output: it is written as \n, which the tool refuses as a host name
    none, note = run_start_script(tmp_path, {"demo": True, "password": "synthetic", "allowed_hosts": ["", ""]})
    assert "--allowed-host" not in none and note == ""
    ignored, note = run_start_script(tmp_path, {"demo": True, "allowed_hosts": ["zigbee.home.example"]})
    assert "--allowed-host" not in ignored and "ignored because no password is set" in note


def test_start_script_reads_allowed_hosts_line_by_line_and_never_by_word_splitting():
    assert "while IFS= read -r" in START
    assert not re.search(r"for \w+ in \$\(opt '\.allowed_hosts", START)


def test_try_locally_stand_in_proxy_answers_only_its_own_host_names():
    """In the ingress channel the app does not check Host, by design: the stand-in for the Supervisor's proxy must, or a rebinding page could use it."""
    script = (ROOT / "homeassistant" / "try-locally.sh").read_text(encoding="utf-8")
    line = r'if (\$http_host !~ "^(127\\.0\\.0\\.1|localhost):$PORT\$") { return 403; }'   # as written in the script: a heredoc, so $ and \ are doubled up
    assert line in script, "the proxy checks Host"
    comment = script[:script.index(line)].rsplit("\n\n", 1)[-1]
    assert "DNS rebinding" in comment and "Host" in comment


# ---- publishing: the image the Supervisor pulls, and the workflow that builds it ------------------------

REPOSITORY = "https://github.com/thomasleveil/zigbee-live-map"
IMAGE = "ghcr.io/thomasleveil/zigbee-live-map"
WORKFLOW = (ROOT / ".github" / "workflows" / "build-app.yaml").read_text(encoding="utf-8")


def workflow_step(name: str) -> str:
    """The text of one step of the workflow, from its `- name:` line to the next step or job."""
    start = WORKFLOW.index(f"- name: {name}\n")
    rest = WORKFLOW[start + 1:]
    end = re.search(r"\n\s*- name: |\n  \w[\w-]*:\n", rest)
    return WORKFLOW[start:start + 1 + (end.start() if end else len(rest))]


def test_no_placeholder_address_is_left():
    for path in (ROOT / "repository.yaml", APP / "config.yaml", ROOT / "README.md", APP / "DOCS.md", APP / "README.md", ROOT / "TODO.md"):
        text = path.read_text(encoding="utf-8")
        assert "OWNER" not in text and "PLACEHOLDER" not in text, path.name
    assert CONFIG["url"] == REPOSITORY == load_yaml(ROOT / "repository.yaml")["url"]


def test_readme_installs_by_adding_the_repository():
    from urllib.parse import quote

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    link = "https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=" + quote(REPOSITORY, safe="")
    assert link in readme   # the one-click link, with the address URL-encoded
    assert f"`{REPOSITORY}`" in readme   # and the address to paste by hand


def test_workflow_reads_the_manifest_the_way_it_is_written(tmp_path):
    """The step's own shell, run on the real config.yaml: what it hands the build is what config.yaml says."""
    step = workflow_step("Read config.yaml")
    body = step[step.index("run: |\n") + len("run: |\n"):]
    indent = len(body) - len(body.lstrip(" "))
    script = "\n".join(line[indent:] for line in body.splitlines())
    out = tmp_path / "out"
    env = {"PATH": os.environ["PATH"], "APP_DIR": "homeassistant/zigbee_live_map", "GITHUB_OUTPUT": str(out)}
    subprocess.run(["bash", "-e", "-c", script], check=True, capture_output=True, cwd=ROOT, env=env)
    got = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines())
    import json

    assert got["version"] == CONFIG["version"]
    assert got["registry_prefix"] + "/" + got["image_name"] == CONFIG["image"]
    assert json.loads(got["architectures"]) == CONFIG["arch"]
    assert (got["name"], got["description"], got["url"]) == (CONFIG["name"], CONFIG["description"], CONFIG["url"])


def test_workflow_pins_every_action_to_a_release():
    used = re.findall(r"uses: (\S+)@(\S+)", WORKFLOW)
    assert len(used) >= 6
    for action, ref in used:
        assert re.fullmatch(r"v?\d+(\.\d+)+", ref), f"{action}@{ref} is not a release"
    builder = {ref for action, ref in used if action.startswith("home-assistant/builder/actions/")}
    assert len(builder) == 1, "the three builder actions come from one release"


def test_workflow_never_pushes_a_tag_twice_and_never_publishes_a_pull_request():
    build, manifest = workflow_step("Build the image"), workflow_step("Publish the multi-arch manifest")
    version = "${{ needs.prepare.outputs.version }}"
    for step in (build, manifest):
        assert f"skip-existing: {version}" in step
        tags = step[step.index("image-tags: |"):].splitlines()[1:3]
        assert [t.strip() for t in tags] == [version, "latest"]   # the first tag is the one the manifest looks the images up by
    only_main = "github.event_name != 'pull_request' && github.ref == 'refs/heads/main'"   # a run started by hand on another branch publishes nothing
    assert f"push: ${{{{ {only_main} }}}}" in build
    assert re.search(r"manifest:\n(?:.*\n)*?\s+if: " + re.escape(only_main) + r"\n", WORKFLOW)
    assert re.search(r"^permissions:\n  contents: read\n", WORKFLOW, re.M)   # write rights only on the two jobs that publish


def test_workflow_builds_from_the_app_folder_with_the_wheel_copied_in():
    assert re.search(r"^  APP_DIR: homeassistant/zigbee_live_map$", WORKFLOW, re.M)
    assert 'context: "./${{ env.APP_DIR }}"' in workflow_step("Build the image")
    wheel = workflow_step("Build the wheel and put it in the app folder")
    assert 'uv build --wheel --out-dir "$RUNNER_TEMP/wheel"' in wheel   # never straight into the app folder
    assert 'cp "$RUNNER_TEMP"/wheel/zigbee_live_map-*.whl "$APP_DIR/"' in wheel


# ------------------------------------------------------------------------------------- the tool knows it is the app

def _hello_of(access_settings, tmp_path, monkeypatch) -> dict:
    """The hello the page would get from a server started with these access settings (nothing listens)."""
    import asyncio
    import types

    from zigbee_live_map import server

    seen = []

    class Stop(Exception):
        pass

    def stop(hub, *_args, **_kwargs):
        seen.append(hub)
        raise Stop

    monkeypatch.setattr(server, "build_app", stop)
    args = types.SimpleNamespace(demo=True, replay=None, data_dir=str(tmp_path), channel=11, focus=None, backlog=100, speed=1.0,
                                 pcap=None, port=0, open=False)
    with pytest.raises(Stop):
        asyncio.run(server.serve(args, access_settings))
    return seen[0].hello()


def test_the_server_says_it_is_the_app_only_when_started_with_ingress(tmp_path, monkeypatch):
    assert _hello_of(access.Access(host="0.0.0.0", ingress=True), tmp_path, monkeypatch)["ha_app"] is True
    # A published port with a password is still the app: the fact is how the process was started, not the request's channel.
    assert _hello_of(access.Access(host="0.0.0.0", ingress=True, password="x"), tmp_path, monkeypatch)["ha_app"] is True
    assert _hello_of(access.Access(), tmp_path, monkeypatch)["ha_app"] is False
    assert _hello_of(access.Access(host="0.0.0.0", password="x"), tmp_path, monkeypatch)["ha_app"] is False


def test_start_lines_outside_home_assistant_are_unchanged():
    from zigbee_live_map.server import startup_lines

    v = __version__
    assert startup_lines(access.Access(), "http://127.0.0.1:8765/", 8765, "live", 20) == [f"zigbee-live-map {v}: http://127.0.0.1:8765/  (live, channel 20)"]
    assert startup_lines(access.Access(password="x"), "http://127.0.0.1:8765/", 8765, "demo", 11) == [
        f"zigbee-live-map {v}: http://127.0.0.1:8765/  (demo)", "  this computer only, but sign-in is required (a password is set)"]
    assert startup_lines(access.Access(host="0.0.0.0", password="x"), "http://127.0.0.1:8765/", 8765, "live", 15) == [
        f"zigbee-live-map {v}: http://127.0.0.1:8765/  (live, channel 15)", "  reachable from your network on port 8765, as plain HTTP; password required"]


def test_start_lines_of_the_app_say_how_to_open_it_and_claim_nothing_about_the_port():
    from zigbee_live_map.server import startup_lines

    for settings in (access.Access(host="0.0.0.0", ingress=True), access.Access(host="0.0.0.0", ingress=True, password="x")):
        lines = startup_lines(settings, "http://127.0.0.1:8099/", 8099, "live", 20)
        text = "\n".join(lines)
        assert lines[0] == f"zigbee-live-map {__version__}: running as a Home Assistant app (live, channel 20)"
        assert "Open Web UI" in text and "only if that port is published in the app's Network section" in text
        assert "127.0.0.1" not in text and "reachable" not in text   # the container's address means nothing in the Log tab


def _element(html: str, element_id: str) -> str:
    found = re.search(rf'<(\w+) id="{element_id}"[^>]*>(.*?)</\1>', html, re.S)
    assert found, element_id
    return found.group(2)


def test_the_notice_gives_each_variant_only_its_own_advice():
    """Desktop advice (libusb packages, udev, the --demo command) stays out of the app's notice, and Home Assistant advice out of the desktop's.
    Which variant shows is decided by ha_app in the hello (index.html); the browser check is in the Supervisor test notes."""
    import json

    static = ROOT / "src" / "zigbee_live_map" / "static"
    html = (static / "index.html").read_text(encoding="utf-8")
    desktop = _element(html, "needsDesktop") + _element(html, "needsDemoDesktop")
    app = _element(html, "needsApp") + _element(html, "needsDemoApp")
    assert re.search(r'<ol id="needsApp" hidden>', html) and re.search(r'<p id="needsDemoApp" hidden', html)   # desktop until told otherwise
    for word in ("brew", "apt", "needs.udev", "--demo", "needs.libusb"):
        assert word in desktop and word not in app, word
    assert "needs.app." not in desktop
    for name in ("en.json", "fr.json"):
        strings = json.loads((static / "locales" / name).read_text(encoding="utf-8"))
        app_texts = " ".join(v for k, v in strings.items() if k.startswith("needs.app."))
        for word in ("brew", "apt ", "udev", "--demo", "this computer", "cet ordinateur"):
            assert word not in app_texts, (name, word)
        assert "Home Assistant" in strings["needs.app.cause.not_found"] and "Home Assistant" in strings["needs.app.plug"]


def png_chunks(path: Path) -> list[tuple[str, bytes]]:
    """The chunks of a PNG file, in order: (type, data)."""
    import struct

    raw = path.read_bytes()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n", path.name
    out, at = [], 8
    while at < len(raw):
        length, kind = struct.unpack(">I4s", raw[at:at + 8])
        out.append((kind.decode("ascii"), raw[at + 8:at + 8 + length]))
        at += 12 + length
    return out


@pytest.mark.parametrize("name", ["icon.png", "logo.png"])
def test_the_store_pictures_have_the_documented_shape_and_carry_nothing_else(name):
    """icon.png is square, logo.png is wide (contributors.home-assistant.io/apps/guides/presentation/); neither holds text, a date or camera data."""
    import struct

    chunks = png_chunks(APP / name)
    width, height = struct.unpack(">II", chunks[0][1][:8])
    if name == "icon.png":
        assert width == height and width >= 128
    else:
        assert width >= 250 and 2 <= width / height <= 3
    assert {kind for kind, _ in chunks} <= {"IHDR", "PLTE", "tRNS", "gAMA", "sRGB", "cHRM", "bKGD", "pHYs", "IDAT", "IEND"}


def test_the_store_pictures_are_what_their_sources_draw():
    """Each picture has its drawing next to the app; the drawing names the command that renders it, and holds no linked file."""
    for name in ("icon", "logo"):
        source = (APP.parent / "art" / f"{name}.svg").read_text(encoding="utf-8")
        assert f"../zigbee_live_map/{name}.png" in source and "rsvg-convert" in source
        assert "href" not in source and "<image" not in source   # nothing fetched or embedded: shapes and text only


def test_the_store_page_shows_a_short_text_and_the_screenshot():
    """The app's README.md is the text of its store page. The page gets it as text: a relative picture path would point into Home Assistant."""
    text = (APP / "README.md").read_text(encoding="utf-8")
    assert len(text.split()) < 160   # "Keep it short" (same guide); the options are on the Documentation tab
    pictures = re.findall(r"!\[[^\]]+\]\(([^)\s]+)\)", text)   # every picture has a description
    assert pictures == ["https://raw.githubusercontent.com/thomasleveil/zigbee-live-map/main/docs/screenshot.png"]
    assert text.count("![") == 1 and (ROOT / "docs" / "screenshot.png").is_file()
    assert "0451:16ae" in text and "Demo network" in text and "Documentation" in text

