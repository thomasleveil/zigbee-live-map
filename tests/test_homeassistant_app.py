"""What can be checked about the Home Assistant app without Docker or a Supervisor: its files agree with each other and with the tool.

The YAML files of the app are read by a small reader for the subset they use (nested maps, lists of scalars, scalars): no YAML library
is a dependency of the tool, and a file that leaves the subset fails the tests here instead of being misread.
"""
from __future__ import annotations

import os
import re
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


def test_runs_under_the_base_images_init_and_builds_locally():
    assert CONFIG["init"] is False   # S6 overlay must be process 1 (an `init: true` stops the container at once)
    assert "image" not in CONFIG   # with an image key the Supervisor pulls it instead of building the folder
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
    assert repo["name"] and "PLACEHOLDER" in text
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


@pytest.mark.parametrize("name", ["config.yaml", "Dockerfile", "start.sh", "DOCS.md", "translations/en.yaml", "../try-locally.sh"])
def test_no_machine_path_or_private_value_in_the_app_files(name):
    text = (APP / name).read_text(encoding="utf-8")
    assert not re.search(r"/Users/|/home/\w|/private/", text)
    assert "thomasleveil" not in text.lower()


def test_the_wheel_is_never_built_straight_into_the_app_folder():
    """uv writes a .gitignore that ignores everything into its output folder: built there, it hides the whole app from git."""
    assert not (APP / ".gitignore").exists()
    for path in (ROOT / "README.md", APP / "DOCS.md", APP.parent / "try-locally.sh"):
        for line in path.read_text(encoding="utf-8").splitlines():
            assert not ("--out-dir" in line and "homeassistant/zigbee_live_map" in line), f"{path.name}: {line.strip()}"
            assert '--out-dir "$APP_DIR' not in line, f"{path.name}: {line.strip()}"
