"""An independent Zigbee stack as an oracle for this tool's own decoders.

zigpy implements the layers above the radio (ZCL, ZDO) for Home Assistant. It shares no code with this tool, so
when the two agree on the same bytes, a mistake would have to be made twice. Here zigpy writes the bytes and this
tool reads them, or the other way round. zigpy is a development dependency only (GPL-3.0, Python 3.11 or later):
the tool never imports it, which the first test holds, and these tests are skipped where it is not installed.
"""

import re
import struct
from pathlib import Path

import pytest

pytest.importorskip("zigpy", reason="zigpy, the oracle of these tests, needs Python 3.11 or later")

import zigpy.types as t   # noqa: E402
import zigpy.zcl   # noqa: E402
import zigpy.zdo.types as zdo_t   # noqa: E402
from zigpy.util import aes_mmo_hash   # noqa: E402
from zigpy.zcl import foundation   # noqa: E402
from zigpy.zcl.clusters.lightlink import LightLink   # noqa: E402

from zigbee_live_map import builders, crypto, decode, wire   # noqa: E402

REPORT, READ_RESPONSE = 0x0A, 0x01
SERVER_TO_CLIENT = foundation.Direction.Server_to_Client


def test_the_tool_itself_never_imports_zigpy():
    for source in Path(decode.__file__).parent.glob("*.py"):
        assert not re.search(r"^\s*(import|from)\s+zigpy", source.read_text(encoding="utf-8"), re.M), source.name
    pyproject = (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    runtime = re.search(r"^dependencies = \[(.*?)\]", pyproject, re.M | re.S).group(1)
    assert "zigpy" not in runtime


def test_zcl_headers_written_by_zigpy_are_read_the_same():
    for manufacturer in (None, 0x100B):
        for direction in foundation.Direction:
            general = foundation.ZCLHeader.general(tsn=0x5A, command_id=REPORT, manufacturer=manufacturer, direction=direction)
            cluster = foundation.ZCLHeader.cluster(tsn=0x5B, command_id=0x02, manufacturer=manufacturer, direction=direction)
            for header in (general, cluster):
                ours = decode.zcl_header(header.serialize() + b"\x01\x02")
                assert ours["global"] is header.frame_control.is_general
                assert (ours["seq"], ours["command"], ours["manufacturer"]) == (header.tsn, header.command_id, manufacturer)
                assert bool(ours["fc"] & 0x08) is (direction is SERVER_TO_CLIENT)
                assert bool(ours["fc"] & 0x10) is bool(header.frame_control.disable_default_response)
                assert ours["body"] == b"\x01\x02"


def _report(*attributes) -> bytes:
    header = foundation.ZCLHeader.general(tsn=1, command_id=REPORT, direction=SERVER_TO_CLIENT)
    return header.serialize() + b"".join(a.serialize() for a in attributes)


def _attribute(attrid: int, type_id: int, value) -> foundation.Attribute:
    return foundation.Attribute(attrid=attrid, value=foundation.TypeValue(type=type_id, value=value))


SAMPLES = {   # a value worth reading for each kind of type: one that a wrong width or a wrong sign would change
    "bool_": 1, "map8": 0xA5, "map16": 0xA55A, "map24": 0xA55AA5, "map32": 0xA55AA55A,
    "uint8": 200, "uint16": 60000, "uint24": 0xFEDCBA, "uint32": 0xFEDCBA98, "uint40": 0xFEDCBA9876,
    "uint48": 0xFEDCBA987654, "uint56": 0xFEDCBA98765432, "uint64": 0xFEDCBA9876543210,
    "int8": -5, "int16": -1250, "int24": -70000, "int32": -2_000_000_000, "enum8": 3, "enum16": 0x0102,
    "single": -12.5,
}


def test_every_attribute_type_this_tool_reads_is_read_as_zigpy_wrote_it():
    sentinel = _attribute(0x0021, 0x20, t.uint8_t(100))
    seen = set()
    for type_id in sorted(decode.ZCL_TYPE_LEN):
        info = foundation.DataType.from_type_id(type_id)
        if info.name not in SAMPLES:
            continue   # the no-data type, the opaque data8..data32 and the half-precision float: no value zigpy writes simply
        seen.add(info.name)
        written = info.python_type(SAMPLES[info.name])
        values = decode.zcl_values(_report(_attribute(0x0001, type_id, written), sentinel))
        assert values == {0x0001: SAMPLES[info.name], 0x0021: 100}, info.name
    assert seen == set(SAMPLES)
    text = _attribute(0x0005, 0x42, t.CharacterString("TRADFRI bulb E27"))
    assert decode.zcl_values(_report(text, sentinel)) == {0x0005: "TRADFRI bulb E27", 0x0021: 100}


def test_the_widths_of_the_types_this_tool_skips_are_zigpys():
    for type_id, width in decode.ZCL_TYPE_LEN.items():
        python_type = foundation.DataType.from_type_id(type_id).python_type
        try:
            written = python_type(0).serialize()
        except TypeError:
            continue   # the no-data type and the opaque data8..data32: zigpy builds them from bytes, their width is in their name
        assert len(written) == width, hex(type_id)


def test_the_frames_the_demo_builds_are_what_zigpy_expects_from_a_device():
    basic = decode.aps_header(builders.zcl_basic_response("IKEA of Sweden", "TRADFRI bulb E27", 1, sw="2.3.093", seq=9))
    header, rest = foundation.ZCLHeader.deserialize(basic["payload"])
    assert header.frame_control.is_general and header.command_id == READ_RESPONSE and header.tsn == 9
    assert header.direction is SERVER_TO_CLIENT   # a device answers: the server side of the cluster speaks
    records, left = foundation.GENERAL_COMMANDS[READ_RESPONSE].schema.deserialize(rest)
    assert left == b""
    theirs = {r.attrid: r.value.value for r in records.status_records if r.status == foundation.Status.SUCCESS}
    ours = decode.zcl_values(basic["payload"])
    assert ours == {k: (v if isinstance(v, str) else int(v)) for k, v in theirs.items()}
    names = zigpy.zcl.clusters.general.Basic.attributes
    assert [names[a].name for a in ours] == ["manufacturer", "model", "power_source", "sw_build_id"]
    assert decode.device_info(basic)["identity"] == {"manufacturer": "IKEA of Sweden", "model": "TRADFRI bulb E27", "power": "mains", "sw": "2.3.093"}

    report = decode.aps_header(builders.power_config_report(77, seq=4))
    header, rest = foundation.ZCLHeader.deserialize(report["payload"])
    assert header.command_id == REPORT and header.direction is SERVER_TO_CLIENT
    attributes, left = foundation.GENERAL_COMMANDS[REPORT].schema.deserialize(rest)
    assert left == b"" and [(a.attrid, int(a.value.value)) for a in attributes.attribute_reports] == [(0x0021, 154)]   # half-percents
    assert decode.device_info(report)["battery"] == {"percent": 77}
    assert decode.exchange(report) == {"seq": "c4", "expects": False}   # a report asks for no default response


def test_a_neighbour_table_written_by_zigpy_is_read_the_same():
    neighbour = zdo_t.Neighbor(
        extended_pan_id=t.ExtendedPanId.convert("11:22:33:44:55:66:77:88"), ieee=t.EUI64.convert("00:15:8d:00:01:a2:b3:c4"),
        nwk=t.NWK(0x3388), device_type=zdo_t.Neighbor.DeviceType.EndDevice, rx_on_when_idle=zdo_t.Neighbor.RxOnWhenIdle.Off,
        relationship=zdo_t.Neighbor.Relationship.Child, reserved1=0, permit_joining=zdo_t.Neighbor.PermitJoins.NotAccepting,
        reserved2=0, depth=2, lqi=47)
    table = zdo_t.Neighbors(Entries=3, StartIndex=1, NeighborTableList=[neighbour])
    zdo = bytes([0x2A, zdo_t.Status.SUCCESS]) + table.serialize()
    assert decode.mgmt_lqi(zdo) == {"total": 3, "start": 1, "rows": [
        {"addr": "0x3388", "ieee": "00:15:8d:00:01:a2:b3:c4", "type": "end_device", "rel": "child", "depth": 2, "lqi": 47}]}
    assert zdo_t.ZDOCmd.Mgmt_Lqi_rsp == decode.MGMT_LQI_RSP


def test_the_aes_mmo_hash_is_zigpys_at_every_padding_boundary():
    for length in range(0, 50):   # the padding changes shape around 14, 16, 30 and 32 bytes
        data = bytes((7 * i + length) & 0xFF for i in range(length))
        assert crypto.aes_mmo_hash(data) == aes_mmo_hash(data).serialize(), length


def test_a_touchlink_scan_response_is_laid_out_as_zigpy_reads_it():
    frame = builders.build_touchlink_scan_response(seq=3, pan=0x1A62, mac_dst=0x0000, mac_src=0x3344,
                                                   transaction_id=0x12345678, response_id=0x9ABCDEF0)
    read = wire.read(frame)
    zcl = frame[read.net.end + 5:]   # after the APS stub: frame control, cluster, profile
    header, rest = foundation.ZCLHeader.deserialize(zcl)
    assert header.frame_control.is_cluster and header.command_id == decode.ZLL_CMD_SCAN_RESPONSE
    theirs, _ = LightLink.client_commands[header.command_id].schema.deserialize(rest)
    assert (theirs.inter_pan_transaction_id, theirs.response_id) == decode.touchlink_scan_response(frame) == (0x12345678, 0x9ABCDEF0)
    assert LightLink.cluster_id == decode.TOUCHLINK_CLUSTER
