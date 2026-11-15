import json

import pytest

from zigbee_live_map.devices import DeviceError, DeviceStore, parse_import, parse_table

A, B = "00:11:22:33:44:55:66:02", "00:11:22:33:44:55:66:03"


def test_table_with_tab_separator_and_french_headers():
    devices = parse_table("Nom\tModèle\tIEEE\tNWK\tRôle\nPrise cuisine\tPrise\t00:11:22:33:44:55:66:02\t0x1A2B\tRouteur\n\tSans nom\t00:11:22:33:44:55:66:09\t0x0001\tRouteur\n")
    assert devices == {A: {"name": "Prise cuisine", "model": "Prise", "nwk": "0x1a2b"}}


def test_table_with_other_headers_and_compact_ieee():
    assert parse_table("ieee_address,friendly_name\n0x0011223344556603,Bedroom thermostat\n") == {B: {"name": "Bedroom thermostat"}}


def test_table_needs_ieee_and_name_columns():
    with pytest.raises(DeviceError):
        parse_table("a,b\n1,2\n")


def test_import_accepts_an_export_and_a_bare_mapping():
    assert parse_import(json.dumps({"name": "Home", "devices": {A: {"name": "Plug", "junk": 1}}})) == ("Home", {A: {"name": "Plug"}})
    assert parse_import(json.dumps({A.upper(): {"name": "Plug", "nwk": "1A2B"}})) == (None, {A: {"name": "Plug", "nwk": "0x1a2b"}})
    with pytest.raises(DeviceError):
        parse_import("{not json")


def test_lists_persist_and_merge_by_enabled_state(tmp_path):
    store = DeviceStore(tmp_path)
    home, office = store.create("Home"), store.create("Office")
    store.set_device(home, A, {"name": "Kitchen plug", "model": "Smart plug", "nwk": "0x1a2b"})
    store.set_device(office, A, {"name": "Shadowed"})
    store.set_device(office, B, {"name": "Desk lamp"})
    assert store.merged() == {A: {"name": "Kitchen plug", "model": "Smart plug", "nwk": "0x1a2b"}, B: {"name": "Desk lamp"}}
    store.update(home, enabled=False)
    assert store.merged()[A] == {"name": "Shadowed"}
    again = DeviceStore(tmp_path)
    assert [(d["name"], d["enabled"], len(d["devices"])) for d in again.describe()] == [("Home", False, 1), ("Office", True, 2)]
    again.delete(office)
    assert [d["id"] for d in DeviceStore(tmp_path).describe()] == [home]


def test_two_lists_with_the_same_name_get_distinct_ids(tmp_path):
    store = DeviceStore(tmp_path)
    assert store.create("Home") != store.create("Home")


def test_rename_from_the_map_goes_to_the_list_that_knows_the_device(tmp_path):
    store = DeviceStore(tmp_path)
    store.rename(A, "First name")  # no list yet: a default one appears
    default = store.describe()[0]
    assert default["name"] == "My devices" and default["devices"] == {A: {"name": "First name"}}
    other = store.create("Aaa first in order")
    store.rename(A, "Second name")
    assert store.lists[default["id"]]["devices"][A]["name"] == "Second name" and not store.lists[other]["devices"]
    store.rename(A, "")
    assert A not in store.merged()


def test_export_round_trips_through_import(tmp_path):
    store = DeviceStore(tmp_path)
    home = store.create("Home")
    store.set_device(home, A, {"name": "Prise, été", "model": "Smart plug", "nwk": "0x1a2b"})
    for fmt in ("json", "csv"):
        name, _type, text = store.export(home, fmt)
        assert name == f"home.{fmt}"
        copy = store.create(f"Copy {fmt}")
        assert store.import_text(copy, text) == 1
        assert store.lists[copy]["devices"] == store.lists[home]["devices"]


def test_invalid_input_is_refused(tmp_path):
    store = DeviceStore(tmp_path)
    home = store.create("Home")
    for bad in (lambda: store.create("  "), lambda: store.set_device(home, "nope", {"name": "x"}),
                lambda: store.set_device(home, A, {"name": ""}), lambda: store.update("missing", name="x")):
        with pytest.raises(DeviceError):
            bad()


def test_memory_store_for_the_demo_never_touches_disk():
    store = DeviceStore(None)
    store.rename(A, "Demo plug")
    assert store.merged() == {A: {"name": "Demo plug"}}
