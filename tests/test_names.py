import pytest

from zigbee_live_map import names


def test_import_tab_separated_table(tmp_path):
    table = tmp_path / "devices.tsv"
    table.write_text("Name\tModel\tIEEE\tNWK\tRole\nKitchen plug\tSmart plug\t00:11:22:33:44:55:66:02\t0x1A2B\tRouter\n\tNo name\t00:11:22:33:44:55:66:09\t0x0001\tRouter\n")
    store = {}
    assert names.import_table(table, store) == 1
    assert store == {"00:11:22:33:44:55:66:02": {"name": "Kitchen plug", "model": "Smart plug", "nwk": "0x1a2b"}}


def test_import_csv_with_other_headers_and_ieee_format(tmp_path):
    table = tmp_path / "devices.csv"
    table.write_text("ieee_address,friendly_name\n0x0011223344556603,Bedroom thermostat\n")
    store = {"00:11:22:33:44:55:66:03": {"model": "kept"}}
    assert names.import_table(table, store) == 1
    assert store["00:11:22:33:44:55:66:03"] == {"model": "kept", "name": "Bedroom thermostat"}


def test_import_needs_ieee_and_name_columns(tmp_path):
    table = tmp_path / "bad.csv"
    table.write_text("a,b\n1,2\n")
    with pytest.raises(ValueError):
        names.import_table(table, {})


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "names.json"
    names.save(path, {"00:11:22:33:44:55:66:02": {"name": "Prise été"}})
    assert names.load(path) == {"00:11:22:33:44:55:66:02": {"name": "Prise été"}}
    assert names.load(tmp_path / "missing.json") == {}


def test_import_accepts_french_headers(tmp_path):
    table = tmp_path / "appareils.tsv"
    table.write_text("Nom\tModèle\tIEEE\tNWK\tRôle\nPrise cuisine\tPrise\t00:11:22:33:44:55:66:04\t0x00AF\tRouteur\n")
    store = {}
    assert names.import_table(table, store) == 1
    assert store["00:11:22:33:44:55:66:04"] == {"name": "Prise cuisine", "model": "Prise", "nwk": "0x00af"}
