import stat

import pytest

from zigbee_live_map.devices import DeviceError
from zigbee_live_map.keys import KeyStore, normalise_key, normalise_pan

SAMPLE = "00112233445566778899aabbccddeeff"


def test_keys_persist_to_disk_with_owner_only_permissions(tmp_path):
    store = KeyStore(tmp_path)
    store.set("3c7e", SAMPLE, "Home")                    # a bare PAN is accepted and normalised
    again = KeyStore(tmp_path)                            # a later session reads it back
    assert again.get("0x3c7e").hex() == SAMPLE
    assert again.describe() == [{"pan": "0x3c7e", "label": "Home", "key": SAMPLE}]
    mode = stat.S_IMODE((tmp_path / "keys.json").stat().st_mode)
    assert mode == 0o600                                  # owner read/write only


def test_delete_and_memory_mode():
    store = KeyStore(None)                                # demo mode: in memory, no file
    store.set("0x1a62", SAMPLE)
    assert store.get("0x1a62").hex() == SAMPLE
    store.delete("0x1a62")
    assert store.get("0x1a62") is None


def test_bad_pan_and_value_are_rejected():
    with pytest.raises(DeviceError):
        normalise_pan("zzzz")
    with pytest.raises(DeviceError):
        normalise_key("00")                              # not 16 bytes
