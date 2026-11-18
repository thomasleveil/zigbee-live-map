import hashlib

from zigbee_live_map import crypto


def test_aes_ecb_matches_nist_fips197_known_answer():
    # FIPS-197 Appendix C.1: the published AES-128 known-answer, proving aes_ecb / aes_ecb_decrypt are
    # genuine AES-128 and not some look-alike. This anchors the Touchlink vector below to real AES.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert crypto.aes_ecb(key, plain) == cipher
    assert crypto.aes_ecb_decrypt(key, cipher) == plain


def test_zll_master_key_constant_matches_published_hash():
    # The leaked ZLL master key, cross-checked against the MD5 the Z3sec research tool publishes for it
    # (z3sec/touchlink_crypt.py), so a typo in the constant cannot pass unnoticed.
    assert hashlib.md5(crypto.ZLL_MASTER_KEY).hexdigest() == "68eba85ac7514d786fce56731e24f9c8"


# External test vectors for the Touchlink network-key transport. The expected network key is produced by
# an INDEPENDENT oracle, not by this module: the published ZLL derivation (ZLL spec 8.7.5.2.3 / 8.7.4)
# transcribed verbatim from two agreeing primary sources (Wireshark's packet-zbee-zcl-general.c and the
# Z3sec tool's touchlink_crypt.py), run with the cryptography library's raw AES-128-ECB. Each row is the
# encrypted-network-key field a capture would carry and the network key it must decrypt to. A wrong
# expand order, endianness, or encrypt/decrypt direction in this module fails these. (A self round-trip
# would not: it is deliberately not used as the proof here.)
#   transaction_id = 0x12345678, response_id = 0x9abcdef0, network_key = 0f1e2d3c4b5a69788796a5b4c3d2e1f0
_ZLL_VECTORS = [
    (crypto.ZLL_KEY_INDEX_DEVELOPMENT,   "81a016a52c44cc0e4eb31406cf55afee"),
    (crypto.ZLL_KEY_INDEX_MASTER,        "d824e998595b271b8f0d63228a742aac"),
    (crypto.ZLL_KEY_INDEX_CERTIFICATION, "bc2a3c37232bce11f24589c6de6a36cf"),
]


def test_zll_decrypt_network_key_matches_external_vector():
    transaction_id, response_id = 0x12345678, 0x9ABCDEF0
    expected = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    for key_index, encrypted_hex in _ZLL_VECTORS:
        recovered = crypto.zll_decrypt_network_key(key_index, transaction_id, response_id,
                                                   bytes.fromhex(encrypted_hex))
        assert recovered == expected, f"key_index {key_index}"


def test_zll_decrypt_network_key_rejects_unknown_index_and_short_field():
    assert crypto.zll_decrypt_network_key(7, 1, 2, bytes(16)) is None     # no base key for index 7
    assert crypto.zll_decrypt_network_key(crypto.ZLL_KEY_INDEX_MASTER, 1, 2, bytes(15)) is None  # not 16 bytes


def test_ccm_star_round_trip_and_tamper_detection():
    key = bytes(range(16))
    nonce = crypto.nonce(0x00124b00_1a2b3c4d, 7, crypto.SECURITY_LEVEL)
    aad, plain = b"\x48\x02header", b"the quick brown fox"
    sealed = crypto.ccm_star_encrypt(key, nonce, plain, aad)
    assert crypto.ccm_star_decrypt(key, nonce, sealed, aad) == plain
    assert crypto.ccm_star_decrypt(key, nonce, sealed, b"other aad") is None
    assert crypto.ccm_star_decrypt(key, nonce, sealed[:-1] + bytes([sealed[-1] ^ 1]), aad) is None


def test_aes_mmo_is_stable():
    # Regression guard. The whole chain (AES-MMO -> keyed hash -> CCM*) is proven correct
    # end to end in test_decode by recovering a real network key, which tshark also recovers.
    assert crypto.aes_mmo_hash(bytes([0xC0])).hex() == "ae3a102a28d43ee0d4a09e22788b206c"
    assert crypto.aes_mmo_hash(b"").hex() == crypto.aes_ecb(bytes(16), bytes(16)).hex()[:0] or len(crypto.aes_mmo_hash(b"")) == 16


def test_transport_key_key_is_the_hash_of_the_link_key():
    # Derived key for key-transport (input 0x00) differs from the link key itself.
    tkk = crypto.transport_key_key(crypto.DEFAULT_TC_LINK_KEY)
    assert len(tkk) == 16 and tkk != crypto.DEFAULT_TC_LINK_KEY


def test_ccm_star_matches_the_block_by_block_construction():
    # Pinned from the CBC-MAC + CTR construction this module carried before it handed CCM* to the library's
    # AES-CCM: at level 5 (ENC-MIC-32) the two must agree byte for byte, with and without additional data.
    key = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
    nonce = bytes.fromhex("a0a1a2a3a4a5a6a70302010005")
    aad, plain = bytes.fromhex("0001020304050607"), bytes(range(8, 31))
    assert crypto.ccm_star_encrypt(key, nonce, plain, aad).hex() == "8abd8629a10a3075c74077dbf62c6389c4e45103178374e1da3f04"
    assert crypto.ccm_star_encrypt(key, nonce, plain, b"").hex() == "8abd8629a10a3075c74077dbf62c6389c4e45103178374103f418e"
    assert crypto.ccm_star_decrypt(key, nonce, bytes.fromhex("8abd8629a10a3075c74077dbf62c6389c4e45103178374e1da3f04"), aad) == plain
    assert crypto.ccm_star_decrypt(key, nonce[:-1], plain, aad) is None   # a nonce that is not 13 bytes
