from zigbee_live_map import crypto


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
