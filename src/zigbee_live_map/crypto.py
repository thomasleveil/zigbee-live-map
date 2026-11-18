"""Zigbee security math, so the tool can decrypt traffic when a key is known or recoverable.

Nothing here attacks anything. It is the standard, published Zigbee crypto (IEEE 802.15.4 CCM*,
the AES-MMO keyed hash of the ZigBee spec), used on traffic the user is entitled to read:

- the famous default Trust Center link key ``ZigBeeAlliance09`` is built in, so the tool can tell
  whether a device's join could be decrypted with it, which is exactly the vulnerability to flag;
- given a network key (entered by the user, or recovered from a join secured with the default link
  key), NWK payloads decrypt, which turns the encrypted part into device identity and the routers'
  own link-quality figures.

AES-128 and AES-CCM come from the `cryptography` library; the AES-MMO keyed hash and the Touchlink key
derivation, which no library offers under a licence this tool can ship, are built on the AES block here.
The one Zigbee quirk is that frames are transmitted with a security level of 0 but secured as level 5
(ENC-MIC-32); decryption restores level 5.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

DEFAULT_TC_LINK_KEY = bytes.fromhex("5a6967426565416c6c69616e63653039")  # "ZigBeeAlliance09"
ZLL_MASTER_KEY = bytes.fromhex("9f5595f10257c8a469cbf42bc93fee31")       # leaked Touchlink (ZLL) master key
ZLL_CERTIFICATION_KEY = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")  # the public ZLL certification (test) key
SECURITY_LEVEL = 5   # ENC-MIC-32: AES encryption + 32-bit MIC, the level Zigbee secures with
MIC_LEN = 4

# Touchlink (ZLL) key-transport key indices: which base key a commissioning join used (ZLL spec 8.7).
ZLL_KEY_INDEX_DEVELOPMENT = 0
ZLL_KEY_INDEX_MASTER = 4
ZLL_KEY_INDEX_CERTIFICATION = 15

# Public link keys, so the tool can tell a user who pastes one that it is not a network key.
KNOWN_LINK_KEYS = {
    DEFAULT_TC_LINK_KEY: "the default Trust Center link key (ZigBeeAlliance09)",
    ZLL_MASTER_KEY: "the Touchlink (ZLL) master key",
}


def link_key_name(key: bytes) -> str | None:
    """If these bytes are a well-known link key (not a network key), say which one."""
    return KNOWN_LINK_KEYS.get(bytes(key))


def aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - ECB is the raw block primitive for CCM*/MMO
    return enc.update(block) + enc.finalize()


def aes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    """Inverse of aes_ecb. Used to unwrap the Touchlink network key, which is AES-ECB encrypted."""
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305 - raw block primitive, see aes_ecb
    return dec.update(block) + dec.finalize()


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# --- AES-MMO hash and the ZigBee keyed hash (spec section B.1.3 / B.1.4) ---------------------

def aes_mmo_hash(data: bytes) -> bytes:
    digest = bytes(16)
    padded = data + b"\x80"
    while len(padded) % 16 != 0:
        padded += b"\x00"
    if (len(data) * 8) % (16 * 8) > (16 * 8) - 16 or len(padded) - len(data) < 3:
        padded += b"\x00" * 16  # room for the length field in a fresh block
    padded = padded[:-2] + (len(data) * 8).to_bytes(2, "big")
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        digest = _xor(aes_ecb(digest, block), block)
    return digest


def keyed_hash(key: bytes, input_byte: int) -> bytes:
    """ZigBee Keyed Hash Function (HMAC shape over AES-MMO), as used to derive APS transport keys."""
    ipad, opad = b"\x36" * 16, b"\x5c" * 16
    inner = aes_mmo_hash(_xor(key, ipad) + bytes([input_byte]))
    return aes_mmo_hash(_xor(key, opad) + inner)


def transport_key_key(link_key: bytes) -> bytes:
    """The key that actually secures an APS Transport-Key command (hash of the link key, input 0x00)."""
    return keyed_hash(link_key, 0x00)


# --- Touchlink (ZigBee Light Link) network-key transport ------------------------------------
#
# A Touchlink commissioning join carries the network key encrypted under a transport key, a scheme
# entirely separate from the APS keyed-hash path above. It is the published ZLL mechanism (ZLL spec
# section 8.7.5.2.3 for the master/certification keys, 8.7.4 for the development key), used here only
# to read the operator's own commissioning frames with a publicly known key. The derivation below is
# the one implemented by Wireshark's dissector (packet-zbee-zcl-general.c, dissect_zcl_touchlink_
# network_join_request) and by the Z3sec research tool (touchlink_crypt.py); the two agree byte for
# byte, and a unit test pins it to an external vector.
#
# The 32-bit inter-PAN transaction identifier and response identifier are read little-endian off the
# wire but expanded big-endian here, exactly as both references do.

def _u32_be(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "big")


def zll_transport_key(key_index: int, transaction_id: int, response_id: int) -> bytes | None:
    """The transport key that encrypts the network key in a Touchlink join, or None for an unknown index.

    Master and certification keys: AES-ECB-encrypt, under the base key the index selects, a 16-byte block
    of the transaction id twice followed by the response id twice. Development key: the block is the
    transport key itself ("PhLi" + transaction id + "CLSN" + response id), with no base key."""
    if key_index == ZLL_KEY_INDEX_DEVELOPMENT:
        return b"PhLi" + _u32_be(transaction_id) + b"CLSN" + _u32_be(response_id)
    base = {ZLL_KEY_INDEX_MASTER: ZLL_MASTER_KEY, ZLL_KEY_INDEX_CERTIFICATION: ZLL_CERTIFICATION_KEY}.get(key_index)
    if base is None:
        return None
    expanded = _u32_be(transaction_id) * 2 + _u32_be(response_id) * 2
    return aes_ecb(base, expanded)


def zll_decrypt_network_key(key_index: int, transaction_id: int, response_id: int, encrypted_key: bytes) -> bytes | None:
    """Recover the network key a Touchlink join transports, or None if the index is unsupported or the
    field is not 16 bytes. The network key is the AES-ECB *decryption* of the field under the transport key."""
    if len(encrypted_key) != 16:
        return None
    transport_key = zll_transport_key(key_index, transaction_id, response_id)
    if transport_key is None:
        return None
    return aes_ecb_decrypt(transport_key, encrypted_key)


# --- CCM* (IEEE 802.15.4 / ZigBee) -----------------------------------------------------------
#
# CCM* differs from plain CCM (RFC 3610) only at the security levels Zigbee does not use for these frames:
# encryption without a MIC, and a MIC without encryption. At level 5 (ENC-MIC-32) the two are the same
# algorithm, so the library's AES-CCM does the work: a 13-byte nonce (hence a 2-byte length field) and a
# 4-byte tag.

def nonce(source_eui64: int, frame_counter: int, security_control: int) -> bytes:
    return source_eui64.to_bytes(8, "little") + frame_counter.to_bytes(4, "little") + bytes([security_control])


def ccm_star_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, mic_len: int = MIC_LEN) -> bytes | None:
    """Return the plaintext if the MIC checks out, else None. nonce is 13 bytes; ciphertext ends with the MIC."""
    if len(nonce) != 13 or len(ciphertext) < mic_len:
        return None
    try:
        return AESCCM(key, tag_length=mic_len).decrypt(nonce, ciphertext, aad or None)
    except InvalidTag:
        return None


def ccm_star_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, mic_len: int = MIC_LEN) -> bytes:
    """Encrypt-and-authenticate, the inverse of ccm_star_decrypt. Used by the demo and the tests."""
    return AESCCM(key, tag_length=mic_len).encrypt(nonce, plaintext, aad or None)
