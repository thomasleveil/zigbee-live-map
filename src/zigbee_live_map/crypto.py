"""Zigbee security math, so the tool can decrypt traffic when a key is known or recoverable.

Nothing here attacks anything. It is the standard, published Zigbee crypto (IEEE 802.15.4 CCM*,
the AES-MMO keyed hash of the ZigBee spec), used on traffic the user is entitled to read:

- the famous default Trust Center link key ``ZigBeeAlliance09`` is built in, so the tool can tell
  whether a device's join could be decrypted with it, which is exactly the vulnerability to flag;
- given a network key (entered by the user, or recovered from a join secured with the default link
  key), NWK payloads decrypt, which turns the encrypted part into device identity and the routers'
  own link-quality figures.

AES-128 is the only primitive taken from a library; CCM* and the keyed hash are built on top so the
behaviour is explicit and testable. The one Zigbee quirk is that frames are transmitted with a
security level of 0 but secured as level 5 (ENC-MIC-32); decryption restores level 5.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_TC_LINK_KEY = bytes.fromhex("5a6967426565416c6c69616e63653039")  # "ZigBeeAlliance09"
ZLL_MASTER_KEY = bytes.fromhex("9f5595f10257c8a469cbf42bc93fee31")       # leaked Touchlink (ZLL) master key
SECURITY_LEVEL = 5   # ENC-MIC-32: AES encryption + 32-bit MIC, the level Zigbee secures with
MIC_LEN = 4

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


# --- CCM* (IEEE 802.15.4 / ZigBee): decrypt-and-verify -------------------------------------

def _ctr_blocks(key: bytes, nonce: bytes, count: int):
    for i in range(count):
        yield aes_ecb(key, b"\x01" + nonce + i.to_bytes(2, "big"))


def ccm_star_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, mic_len: int = MIC_LEN) -> bytes | None:
    """Return the plaintext if the MIC checks out, else None. nonce is 13 bytes."""
    if len(nonce) != 13 or len(ciphertext) < mic_len:
        return None
    body, mic = ciphertext[:-mic_len], ciphertext[-mic_len:]
    keystream = list(_ctr_blocks(key, nonce, (len(body) + 15) // 16 + 1))
    plaintext = _xor(body, b"".join(keystream[1:])[:len(body)])

    flags = (0x40 if aad else 0) | (((mic_len - 2) // 2) << 3) | 1
    mac = aes_ecb(key, bytes([flags]) + nonce + len(plaintext).to_bytes(2, "big"))
    if aad:
        block = len(aad).to_bytes(2, "big") + aad
        block += b"\x00" * (-len(block) % 16)
        for i in range(0, len(block), 16):
            mac = aes_ecb(key, _xor(mac, block[i:i + 16]))
    pt = plaintext + b"\x00" * (-len(plaintext) % 16)
    for i in range(0, len(pt), 16):
        mac = aes_ecb(key, _xor(mac, pt[i:i + 16]))
    if _xor(mac[:mic_len], keystream[0][:mic_len]) != mic:
        return None
    return plaintext


def nonce(source_eui64: int, frame_counter: int, security_control: int) -> bytes:
    return source_eui64.to_bytes(8, "little") + frame_counter.to_bytes(4, "little") + bytes([security_control])


def ccm_star_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, mic_len: int = MIC_LEN) -> bytes:
    """Encrypt-and-authenticate, the inverse of ccm_star_decrypt. Used by the demo and the tests."""
    flags = (0x40 if aad else 0) | (((mic_len - 2) // 2) << 3) | 1
    mac = aes_ecb(key, bytes([flags]) + nonce + len(plaintext).to_bytes(2, "big"))
    if aad:
        block = len(aad).to_bytes(2, "big") + aad
        block += b"\x00" * (-len(block) % 16)
        for i in range(0, len(block), 16):
            mac = aes_ecb(key, _xor(mac, block[i:i + 16]))
    pt = plaintext + b"\x00" * (-len(plaintext) % 16)
    for i in range(0, len(pt), 16):
        mac = aes_ecb(key, _xor(mac, pt[i:i + 16]))
    keystream = list(_ctr_blocks(key, nonce, (len(plaintext) + 15) // 16 + 1))
    body = _xor(plaintext, b"".join(keystream[1:])[:len(plaintext)])
    mic = _xor(mac[:mic_len], keystream[0][:mic_len])
    return body + mic
