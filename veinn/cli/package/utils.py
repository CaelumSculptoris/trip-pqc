# veinn/utils.py
import hashlib
import numpy as np
from .params import Q
from .lwe import lwe_prf_expand

def shake(expand_bytes: int, *chunks: bytes) -> bytes:
    xof = hashlib.shake_256()
    for c in chunks:
        xof.update(len(c).to_bytes(2, "big"))
        xof.update(c)
    return xof.digest(expand_bytes)

def derive_u16(count: int, vp, *chunks: bytes) -> np.ndarray:
    if vp.use_lwe:
        seed_derive = shake(32, *chunks)
        return lwe_prf_expand(seed_derive, count, vp)
    raw = shake(count * 2, *chunks)
    return np.frombuffer(raw, dtype=np.uint16)[:count].copy()

def odd_constant_from_key(tag: bytes) -> int:
    x = int.from_bytes(shake(2, tag), "little")
    x |= 1
    return x & (Q - 1)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")
    if not all(b == pad_len for b in data[-pad_len:]):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def derive_seed_bytes(nonce: bytes, seed_len: int = 32) -> bytes:
    return shake(seed_len, nonce)

def int_to_bytes_be(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def bytes_be_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")
