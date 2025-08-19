# veinn/utils.py
import hashlib
import numpy as np
from .params import Q, DTYPE, VeinnParams
from .ring import negacyclic_convolution

def lwe_prf_expand(seed: bytes, out_n: int, vp) -> np.ndarray:
    """Generate pseudorandom parameters with small-noise LWE flavor."""
    n = vp.n
    s = np.frombuffer(shake(n * 2, seed, b"s"), dtype=np.uint16)[:n] & (Q - 1)
    a = np.frombuffer(shake(n * 2, seed, b"A"), dtype=np.uint16)[:n] & (Q - 1)
    raw = shake(n, seed, b"e")
    e = (np.frombuffer(raw, dtype=np.uint8)[:n] % 3).astype(np.int64)  # small noise
    b = negacyclic_convolution(a, s, Q).astype(np.int64)
    b = (b + e) % Q
    out = np.zeros(out_n, dtype=DTYPE)
    for i in range(out_n):
        out[i] = int(b[i % n]) & (Q - 1)
    return out

def shake(expand_bytes: int, *chunks: bytes) -> bytes:
    xof = hashlib.shake_256()
    for c in chunks:
        xof.update(len(c).to_bytes(2, 'big'))
        xof.update(c)
    return xof.digest(expand_bytes)

def derive_u16(count: int, vp: VeinnParams, *chunks: bytes) -> np.ndarray:
    if vp.use_lwe:
        seed_derive = shake(32, *chunks)
        return lwe_prf_expand(seed_derive, count, vp)
    raw = shake(count * 2, *chunks)
    return np.frombuffer(raw, dtype=np.uint16)[:count].copy()

def odd_constant_from_key(tag: bytes) -> int:
    x = int.from_bytes(shake(2, tag), 'little')
    x |= 1
    return x & (Q - 1)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty data")
    padding_len = data[-1]
    if padding_len == 0 or padding_len > len(data):
        raise ValueError("Invalid padding")
    if not all(b == padding_len for b in data[-padding_len:]):
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def derive_seed_bytes(nonce: bytes, seed_len: int = 32) -> bytes:
    return shake(seed_len, nonce)

def int_to_bytes_be(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def bytes_be_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def int_to_bytes_be_fixed(n: int, k: int) -> bytes:
    """Big-endian, left-padded with zeros to exactly k bytes."""
    b = int_to_bytes_be(n)
    if len(b) > k:
        raise ValueError("Integer too large for target length")
    return b.rjust(k, b'\x00')
