# veinn/lwe.py
import numpy as np
from .params import Q, DTYPE
from .ring import negacyclic_convolution
from .utils import shake

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
