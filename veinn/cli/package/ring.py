# veinn/ring.py
import numpy as np
from .params import DTYPE

def negacyclic_convolution(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    assert a.shape == b.shape, f"Convolution shape mismatch: a {a.shape}, b {b.shape}"
    n = a.shape[0]
    res = np.zeros(n, dtype=np.int64)
    a_int = a.astype(np.int64)
    b_int = b.astype(np.int64)
    for i in range(n):
        ai = a_int[i]
        for j in range(n):
            k = (i + j) % n
            sign = -1 if (i + j) >= n else 1
            res[k] = (res[k] + ai * b_int[j] * sign)
    return (res % q).astype(DTYPE)
