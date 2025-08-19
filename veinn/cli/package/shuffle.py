# veinn/shuffle.py
import math
import numpy as np
from .params import DTYPE

def make_shuffle_indices(n: int, stride: int) -> np.ndarray:
    if math.gcd(stride, n) != 1:
        raise ValueError("shuffle_stride must be coprime with n")
    return np.array([(i * stride) % n for i in range(n)], dtype=np.int32)

def shuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    assert x.shape[0] == idx.shape[0]
    return x[idx].astype(DTYPE)

def unshuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    assert x.shape[0] == idx.shape[0]
    inv = np.empty_like(idx)
    inv[idx] = np.arange(len(idx))
    return x[inv].astype(DTYPE)
