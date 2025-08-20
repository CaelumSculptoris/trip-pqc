import math
import numpy as np
from .params import DTYPE, bcolors

# -----------------------------
# Shuffle
# -----------------------------
def make_shuffle_indices(n: int, stride: int) -> np.ndarray:
    if math.gcd(stride, n) != 1:
        raise ValueError(f"{bcolors.FAIL}shuffle_stride must be coprime with n{bcolors.ENDC}")
    return np.array([(i * stride) % n for i in range(n)], dtype=np.int32)

def shuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    assert x.shape[0] == idx.shape[0], f"Shuffle shape mismatch: input {x.shape}, indices {idx.shape}"
    return x[idx].astype(DTYPE)

def unshuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    assert x.shape[0] == idx.shape[0], f"Unshuffle shape mismatch: input {x.shape}, indices {idx.shape}"
    inv = np.empty_like(idx)
    inv[idx] = np.arange(len(idx))
    return x[inv].astype(DTYPE)