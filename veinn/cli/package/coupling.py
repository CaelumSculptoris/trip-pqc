# veinn/coupling.py
import numpy as np
from dataclasses import dataclass
from params import Q, DTYPE
from ring import negacyclic_convolution

@dataclass
class CouplingParams:
    mask_a: np.ndarray
    mask_b: np.ndarray

def coupling_forward(x: np.ndarray, cp: CouplingParams) -> np.ndarray:
    n = x.shape[0]
    h = n // 2
    assert cp.mask_a.shape == (h,) and cp.mask_b.shape == (h,)
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    t = (x2.astype(np.int64) + cp.mask_a.astype(np.int64)) % Q
    t = negacyclic_convolution(t, np.ones(h, dtype=DTYPE), Q)
    x1 = (x1.astype(np.int64) + t) % Q
    u = (x1.astype(np.int64) + cp.mask_b.astype(np.int64)) % Q
    u = negacyclic_convolution(u, np.ones(h, dtype=DTYPE), Q)
    x2 = (x2.astype(np.int64) + u) % Q
    return np.concatenate([x1.astype(DTYPE), x2.astype(DTYPE)])

def coupling_inverse(x: np.ndarray, cp: CouplingParams) -> np.ndarray:
    n = x.shape[0]
    h = n // 2
    assert cp.mask_a.shape == (h,) and cp.mask_b.shape == (h,)
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    u = (x1.astype(np.int64) + cp.mask_b.astype(np.int64)) % Q
    u = negacyclic_convolution(u, np.ones(h, dtype=DTYPE), Q)
    x2 = (x2.astype(np.int64) - u) % Q
    t = (x2.astype(np.int64) + cp.mask_a.astype(np.int64)) % Q
    t = negacyclic_convolution(t, np.ones(h, dtype=DTYPE), Q)
    x1 = (x1.astype(np.int64) - t) % Q
    return np.concatenate([x1.astype(DTYPE), x2.astype(DTYPE)])
