# veinn/permutation.py
import numpy as np
from .params import Q, DTYPE
from .key_schedule import VeinnKey
from .ring import negacyclic_convolution
from .shuffle import shuffle, unshuffle

def permute_forward(x: np.ndarray, key: VeinnKey) -> np.ndarray:
    vp = key.params
    idx = key.shuffle_idx
    y = x.copy()
    for r in range(vp.rounds):
        for cp in key.rounds[r].cpls:
            # late import to avoid cycle
            from .coupling import coupling_forward
            y = coupling_forward(y, cp)
        y = negacyclic_convolution(y, key.rounds[r].ring_poly, Q)
        y = shuffle(y, idx)
    return y.astype(DTYPE)

def permute_inverse(x: np.ndarray, key: VeinnKey) -> np.ndarray:
    vp = key.params
    idx = key.shuffle_idx
    y = x.copy()
    for r in reversed(range(vp.rounds)):
        y = unshuffle(y, idx)
        y = negacyclic_convolution(y, key.rounds[r].ring_poly, Q)
        for cp in reversed(key.rounds[r].cpls):
            from .coupling import coupling_inverse
            y = coupling_inverse(y, cp)
    return y.astype(DTYPE)
