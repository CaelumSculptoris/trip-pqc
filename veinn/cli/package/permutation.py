import numpy as np
from .params import Q, DTYPE
from .key_schedule import VeinnKey
from .coupling import coupling_forward, coupling_inverse
from .shuffle import shuffle, unshuffle

# -----------------------------
# Permutation (updated to use invertible scaling)
# -----------------------------
def permute_forward(x: np.ndarray, key: VeinnKey) -> np.ndarray:
    vp = key.params
    idx = key.shuffle_idx
    assert x.shape == (vp.n,), f"Expected input shape {(vp.n,)}, got {x.shape}"
    y = x.copy()
    for r in range(vp.rounds):
        for cp in key.rounds[r].cpls:
            y = coupling_forward(y, cp)
        # Invertible elementwise scaling
        y = (y.astype(np.int64) * key.rounds[r].ring_scale.astype(np.int64)) % Q
        y = shuffle(y, idx)
    return y.astype(DTYPE)

def permute_inverse(x: np.ndarray, key: VeinnKey) -> np.ndarray:
    vp = key.params
    idx = key.shuffle_idx
    assert x.shape == (vp.n,), f"Expected input shape {(vp.n,)}, got {x.shape}"
    y = x.copy()
    for r in reversed(range(vp.rounds)):
        y = unshuffle(y, idx)
        # Apply precomputed inverse scaling
        y = (y.astype(np.int64) * key.rounds[r].ring_scale_inv.astype(np.int64)) % Q
        for cp in reversed(key.rounds[r].cpls):
            y = coupling_inverse(y, cp)
    return y.astype(DTYPE)
