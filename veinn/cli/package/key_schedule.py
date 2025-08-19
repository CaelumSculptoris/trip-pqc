# veinn/key_schedule.py
import numpy as np
from dataclasses import dataclass
from .params import DTYPE
from .coupling import CouplingParams
from .utils import derive_u16
from .shuffle import make_shuffle_indices

@dataclass
class RoundParams:
    cpls: list[CouplingParams]
    ring_poly: np.ndarray

@dataclass
class VeinnKey:
    seed: bytes
    params: any
    shuffle_idx: np.ndarray
    rounds: list[RoundParams]

def key_from_seed(seed: bytes, vp) -> VeinnKey:
    n = vp.n
    h = n // 2
    shuffle_idx = make_shuffle_indices(n, vp.shuffle_stride)
    rounds = []
    for r in range(vp.rounds):
        cpls = []
        for l in range(vp.layers_per_round):
            tag = b"VEINN|r%d|l%d" % (r, l)
            mask_a = derive_u16(h, vp, seed, tag, b"A")
            mask_b = derive_u16(h, vp, seed, tag, b"B")
            cpls.append(CouplingParams(mask_a, mask_b))
        ring_poly = derive_u16(n, vp, seed, b"ring", bytes([r]))
        rounds.append(RoundParams(cpls, ring_poly.astype(DTYPE)))
    return VeinnKey(seed=seed, params=vp, shuffle_idx=shuffle_idx, rounds=rounds)
