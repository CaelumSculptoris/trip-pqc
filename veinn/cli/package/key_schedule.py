import numpy as np
from dataclasses import dataclass
from .params import DTYPE, VeinnParams
from .coupling import CouplingParams
from .utils import derive_u16
from .shuffle import make_shuffle_indices
from .rsa_oaep import ensure_odd_vec, inv_vec_mod_q

@dataclass
class RoundParams:
    cpls: list[CouplingParams]
    ring_scale: np.ndarray          # elementwise odd scale (unit in Z_{2^16})
    ring_scale_inv: np.ndarray      # elementwise modular inverse

@dataclass
class VeinnKey:
    seed: bytes
    params: any
    shuffle_idx: np.ndarray
    rounds: list[RoundParams]

def key_from_seed(seed: bytes, vp: VeinnParams) -> VeinnKey:
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
            assert mask_a.shape == (h,) and mask_b.shape == (h,), f"Mask shape mismatch: expected {(h,)}, got {mask_a.shape}, {mask_b.shape}"
            cpls.append(CouplingParams(mask_a, mask_b))

        # Derive invertible per-word scaling (odd => invertible mod 2^16)
        scale = derive_u16(n, vp, seed, b"ring", bytes([r]))
        scale = ensure_odd_vec(scale)
        scale_inv = inv_vec_mod_q(scale)

        assert scale.shape == (n,), f"Ring scale shape mismatch: expected {(n,)}, got {scale.shape}"
        assert scale_inv.shape == (n,), f"Ring inv shape mismatch: expected {(n,)}, got {scale_inv.shape}"
        rounds.append(RoundParams(cpls, scale, scale_inv))
    return VeinnKey(seed=seed, params=vp, shuffle_idx=shuffle_idx, rounds=rounds)
