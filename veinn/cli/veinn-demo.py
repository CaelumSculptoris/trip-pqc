
"""
A didactic, invertible, vector-native "VEINN" toy cipher.

This demonstrates the *structure* of a Vector-Encrypted Invertible Neural Network (VEINN):
- State space: Z_q^n (q = 2^16), vector-native arithmetic.
- Keyed, invertible coupling layers (RealNVP/Glow-style, but discrete and exactly invertible).
- Parameters are derived via SHAKE-256 (standing in for an LWE/RLWE-based PRF/PRG in a real design).
- Round structure: [Coupling → Shuffle] x L per round, repeated R rounds.
- All operations are constant-time-ish array arithmetic over uint16.

DISCLAIMER: Educational only. No security claims. Do not use for real data.
"""

from __future__ import annotations
import hashlib
import numpy as np
from dataclasses import dataclass

# ---------------------------------------------------------
# Field / block params
# ---------------------------------------------------------
Q = 2**16
DTYPE = np.uint16

@dataclass
class VeinnParams:
    n: int = 256       # state vector length (coefficients over Z_q)
    rounds: int = 6    # number of rounds
    layers_per_round: int = 2  # coupling layers per round
    # shuffle pattern (a fixed invertible permutation)
    shuffle_stride: int = 7    # must be coprime with n for a full-length permutation

# ---------------------------------------------------------
# Utilities
# ---------------------------------------------------------
def shake(expand_bytes: int, *chunks: bytes) -> bytes:
    """Domain-separated SHAKE-256 expand."""
    xof = hashlib.shake_256()
    for c in chunks:
        xof.update(len(c).to_bytes(2, 'big'))
        xof.update(c)
    return xof.digest(expand_bytes)

def derive_u16(count: int, *chunks: bytes) -> np.ndarray:
    """Derive 'count' uint16 words via SHAKE-256."""
    raw = shake(count * 2, *chunks)
    arr = np.frombuffer(raw, dtype=np.uint16)
    return arr.copy()  # ensure writable

def odd_constant_from_key(tag: bytes) -> int:
    """Map tag bytes -> an odd 16-bit multiplicative constant (invertible mod 2^16)."""
    x = int.from_bytes(shake(2, tag), 'little')
    x |= 1  # force odd
    return x & 0xFFFF

def mul_inv_mod_2_16(a: int) -> int:
    """Multiplicative inverse of an odd 16-bit integer modulo 2^16."""
    # Newton–Raphson on 2-adic integers
    x = a
    for _ in range(5):
        x = (x * (2 - a * x)) & 0xFFFF
    return x

# ---------------------------------------------------------
# Bijective 16-bit "ARX-ish" S-box (per coefficient)
# ---------------------------------------------------------
def sbox16_forward(x: np.ndarray, mul_c: int, rot: int) -> np.ndarray:
    """Bijective map on 16-bit words: x -> rotl( (x ^ (x<<7) ^ (x>>3)) * mul_c, rot )."""
    x = x.astype(DTYPE)
    y = x ^ ((x << 7) & 0xFFFF) ^ (x >> 3)
    y = (y.astype(np.uint32) * mul_c) & 0xFFFF
    # rotate left by rot bits
    rot %= 16
    if rot:
        y = ((y << rot) | (y >> (16 - rot))) & 0xFFFF
    return y.astype(DTYPE)

def sbox16_inverse(x: np.ndarray, mul_c: int, rot: int) -> np.ndarray:
    """Inverse of sbox16_forward."""
    x = x.astype(DTYPE)
    # inverse rotate right
    rot %= 16
    if rot:
        y = ((x >> rot) | (x << (16 - rot))) & 0xFFFF
    else:
        y = x
    # inverse multiply
    inv_c = mul_inv_mod_2_16(mul_c)
    y = (y.astype(np.uint32) * inv_c) & 0xFFFF
    # invert y = x ^ (x<<7) ^ (x>>3)
    # This XOR-linear map is invertible on 16-bit; we can solve by fixed-point iteration.
    # Do 4 iterations (more than enough for 16-bit).
    z = y.copy().astype(np.uint16)
    for _ in range(4):
        z = y ^ ((z << 7) & 0xFFFF) ^ (z >> 3)
    return z.astype(DTYPE)

# ---------------------------------------------------------
# Coupling layer (invertible flow over Z_q^n)
# ---------------------------------------------------------
@dataclass
class CouplingParams:
    mask_a: np.ndarray  # uint16 vector (size n//2)
    mask_b: np.ndarray  # uint16 vector (size n//2)
    mul_c: int          # odd 16-bit
    rot: int            # 0..15

def coupling_forward(x: np.ndarray, cp: CouplingParams) -> np.ndarray:
    """Forward coupling: split x=(x1,x2);
       x1 = x1 + S(x2 + mask_a);  x2 = x2 + S(x1 + mask_b)."""
    n = x.shape[0]
    h = n // 2
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    # first half update
    t = (x2 + cp.mask_a) & 0xFFFF
    t = sbox16_forward(t, cp.mul_c, cp.rot)
    x1 = (x1 + t) & 0xFFFF
    # second half update
    u = (x1 + cp.mask_b) & 0xFFFF
    u = sbox16_forward(u, cp.mul_c, cp.rot)
    x2 = (x2 + u) & 0xFFFF
    return np.concatenate([x1, x2]).astype(DTYPE)

def coupling_inverse(x: np.ndarray, cp: CouplingParams) -> np.ndarray:
    """Inverse of coupling_forward (reverse the two updates)."""
    n = x.shape[0]
    h = n // 2
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    # invert second half update
    u = sbox16_forward((x1 + cp.mask_b) & 0xFFFF, cp.mul_c, cp.rot)
    x2 = (x2 - u) & 0xFFFF
    # invert first half update
    t = sbox16_forward((x2 + cp.mask_a) & 0xFFFF, cp.mul_c, cp.rot)
    x1 = (x1 - t) & 0xFFFF
    return np.concatenate([x1, x2]).astype(DTYPE)

# ---------------------------------------------------------
# Shuffle (invertible permutation for diffusion)
# ---------------------------------------------------------
def make_shuffle_indices(n: int, stride: int) -> np.ndarray:
    # permutation i -> (i*stride) mod n ; requires gcd(stride, n) = 1
    if np.gcd(stride, n) != 1:
        raise ValueError("shuffle_stride must be coprime with n")
    return np.array([(i * stride) % n for i in range(n)], dtype=np.int32)

def shuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    return x[idx].astype(DTYPE)

def unshuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    inv = np.empty_like(idx)
    inv[idx] = np.arange(len(idx))
    return x[inv].astype(DTYPE)

# ---------------------------------------------------------
# Key schedule / parameter derivation (PRF/PRG stand-in via SHAKE)
# ---------------------------------------------------------
@dataclass
class RoundParams:
    cpls: list  # list[CouplingParams]

@dataclass
class VeinnKey:
    K: bytes
    params: VeinnParams
    shuffle_idx: np.ndarray
    rounds: list  # list[RoundParams]

def key_from_seed(seed: bytes, vp: VeinnParams) -> VeinnKey:
    n = vp.n
    h = n // 2
    shuffle_idx = make_shuffle_indices(n, vp.shuffle_stride)
    rounds = []
    for r in range(vp.rounds):
        cpls = []
        for l in range(vp.layers_per_round):
            tag = b"VEINN|r%d|l%d" % (r, l)
            mask_a = derive_u16(h, seed, tag, b"A")
            mask_b = derive_u16(h, seed, tag, b"B")
            mul_c = int(odd_constant_from_key(seed + tag + b"M"))
            rot = int(derive_u16(1, seed, tag, b"R")[0] % 16)
            cpls.append(CouplingParams(mask_a, mask_b, mul_c, rot))
        rounds.append(RoundParams(cpls))
    return VeinnKey(K=seed, params=vp, shuffle_idx=shuffle_idx, rounds=rounds)

# ---------------------------------------------------------
# Core permutation (PRP) — encrypt/decrypt one block
# ---------------------------------------------------------
def permute_forward(x: np.ndarray, key: VeinnKey) -> np.ndarray:
    assert x.dtype == DTYPE
    idx = key.shuffle_idx
    y = x.copy()
    for r in range(key.params.rounds):
        for cp in key.rounds[r].cpls:
            y = coupling_forward(y, cp)
            y = shuffle(y, idx)
    return y

def permute_inverse(x: np.ndarray, key: VeinnKey) -> np.ndarray:
    assert x.dtype == DTYPE
    idx = key.shuffle_idx
    y = x.copy()
    # reverse order
    for r in reversed(range(key.params.rounds)):
        for cp in reversed(key.rounds[r].cpls):
            y = unshuffle(y, idx)
            y = coupling_inverse(y, cp)
    return y

# ---------------------------------------------------------
# Helpers: encode/decode strings to Z_q^n blocks
# ---------------------------------------------------------
def bytes_to_block(b: bytes, n: int) -> np.ndarray:
    """Pack bytes into n uint16 words (little-endian), padding with zeros."""
    arr = np.frombuffer(b + b'\x00' * ((2*n - len(b)) % (2*n)), dtype=np.uint16)
    if arr.size < n:
        arr = np.pad(arr, (0, n - arr.size), constant_values=0)
    else:
        arr = arr[:n]
    return arr.astype(DTYPE)

def block_to_bytes(x: np.ndarray) -> bytes:
    return x.astype(np.uint16).tobytes()

# ---------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------

def demo():
    vp = VeinnParams(n=256, rounds=6, layers_per_round=2, shuffle_stride=7)
    seed = b"example-VEINN-seed-32bytes........"[:32]
    key = key_from_seed(seed, vp)

    msg = b"hello world"
    print("Plaintext:", msg)

    # Encode to block
    x = bytes_to_block(msg, vp.n)

    # Encrypt
    c = permute_forward(x, key)
    print("Ciphertext (first 16 words):", c[:16].tolist())

    # Decrypt
    x2 = permute_inverse(c, key)
    pt = block_to_bytes(x2)[:len(msg)]
    print("Decrypted:", pt)

    assert pt == msg, "Decryption failed!"

    # Avalanche: flip 1 bit in plaintext, measure Hamming distance of ciphertexts
    x_flip = x.copy()
    x_flip[0] ^= np.uint16(1)  # flip LSB of first word
    c2 = permute_forward(x_flip, key)
    hamming = int(np.unpackbits((c ^ c2).view(np.uint8)).sum())
    print("Avalanche test (hamming distance bits):", hamming)

    return {"cipher_ok": True, "hamming_distance_bits": hamming, "ciphertext_sample": c[:8].tolist()}


if __name__ == "__main__":
    out = demo()
    print(out)
