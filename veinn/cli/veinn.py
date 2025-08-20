import os
import sys
import json
import math
import hashlib
import hmac
import secrets
import numpy as np
import argparse
import pickle
import time
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
from dataclasses import dataclass
# -----------------------------
# CLI Colors
# -----------------------------
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    GREY = '\033[90m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# -----------------------------
# Core Parameters
# -----------------------------
Q = 2**16  # Modulus
DTYPE = np.uint16

@dataclass
class VeinnParams:
    n: int = 8  # Number of uint16 words per block (default 8 -> 16 bytes/block)
    rounds: int = 3
    layers_per_round: int = 2
    shuffle_stride: int = 7
    use_lwe: bool = True  # LWE PRF for key nonlinearity and PQ security

# -----------------------------
# Utilities
# -----------------------------
def shake(expand_bytes: int, *chunks: bytes) -> bytes:
    xof = hashlib.shake_256()
    for c in chunks:
        xof.update(len(c).to_bytes(2, 'big'))
        xof.update(c)
    return xof.digest(expand_bytes)

def derive_u16(count: int, vp: VeinnParams, *chunks: bytes) -> np.ndarray:
    if vp.use_lwe:
        seed_derive = shake(32, *chunks)
        return lwe_prf_expand(seed_derive, count, vp)
    raw = shake(count * 2, *chunks)
    return np.frombuffer(raw, dtype=np.uint16)[:count].copy()

def odd_constant_from_key(tag: bytes) -> int:
    x = int.from_bytes(shake(2, tag), 'little')
    x |= 1
    return x & (Q - 1)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError(f"{bcolors.FAIL}Cannot unpad empty data{bcolors.ENDC}")
    padding_len = data[-1]
    if padding_len == 0 or padding_len > len(data):
        raise ValueError(f"{bcolors.FAIL}Invalid padding{bcolors.ENDC}")
    if not all(b == padding_len for b in data[-padding_len:]):
        raise ValueError(f"{bcolors.FAIL}Invalid padding{bcolors.ENDC}")
    return data[:-padding_len]

# -----------------------------
# LWE-Based PRF
# -----------------------------
def int_ring_convolve(a, b, q, root):
    """Convolution over Z_q[x]/(x^n+1) using NTT"""
    n = len(a)
    A = ntt(a, q, root)
    B = ntt(b, q, root)
    C = (A * B) % q
    # Inverse NTT: use modular inverse of n and root
    inv_n = pow(n, -1, q)
    inv_root = pow(root, -1, q)
    c = ntt(C, q, inv_root)
    return (c * inv_n) % q

def ring_convolution(a, b, q, method="naive"):
    """
    Ring convolution modulo q, drop-in replacement for your current method.

    Args:
        a, b : list[int] or np.ndarray
            Polynomials represented as coefficient lists of length n
        q : int
            Modulus
        method : str
            "naive" → O(n^2), slow but exact
            "fft"   → O(n log n), floating point FFT (fast, but rounding)
            "ntt"   → O(n log n), modular NTT (exact if q supports)

    Returns:
        np.ndarray : coefficients of (a * b) mod (x^n+1, q)
    """
    n = len(a)
    a = np.array(a, dtype=int) % q
    b = np.array(b, dtype=int) % q

    if method == "naive":
        # direct polynomial multiplication
        res = np.zeros(2*n, dtype=int)
        for i in range(n):
            for j in range(n):
                res[i+j] += a[i] * b[j]
        # wrap back into ring (mod x^n + 1)
        res = (res[:n] - res[n:]) % q
        return res

    elif method == "fft":
        # floating point FFT
        A = np.fft.fft(a, 2*n)
        B = np.fft.fft(b, 2*n)
        C = A * B
        res = np.fft.ifft(C).real.round().astype(int)
        res = (res[:n] - res[n:]) % q
        return res

    elif method == "ntt":
        # NTT requires q ≡ 1 mod 2n (so a primitive root exists)
        # toy implementation: only works if q is carefully chosen
        # Here we fallback to naive if q is unsuitable
        if (q - 1) % (2*n) != 0:
            return ring_convolution(a, b, q, method="naive")

        # find primitive 2n-th root of unity modulo q
        g = find_primitive_root(q)
        root = pow(g, (q - 1) // (2*n), q)

        A = ntt(a, root, q)
        B = ntt(b, root, q)
        C = [(x*y) % q for x, y in zip(A, B)]
        res = intt(C, root, q)
        res = (np.array(res[:n]) - np.array(res[n:])) % q
        return res

    else:
        raise ValueError("method must be one of: naive, fft, ntt")

# -----------------------------
# Helper functions for NTT 
# -----------------------------
def ntt(a, root, q):
    n = len(a)
    A = [0]*n
    for k in range(n):
        s = 0
        for j in range(n):
            s = (s + a[j] * pow(root, (j*k) % (2*n), q)) % q
        A[k] = s
    return A

def intt(A, root, q):
    n = len(A)
    inv_n = pow(n, -1, q)
    root_inv = pow(root, -1, q)
    a = [0]*n
    for j in range(n):
        s = 0
        for k in range(n):
            s = (s + A[k] * pow(root_inv, (j*k) % (2*n), q)) % q
        a[j] = (s * inv_n) % q
    return a

def find_primitive_root(q):
    """Finds a primitive root modulo q (very naive)."""
    factors = factorize(q-1)
    for g in range(2, q):
        ok = True
        for f in factors:
            if pow(g, (q-1)//f, q) == 1:
                ok = False
                break
        if ok:
            return g
    return None

def factorize(n):
    factors = set()
    d = 2
    while d*d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return list(factors)

def negacyclic_convolution(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    """O(n^2) negacyclic convolution in Z_q[x]/(x^n+1)."""
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

def lwe_prf_expand(seed: bytes, out_n: int, vp: VeinnParams) -> np.ndarray:
    """Generate pseudorandom parameters with LWE noise, avoiding recursion."""
    n = vp.n
    # Use SHAKE-256 directly for s and a to prevent recursive calls
    s = np.frombuffer(shake(n * 2, seed, b"s"), dtype=np.uint16)[:n] & (Q - 1)
    a = np.frombuffer(shake(n * 2, seed, b"A"), dtype=np.uint16)[:n] & (Q - 1)
    raw = shake(n, seed, b"e")
    e = (np.frombuffer(raw, dtype=np.uint8)[:n] % 3).astype(np.int64)  # Small noise
    assert s.shape == (n,) and a.shape == (n,) and e.shape == (n,), "LWE parameter shape mismatch"
    b = ring_convolution(a, s, Q, 'ntt').astype(np.int64)
    b = (b + e) % Q
    out = np.zeros(out_n, dtype=DTYPE)
    for i in range(out_n):
        out[i] = int(b[i % n]) & (Q - 1)
    assert out.shape == (out_n,), f"Expected output shape {(out_n,)}, got {out.shape}"
    return out

# -----------------------------
# Coupling Layer
# -----------------------------
@dataclass
class CouplingParams:
    mask_a: np.ndarray
    mask_b: np.ndarray

def coupling_forward(x: np.ndarray, cp: CouplingParams) -> np.ndarray:
    n = x.shape[0]
    h = n // 2
    assert x.shape == (n,), f"Expected input shape {(n,)}, got {x.shape}"
    assert cp.mask_a.shape == (h,) and cp.mask_b.shape == (h,), f"Mask shape mismatch: expected {(h,)}, got {cp.mask_a.shape}, {cp.mask_b.shape}"
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    t = (x2.astype(np.int64) + cp.mask_a.astype(np.int64)) % Q
    t = ring_convolution(t, np.ones(h, dtype=DTYPE), Q, 'ntt')
    x1 = (x1.astype(np.int64) + t) % Q
    u = (x1.astype(np.int64) + cp.mask_b.astype(np.int64)) % Q
    u = ring_convolution(u, np.ones(h, dtype=DTYPE), Q, 'ntt')
    x2 = (x2.astype(np.int64) + u) % Q
    return np.concatenate([x1.astype(DTYPE), x2.astype(DTYPE)])

def coupling_inverse(x: np.ndarray, cp: CouplingParams) -> np.ndarray:
    n = x.shape[0]
    h = n // 2
    assert x.shape == (n,), f"Expected input shape {(n,)}, got {x.shape}"
    assert cp.mask_a.shape == (h,) and cp.mask_b.shape == (h,), f"Mask shape mismatch: expected {(h,)}, got {cp.mask_a.shape}, {cp.mask_b.shape}"
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    u = (x1.astype(np.int64) + cp.mask_b.astype(np.int64)) % Q
    u = ring_convolution(u, np.ones(h, dtype=DTYPE), Q, 'ntt')
    x2 = (x2.astype(np.int64) - u) % Q
    t = (x2.astype(np.int64) + cp.mask_a.astype(np.int64)) % Q
    t = ring_convolution(t, np.ones(h, dtype=DTYPE), Q, 'ntt')
    x1 = (x1.astype(np.int64) - t) % Q
    return np.concatenate([x1.astype(DTYPE), x2.astype(DTYPE)])

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

# -----------------------------
# Round Params (updated: invertible scaling)
# -----------------------------
@dataclass
class RoundParams:
    cpls: list[CouplingParams]
    ring_scale: np.ndarray          # elementwise odd scale (unit in Z_{2^16})
    ring_scale_inv: np.ndarray      # elementwise modular inverse

# -----------------------------
# Modular inverse helpers for 2^k
# -----------------------------
def modinv(a: int, m: int) -> int:
    # Extended Euclid
    def egcd(aa: int, bb: int):
        if aa == 0:
            return bb, 0, 1
        g, x1, y1 = egcd(bb % aa, aa)
        return g, y1 - (bb // aa) * x1, x1
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"{bcolors.FAIL}Modular inverse does not exist{bcolors.ENDC}")
    return x % m

def inv_vec_mod_q(arr: np.ndarray) -> np.ndarray:
    out = np.zeros_like(arr, dtype=np.uint16)
    for i, v in enumerate(arr.astype(int).tolist()):
        if v % 2 == 0:
            raise ValueError(f"{bcolors.FAIL}Non-odd element encountered; not invertible modulo 2^16{bcolors.ENDC}")
        out[i] = modinv(v, Q)
    return out

def ensure_odd_vec(arr: np.ndarray) -> np.ndarray:
    arr = arr.copy().astype(np.uint16)
    arr |= 1  # force odd
    return arr

# -----------------------------
# Veinn Key
# -----------------------------
@dataclass
class VeinnKey:
    seed: bytes
    params: VeinnParams
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

# -----------------------------
# Block Helpers
# -----------------------------
def bytes_to_block(b: bytes, n: int) -> np.ndarray:
    # padded = b + b'\x00' * ((2 * n - len(b)) % (2 * n))
    # arr = np.frombuffer(padded, dtype=np.uint16)
    # if arr.shape[0] < n:
    #     arr = np.pad(arr, (0, n - arr.shape[0]), mode='constant', constant_values=0)
    # return arr[:n].astype(DTYPE)
    padded = b.ljust(2 * n, b'\x00')
    arr = np.frombuffer(padded, dtype='<u2')[:n].copy()
    return arr.astype(DTYPE)

def block_to_bytes(x: np.ndarray) -> bytes:
    # return x.tobytes()
    return x.astype('<u2').tobytes()

# -----------------------------
# Homomorphic Operations
# -----------------------------
def _load_encrypted_file(enc_file: str):
    metadata, _, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file)
    meta_parsed = {
        "n": int(metadata["n"]),
        "rounds": int(metadata["rounds"]),
        "layers_per_round": int(metadata["layers_per_round"]),
        "shuffle_stride": int(metadata["shuffle_stride"]),
        "use_lwe": metadata["use_lwe"],
        "mode": metadata.get("mode", "n"),
        "bytes_per_number": int(metadata.get("bytes_per_number", metadata.get("n", 4) * 2))
    }
    return enc_blocks, meta_parsed, hmac_value, nonce, timestamp

def _write_encrypted_payload(out_file: str, enc_blocks, meta, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    out = {
        "veinn_metadata": {
            "n": int(meta["n"]),
            "rounds": int(meta["rounds"]),
            "layers_per_round": int(meta["layers_per_round"]),
            "shuffle_stride": int(meta["shuffle_stride"]),
            "use_lwe": meta["use_lwe"],
            "mode": meta.get("mode", "n"),
            "bytes_per_number": int(meta.get("bytes_per_number", meta["n"] * 2))
        },
        "enc_seed": [],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks]
    }
    if hmac_value:
        out["hmac"] = hmac_value
    if nonce:
        out["nonce"] = [int(b) for b in nonce]
    if timestamp:
        out["timestamp"] = timestamp
    with open(out_file, "w") as f:
        json.dump(out, f)

def homomorphic_add_files(f1: str, f2: str, out_file: str):
    enc1, meta1, _, _, _ = _load_encrypted_file(f1)
    enc2, meta2, _, _, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError(f"{bcolors.FAIL}Encrypted files metadata mismatch{bcolors.ENDC}")
    if len(enc1) != len(enc2):
        raise ValueError(f"{bcolors.FAIL}Encrypted files must have same number of blocks{bcolors.ENDC}")
    summed = [(a + b) % Q for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, summed, meta1)
    print(f"Lattice-based homomorphic sum saved to {out_file}")

def homomorphic_mul_files(f1: str, f2: str, out_file: str):
    enc1, meta1, _, _, _ = _load_encrypted_file(f1)
    enc2, meta2, _, _, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError(f"{bcolors.FAIL}Encrypted files metadata mismatch{bcolors.ENDC}")
    if len(enc1) != len(enc2):
        raise ValueError(f"{bcolors.FAIL}Encrypted files must have same number of blocks{bcolors.ENDC}")
    prod = [ring_convolution(a, b, Q, 'ntt') for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, prod, meta1)
    print(f"Lattice-based homomorphic product saved to {out_file}")

# -----------------------------
# Key Management
# -----------------------------
def create_keystore(passphrase: str, keystore_file: str):
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = b64encode(kdf.derive(passphrase.encode()))
    Fernet(key)  # materialized to ensure validity
    keystore = {"salt": b64encode(salt).decode(), "keys": {}}
    with open(keystore_file, "wb") as kf:
        pickle.dump(keystore, kf)
    print(f"Keystore created at {keystore_file}")

def load_keystore(passphrase: str, keystore_file: str):
    with open(keystore_file, "rb") as kf:
        keystore = pickle.load(kf)
    salt = b64decode(keystore["salt"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = b64encode(kdf.derive(passphrase.encode()))
    return keystore, Fernet(key)

def store_key_in_keystore(passphrase: str, key_name: str, key_data: dict, keystore_file: str):
    keystore, fernet = load_keystore(passphrase, keystore_file)
    encrypted_key = fernet.encrypt(json.dumps(key_data).encode()).decode()
    keystore["keys"][key_name] = encrypted_key
    with open(keystore_file, "wb") as kf:
        pickle.dump(keystore, kf)

def retrieve_key_from_keystore(passphrase: str, key_name: str, keystore_file: str) -> dict:
    keystore, fernet = load_keystore(passphrase, keystore_file)
    if key_name not in keystore["keys"]:
        raise ValueError(f"{bcolors.FAIL}Key {key_name} not found in keystore{bcolors.ENDC}")
    encrypted_key = keystore["keys"][key_name]
    try:
        decrypted_key = fernet.decrypt(encrypted_key.encode())
        return json.loads(decrypted_key.decode())
    except Exception:
        raise ValueError(f"{bcolors.FAIL}Failed to decrypt key. Wrong passphrase?{bcolors.ENDC}")

# -----------------------------
# RSA Helpers
# -----------------------------
def is_probable_prime(n: int, trials: int = 5) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(trials):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def egcd(a: int, b: int) -> tuple:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modinv_int(a: int, m: int) -> int:
    gcd, x, _ = egcd(a, m)
    if gcd != 1:
        raise ValueError(f"{bcolors.FAIL}Modular inverse does not exist{bcolors.ENDC}")
    return x % m

def generate_rsa_keypair(bits: int) -> dict:
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    d = modinv_int(e, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}

def int_to_bytes_be(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def int_to_bytes_be_fixed(n: int, k: int) -> bytes:
    """Big-endian, left-padded with zeros to exactly k bytes."""
    b = int_to_bytes_be(n)
    if len(b) > k:
        raise ValueError(f"{bcolors.FAIL}Integer too large for target length{bcolors.ENDC}")
    return b.rjust(k, b'\x00')

def bytes_be_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

# -----------------------------
# Encryption/Decryption
# -----------------------------
def derive_seed_bytes(nonce: bytes, seed_len: int = 32) -> bytes:
    return shake(seed_len, nonce)

def oaep_encode(message: bytes, n: int, seed: bytes) -> int:
    k = (n.bit_length() + 7) // 8
    mlen = len(message)
    if mlen > k - 2 * 32 - 2:
        raise ValueError(f"{bcolors.FAIL}Message too long for OAEP{bcolors.ENDC}")
    hlen = 32
    pad_len = k - mlen - 2 * hlen - 2
    lhash = shake(hlen, b"")
    ps = b'\x00' * pad_len
    db = lhash + ps + b'\x01' + message
    seed = shake(hlen, seed)
    db_mask = shake(k - hlen - 1, seed)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = shake(hlen, masked_db)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return int.from_bytes(b'\x00' + masked_seed + masked_db, 'big')

def oaep_decode(cipher_int: int, n: int) -> bytes:
    """Decode OAEP given integer ciphertext and modulus. Handles left-padding to k bytes."""
    k = (n.bit_length() + 7) // 8
    c = int_to_bytes_be_fixed(cipher_int, k)
    if c[0] != 0:
        raise ValueError(f"{bcolors.FAIL}Invalid OAEP format{bcolors.ENDC}")
    hlen = 32
    masked_seed = c[1:1 + hlen]
    masked_db = c[1 + hlen:]
    seed_mask = shake(hlen, masked_db)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = shake(k - hlen - 1, seed)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    lhash = shake(hlen, b"")
    if db[:hlen] != lhash:
        raise ValueError(f"{bcolors.FAIL}Invalid OAEP lhash{bcolors.ENDC}")
    i = hlen
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 1:
        raise ValueError(f"{bcolors.FAIL}Invalid OAEP padding{bcolors.ENDC}")
    return db[i + 1:]

def validate_timestamp(timestamp: float, validity_window: int) -> bool:
    current_time = time.time()
    return abs(current_time - timestamp) <= validity_window

def veinn_from_seed(seed_input: str, vp: VeinnParams):
    seed = seed_input.encode('utf-8')
    k = key_from_seed(seed, vp)
    print(f"Derived VEINN key with params: n={vp.n}, rounds={vp.rounds}, layers_per_round={vp.layers_per_round}, shuffle_stride={vp.shuffle_stride}, use_lwe={vp.use_lwe}")

def encrypt_with_pub(pubfile: str, message: Optional[str] = None, numbers: Optional[list] = None, in_path: Optional[str] = None, mode: str = "t", vp: VeinnParams = VeinnParams(), seed_len: int = 32, nonce: Optional[bytes] = None, out_file: str = "enc_pub.json") -> str:
    with open(pubfile, "r") as f:
        pub = json.load(f)
    n = pub["n"]
    e = pub["e"]
    if in_path:
        with open(in_path, "rb") as f:
            message_bytes = f.read()
    elif mode == "t":
        if not message:
            raise ValueError(f"{bcolors.FAIL}Message required for text mode{bcolors.ENDC}")
        message_bytes = message.encode('utf-8')
    else:
        if not numbers:
            raise ValueError(f"{bcolors.FAIL}Numbers required for numeric mode{bcolors.ENDC}")
        bytes_per_number = vp.n * 2
        message_bytes = b""
        for num in numbers:
            message_bytes += num.to_bytes(bytes_per_number, 'big', signed=True)
    message_bytes = pkcs7_pad(message_bytes, vp.n * 2)
    nonce = nonce or secrets.token_bytes(16)
    ephemeral_seed = derive_seed_bytes(nonce, seed_len)
    k = key_from_seed(ephemeral_seed, vp)
    blocks = [bytes_to_block(message_bytes[i:i + vp.n * 2], vp.n) for i in range(0, len(message_bytes), vp.n * 2)]
    for b in blocks:
        assert b.shape == (vp.n,), f"Block shape mismatch: expected {(vp.n,)}, got {b.shape}"
    enc_blocks = [permute_forward(b, k) for b in blocks]
    seed_int = oaep_encode(ephemeral_seed, n, nonce)
    enc_seed = pow(seed_int, e, n)
    enc_seed_bytes = int_to_bytes_be(enc_seed)  # HMAC uses this raw (unpadded) form
    metadata = {
        "n": vp.n,
        "rounds": vp.rounds,
        "layers_per_round": vp.layers_per_round,
        "shuffle_stride": vp.shuffle_stride,
        "use_lwe": vp.use_lwe,
        "mode": mode,
        "bytes_per_number": vp.n * 2
    }
    timestamp = time.time()
    msg_for_hmac = enc_seed_bytes + b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, 'big')
    hmac_value = hmac.new(ephemeral_seed, msg_for_hmac, hashlib.sha256).hexdigest()
    write_ciphertext_json(out_file, enc_blocks, metadata, enc_seed_bytes, hmac_value, nonce, timestamp)
    print(f"Encrypted to {out_file}")
    return out_file

def decrypt_with_priv(keystore: Optional[str], privfile: Optional[str], encfile: str, passphrase: Optional[str], key_name: Optional[str], validity_window: int):
    if keystore and passphrase and key_name:
        privkey = retrieve_key_from_keystore(passphrase, key_name, keystore)
    else:
        with open(privfile, "r") as f:
            privkey = json.load(f)
    n = privkey["n"]
    d = privkey["d"]
    metadata, enc_seed_bytes, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(encfile)
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError(f"{bcolors.FAIL}Timestamp outside validity window{bcolors.ENDC}")
    # RSA decrypt OAEP
    enc_seed_int = bytes_be_to_int(enc_seed_bytes)
    seed_int = pow(enc_seed_int, d, n)
    ephemeral_seed = oaep_decode(seed_int, n)
    # Verify HMAC
    msg_for_hmac = enc_seed_bytes + b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, 'big')
    if not hmac.compare_digest(hmac.new(ephemeral_seed, msg_for_hmac, hashlib.sha256).hexdigest(), hmac_value):
        raise ValueError(f"{bcolors.FAIL}HMAC verification failed{bcolors.ENDC}")
    # Decrypt blocks
    vp = VeinnParams(
        n=metadata["n"],
        rounds=metadata["rounds"],
        layers_per_round=metadata["layers_per_round"],
        shuffle_stride=metadata["shuffle_stride"],
        use_lwe=metadata["use_lwe"]
    )
    k = key_from_seed(ephemeral_seed, vp)
    dec_blocks = [permute_inverse(b, k) for b in enc_blocks]
    dec_bytes = b"".join(block_to_bytes(b) for b in dec_blocks)
    dec_bytes = pkcs7_unpad(dec_bytes)
    mode = metadata.get("mode", "n")
    if mode == "t":
        print("Decrypted message:", dec_bytes.decode('utf-8'))
    else:
        bytes_per_number = metadata.get("bytes_per_number", vp.n * 2)
        numbers = [int.from_bytes(dec_bytes[i:i + bytes_per_number], 'big', signed=True)
                   for i in range(0, len(dec_bytes), bytes_per_number)]
        print("Decrypted numbers:", numbers)

def encrypt_with_public_veinn(seed_input: str, message: Optional[str] = None, numbers: Optional[list] = None, vp: VeinnParams = VeinnParams(), out_file: str = "enc_pub_veinn.json", mode: str = "t", bytes_per_number: Optional[int] = None, nonce: Optional[bytes] = None) -> str:
    seed = seed_input.encode('utf-8')
    k = key_from_seed(seed, vp)
    if message or mode == "t":
        if not message:
            raise ValueError(f"{bcolors.FAIL}Message required for text mode{bcolors.ENDC}")
        message_bytes = message.encode('utf-8')
    else:
        if not numbers:
            raise ValueError(f"{bcolors.FAIL}Numbers required for numeric mode{bcolors.ENDC}")
        if not bytes_per_number:
            bytes_per_number = vp.n * 2
        message_bytes = b""
        for num in numbers:
            message_bytes += num.to_bytes(bytes_per_number, 'big', signed=True)
    message_bytes = pkcs7_pad(message_bytes, vp.n * 2)
    nonce = nonce or secrets.token_bytes(16)
    blocks = [bytes_to_block(message_bytes[i:i + vp.n * 2], vp.n) for i in range(0, len(message_bytes), vp.n * 2)]
    for b in blocks:
        assert b.shape == (vp.n,), f"Block shape mismatch: expected {(vp.n,)}, got {b.shape}"
    enc_blocks = [permute_forward(b, k) for b in blocks]
    metadata = {
        "n": vp.n,
        "rounds": vp.rounds,
        "layers_per_round": vp.layers_per_round,
        "shuffle_stride": vp.shuffle_stride,
        "use_lwe": vp.use_lwe,
        "mode": mode,
        "bytes_per_number": bytes_per_number or vp.n * 2
    }
    timestamp = time.time()
    msg_for_hmac = b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, 'big')
    hmac_value = hmac.new(seed, msg_for_hmac, hashlib.sha256).hexdigest()
    write_ciphertext_json(out_file, enc_blocks, metadata, b"", hmac_value, nonce, timestamp)
    print(f"Encrypted to {out_file}")
    return out_file

def decrypt_with_public_veinn(seed_input: str, enc_file: str, validity_window: int):
    seed = seed_input.encode('utf-8')
    metadata, _, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file)
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError(f"{bcolors.FAIL}Timestamp outside validity window{bcolors.ENDC}")
    msg_for_hmac = b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, 'big')
    if not hmac.compare_digest(hmac.new(seed, msg_for_hmac, hashlib.sha256).hexdigest(), hmac_value):
        raise ValueError(f"{bcolors.FAIL}HMAC verification failed{bcolors.ENDC}")
    vp = VeinnParams(
        n=metadata["n"],
        rounds=metadata["rounds"],
        layers_per_round=metadata["layers_per_round"],
        shuffle_stride=metadata["shuffle_stride"],
        use_lwe=metadata["use_lwe"]
    )
    k = key_from_seed(seed, vp)
    dec_blocks = [permute_inverse(b, k) for b in enc_blocks]
    dec_bytes = b"".join(block_to_bytes(b) for b in dec_blocks)
    dec_bytes = pkcs7_unpad(dec_bytes)
    mode = metadata.get("mode", "n")
    if mode == "t":
        print("Decrypted message:", dec_bytes.decode('utf-8'))
    else:
        bytes_per_number = metadata.get("bytes_per_number", vp.n * 2)
        numbers = [int.from_bytes(dec_bytes[i:i + bytes_per_number], 'big', signed=True)
                   for i in range(0, len(dec_bytes), bytes_per_number)]
        print("Decrypted numbers:", numbers)

# -----------------------------
# Serialization Helpers
# -----------------------------
def write_ciphertext_json(path: str, encrypted_blocks: list, metadata: dict, enc_seed_bytes: bytes, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    payload = {
        "veinn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed_bytes],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in encrypted_blocks]
    }
    if hmac_value:
        payload["hmac"] = hmac_value
    if nonce:
        payload["nonce"] = [int(b) for b in nonce]
    if timestamp:
        payload["timestamp"] = timestamp
    with open(path, "w") as f:
        json.dump(payload, f)

def read_ciphertext(path: str):
    with open(path, "r") as f:
        payload = json.load(f)
    enc_seed = bytes([int(b) for b in payload["enc_seed"]])
    metadata = payload["veinn_metadata"]
    enc_blocks = [np.array([int(x) for x in blk], dtype=DTYPE) for blk in payload["encrypted"]]
    hmac_value = payload.get("hmac")
    nonce = bytes([int(b) for b in payload.get("nonce", [])]) if "nonce" in payload else None
    timestamp = payload.get("timestamp")
    return metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp

# -----------------------------
# CLI Main with Interactive Menu
# -----------------------------
def menu_generate_keystore():
    passphrase = input("Enter keystore passphrase: ")
    keystore_file = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
    create_keystore(passphrase, keystore_file)

def menu_generate_rsa_keypair():
    bits = int(input("RSA key size in bits (default 2048): ").strip() or 2048)
    pubfile = input("Public key filename (default rsa_pub.json): ").strip() or "rsa_pub.json"
    use_keystore = input("Store private key in keystore? (y/n): ").strip().lower() or "y"
    privfile, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Key name in keystore: ")
    else:
        privfile = input("Private key filename (default rsa_priv.json): ").strip() or "rsa_priv.json"
    keypair = generate_rsa_keypair(bits)
    with open(pubfile, "w") as f:
        json.dump({"n": keypair["n"], "e": keypair["e"]}, f)
    if use_keystore == "y":
        store_key_in_keystore(passphrase, key_name, keypair, keystore)
        print(f"RSA keys generated: {pubfile} (public), private stored in keystore")
    else:
        with open(privfile, "w") as f:
            json.dump(keypair, f)
        print(f"RSA keys generated: {pubfile} (public), {privfile} (private)")

def menu_encrypt_with_pub():
    pubfile = input("Recipient RSA public key file (default rsa_pub.json): ").strip() or "rsa_pub.json"
    if not os.path.exists(pubfile):
        print("Public key not found. Generate RSA keys first.")        
    inpath = input("Optional input file path (blank = prompt): ").strip() or None
    mode = input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "t"
    n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
    rounds = int(input("Number of rounds (default 3): ").strip() or 3)
    layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
    shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    seed_len = int(input("Seed length (default 32): ").strip() or 32)
    nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
    nonce = b64decode(nonce_str) if nonce_str else None
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
    message = None
    numbers = None
    if inpath is None:
        if mode == "t":
            message = input("Message to encrypt: ")
        else:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
            numbers = [int(x) for x in raw_nums]
    encrypt_with_pub(pubfile, message=message, numbers=numbers, in_path=inpath, mode=mode, vp=vp, seed_len=seed_len, nonce=nonce)

def menu_decrypt_with_priv():
    use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() or "y"
    privfile, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Key name in keystore: ")
    else:
        privfile = input("RSA private key file (default rsa_priv.json): ").strip() or "rsa_priv.json"
    encfile = input("Encrypted file to decrypt (default enc_pub.json): ").strip() or "enc_pub.json"
    validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
    if not os.path.exists(encfile):
        print("Encrypted file not found.")
    decrypt_with_priv(keystore, privfile, encfile, passphrase, key_name, validity_window)

def menu_homomorphic_add_files():
    f1 = input("Encrypted file 1: ").strip()
    f2 = input("Encrypted file 2: ").strip()
    out = input("Output filename (default hom_add.json): ").strip() or "hom_add.json"
    homomorphic_add_files(f1, f2, out)

def menu_homomorphic_mul_files():
    f1 = input("Encrypted file 1: ").strip()
    f2 = input("Encrypted file 2: ").strip()
    out = input("Output filename (default hom_mul.json): ").strip() or "hom_mul.json"
    homomorphic_mul_files(f1, f2, out)

def menu_veinn_from_seed():
    use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() == "y"
    seed_input, keystore, passphrase, key_name = None, None, None, None
    if use_keystore:
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Seed name in keystore: ")
        seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
        seed_input = seed_data["seed"]
    else:
        seed_input = input("Enter seed string (publicly shared): ").strip()
    n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
    rounds = int(input("Number of rounds (default 3): ").strip() or 3)
    layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
    shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
    veinn_from_seed(seed_input, vp)

def menu_encrypt_with_public_veinn():
    use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() or "y"
    seed_input, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Seed name in keystore: ")                            
        store_key_in_keystore(passphrase, key_name, {"seed": key_name}, keystore)
        seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
        seed_input = seed_data["seed"]
    else:
        seed_input = input("Enter public seed string: ").strip()
    mode = input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "t"
    message = None
    numbers = None
    bytes_per_number = None
    if mode == "t":
        message = input("Message to encrypt: ")
    else:
        content = input("Enter numbers (comma or whitespace separated): ").strip()
        raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
        numbers = [int(x) for x in raw_nums]
        bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
    n = int(input("Number of uint16 words per block (default 8): ").strip() or 8)
    rounds = int(input("Number of rounds (default 3): ").strip() or 3)
    layers_per_round = int(input("Layers per round (default 2): ").strip() or 2)
    shuffle_stride = int(input("Shuffle stride (default 7): ").strip() or 7)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    out_file = input("Output encrypted filename (default enc_pub_veinn.json): ").strip() or "enc_pub_veinn.json"
    nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
    nonce = b64decode(nonce_str) if nonce_str else None
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe)
    out_file = encrypt_with_public_veinn(seed_input, message, numbers, vp, out_file, mode, bytes_per_number, nonce)   

def menu_decrypt_with_public_veinn():
    use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() or "y"
    seed_input, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Seed name in keystore: ")
        seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
        seed_input = seed_data["seed"]
    else:
        seed_input = input("Enter public seed string: ").strip()
    enc_file = input("Encrypted file to decrypt (default enc_pub_veinn.json): ").strip() or "enc_pub_veinn.json"
    validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
    if not os.path.exists(enc_file):
        print("Encrypted file not found.")        
    decrypt_with_public_veinn(seed_input, enc_file, validity_window)

def main():
    parser = argparse.ArgumentParser(description="VEINN CLI with Lattice-based INN")
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for homomorphic addition
    hom_add_parser = subparsers.add_parser("hom_add", help="Lattice-based homomorphic addition")
    hom_add_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_add_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_add_parser.add_argument("--out_file", default="hom_add.json", help="Output file")

    # Subparser for homomorphic multiplication
    hom_mul_parser = subparsers.add_parser("hom_mul", help="Lattice-based homomorphic multiplication")
    hom_mul_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_mul_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_mul_parser.add_argument("--out_file", default="hom_mul.json", help="Output file")

    # Subparser for creating keystore
    create_keystore_parser = subparsers.add_parser("create_keystore", help="Create encrypted keystore")
    create_keystore_parser.add_argument("--passphrase", required=True, help="Keystore passphrase")
    create_keystore_parser.add_argument("--keystore_file", default="keystore.json", help="Keystore filename")

    # Subparser for generating RSA keypair
    generate_rsa_parser = subparsers.add_parser("generate_rsa", help="Generate RSA keypair")
    generate_rsa_parser.add_argument("--bits", type=int, default=2048, help="RSA key size in bits")
    generate_rsa_parser.add_argument("--pubfile", default="rsa_pub.json", help="Public key filename")
    generate_rsa_parser.add_argument("--privfile", default="rsa_priv.json", help="Private key filename")
    generate_rsa_parser.add_argument("--keystore", help="Keystore filename for private key")
    generate_rsa_parser.add_argument("--passphrase", help="Keystore passphrase")
    generate_rsa_parser.add_argument("--key_name", help="Key name in keystore")

    # Subparser for public encryption
    public_encrypt_parser = subparsers.add_parser("public_encrypt", help="Encrypt with public key (RSA + VEINN)")
    public_encrypt_parser.add_argument("--pubfile", default="rsa_pub.json", help="RSA public key file")
    public_encrypt_parser.add_argument("--in_path", help="Input file path")
    public_encrypt_parser.add_argument("--mode", choices=["t", "n"], default="t", help="Input mode")
    public_encrypt_parser.add_argument("--n", type=int, default=8, help="Number of uint16 words per block")
    public_encrypt_parser.add_argument("--rounds", type=int, default=3, help="Number of rounds")
    public_encrypt_parser.add_argument("--layers_per_round", type=int, default=2, help="Layers per round")
    public_encrypt_parser.add_argument("--shuffle_stride", type=int, default=7, help="Shuffle stride")
    public_encrypt_parser.add_argument("--use_lwe", type=bool, default=True, help="Use LWE PRF")
    public_encrypt_parser.add_argument("--seed_len", type=int, default=32, help="Seed length")
    public_encrypt_parser.add_argument("--nonce", help="Custom nonce (base64)")
    public_encrypt_parser.add_argument("--out_file", default="enc_pub.json", help="Output encrypted file")

    # Subparser for decryption
    public_decrypt_parser = subparsers.add_parser("public_decrypt", help="Decrypt with private key")
    public_decrypt_parser.add_argument("--keystore", help="Keystore filename")
    public_decrypt_parser.add_argument("--privfile", default="rsa_priv.json", help="Private key file")
    public_decrypt_parser.add_argument("--encfile", default="enc_pub.json", help="Encrypted file")
    public_decrypt_parser.add_argument("--passphrase", help="Keystore passphrase")
    public_decrypt_parser.add_argument("--key_name", help="Key name in keystore")
    public_decrypt_parser.add_argument("--validity_window", type=int, default=3600, help="Timestamp validity window (seconds)")

    # Subparser for public VEINN derivation
    public_veinn_parser = subparsers.add_parser("public_veinn", help="Derive public VEINN from seed")
    public_veinn_parser.add_argument("--seed", required=True, help="Seed string")
    public_veinn_parser.add_argument("--n", type=int, default=8, help="Number of uint16 words per block")
    public_veinn_parser.add_argument("--rounds", type=int, default=3, help="Number of rounds")
    public_veinn_parser.add_argument("--layers_per_round", type=int, default=2, help="Layers per round")
    public_veinn_parser.add_argument("--shuffle_stride", type=int, default=7, help="Shuffle stride")
    public_veinn_parser.add_argument("--use_lwe", type=bool, default=True, help="Use LWE PRF")

    args = parser.parse_known_args()[0]

    try:
        match args.command:
            case "hom_add":
                homomorphic_add_files(args.file1, args.file2, args.out_file)        
            case "hom_mul":
                homomorphic_mul_files(args.file1, args.file2, args.out_file)
            case "create_keystore":
                create_keystore(args.passphrase, args.keystore_file)
                print(f"Keystore created: {args.keystore_file}")
            case "generate_rsa":
                keypair = generate_rsa_keypair(args.bits)
                with open(args.pubfile, "w") as f:
                    json.dump({"n": keypair["n"], "e": keypair["e"]}, f)
                if args.keystore and args.passphrase and args.key_name:
                    store_key_in_keystore(args.passphrase, args.key_name, keypair, args.keystore)
                    print(f"RSA keys generated: {args.pubfile} (public), private stored in keystore")
                else:
                    with open(args.privfile, "w") as f:
                        json.dump(keypair, f)
                    print(f"RSA keys generated: {args.pubfile} (public), {args.privfile} (private)")
            case "public_encrypt":
                vp = VeinnParams(
                    n=args.n,
                    rounds=args.rounds,
                    layers_per_round=args.layers_per_round,
                    shuffle_stride=args.shuffle_stride,
                    use_lwe=args.use_lwe
                )
                nonce = b64decode(args.nonce) if args.nonce else None
                encrypt_with_pub(
                    args.pubfile,
                    in_path=args.in_path,
                    mode=args.mode,
                    vp=vp,
                    seed_len=args.seed_len,
                    nonce=nonce,
                    out_file=args.out_file
                )
            case "public_decrypt":
                decrypt_with_priv(
                    args.keystore,
                    args.privfile,
                    args.encfile,
                    args.passphrase,
                    args.key_name,
                    args.validity_window
                )
            case "public_veinn":
                vp = VeinnParams(
                    n=args.n,
                    rounds=args.rounds,
                    layers_per_round=args.layers_per_round,
                    shuffle_stride=args.shuffle_stride,
                    use_lwe=args.use_lwe
                )
                veinn_from_seed(args.seed, vp)
        _=os.system("cls") | os.system("clear")        
        while True:
            print(f"{bcolors.OKCYAN}VEINN CLI — Lattice-based INN with LWE-based Key Nonlinearity{bcolors.ENDC}")
            print(f"{bcolors.OKCYAN}Nonlinearity via LWE PRF; linear INN for invertibility and homomorphism.{bcolors.ENDC}")
            print("")
            print(f"{bcolors.BOLD}1){bcolors.ENDC} Create encrypted keystore")
            print(f"{bcolors.BOLD}2){bcolors.ENDC} Generate RSA keypair (public/private)")
            print(f"{bcolors.BOLD}3){bcolors.ENDC} Encrypt with recipient public key (RSA + VEINN)")
            print(f"{bcolors.BOLD}4){bcolors.ENDC} Decrypt with private key")
            print(f"{bcolors.BOLD}5){bcolors.ENDC} Encrypt deterministically using public VEINN")
            print(f"{bcolors.BOLD}6){bcolors.ENDC} Decrypt deterministically using public VEINN")
            print(f"{bcolors.GREY}7) Lattice-based homomorphic add (file1, file2 -> out){bcolors.ENDC}")
            print(f"{bcolors.GREY}8) Lattice-based homomorphic multiply (file1, file2 -> out){bcolors.ENDC}")
            print(f"{bcolors.GREY}9) Derive public VEINN from seed{bcolors.ENDC}")

            print(f"{bcolors.BOLD}0){bcolors.ENDC} Exit")
            choice = input(f"{bcolors.BOLD}Choice: {bcolors.ENDC}").strip()

            try:
                match choice:
                    case "0":
                        break
                    case "1":
                        menu_generate_keystore()
                    case "2":
                        menu_generate_rsa_keypair()
                    case "3":
                        menu_encrypt_with_pub()
                    case "4":
                        menu_decrypt_with_priv()
                    case "5":
                        menu_encrypt_with_public_veinn()
                    case "6":
                        menu_decrypt_with_public_veinn()
                    case "7":
                        menu_homomorphic_add_files()
                    case "8":
                        menu_homomorphic_mul_files()
                    case "9":                        
                        menu_veinn_from_seed()
                    case _:
                        print("Invalid choice")
            except Exception as e:
                print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC}", e)
            _=input(f"{bcolors.OKGREEN}Any Key to Continue{bcolors.ENDC}")
            _=os.system("cls") | os.system("clear")
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC}", e)
        sys.exit(1)
if __name__ == "__main__":
    main()
