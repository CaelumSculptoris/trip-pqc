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
from kyber_py.ml_kem import ML_KEM_768  # Using ML_KEM_768 for ~128-bit security

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
@dataclass
class VeinnParams:
    n: int = 512  # Number of int64 words per block
    rounds: int = 10
    layers_per_round: int = 10
    shuffle_stride: int = 11
    use_lwe: bool = True
    valid: int = 3600
    seed_len: int = 32
    q: int = 1049089 #1048577

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
    return np.frombuffer(raw, dtype=np.int64)[:count].copy()

def odd_constant_from_key(tag: bytes) -> int:
    x = int.from_bytes(shake(2, tag), 'little')
    x |= 1
    return x & (VeinnParams.q - 1)

def pad_iso7816(data: bytes, blocksize: int) -> bytes:
    padlen = (-len(data)) % blocksize
    if padlen == 0:
        padlen = blocksize
    return data + b"\x80" + b"\x00"*(padlen-1)

def unpad_iso7816(padded: bytes) -> bytes:
    i = padded.rfind(b"\x80")
    if i == -1 or any(b != 0 for b in padded[i+1:]):
        raise ValueError("Invalid padding")
    return padded[:i]

# Primary S-box: modular inverse (0 -> 0). Clean, bijective if q is prime (or for units).
def sbox_val_modinv(x, q: int):
    x = int(x) % q  # force to plain int
    if x == 0:
        return 0
    try:
        return pow(x, -1, q)  # Python int only
    except ValueError:
        return None  # no modular inverse

# Fallback S-box: exponentiation
def sbox_val_pow(x, q: int, e: int = 3):
    x = int(x) % q
    if x == 0:
        return 0
    return pow(x, e, q)

# Wrapper: try modinv, otherwise fallback
def sbox_val(x, q: int, fallback_e: int = 3):
    v = sbox_val_modinv(x, q)
    if v is not None:
        return v
    return sbox_val_pow(x, q, fallback_e)

# Vectorized layer
def sbox_layer(vec, q: int, fallback_e: int = 3):
    if isinstance(vec, np.ndarray):
        out = np.empty_like(vec, dtype=np.int64)
        it = np.nditer(vec, flags=['multi_index'])
        while not it.finished:
            out[it.multi_index] = sbox_val(int(it[0]), q, fallback_e)
            it.iternext()
        return out % q
    else:
        return [sbox_val(int(x), q, fallback_e) for x in vec]

# Inverse S-box
def inv_sbox_val(x, q: int, fallback_e: int = 3):
    x = int(x) % q
    try:
        return sbox_val_modinv(x, q) or sbox_val_pow(x, q, fallback_e)
    except Exception:
        return sbox_val_pow(x, q, fallback_e)

def inv_sbox_layer(vec, q: int, fallback_e: int = 3):
    if isinstance(vec, np.ndarray):
        out = np.empty_like(vec, dtype=np.int64)
        it = np.nditer(vec, flags=['multi_index'])
        while not it.finished:
            out[it.multi_index] = inv_sbox_val(int(it[0]), q, fallback_e)
            it.iternext()
        return out % q
    else:
        return [inv_sbox_val(int(x), q, fallback_e) for x in vec]


# -----------------------------
# Ring Convolution with Iterative NTT
# -----------------------------
def ring_convolution(a, b, q, method="ntt"):
    n = len(a)
    a = np.array(a, dtype=np.int64) % q
    b = np.array(b, dtype=np.int64) % q
    
    if method == "naive":
        res = np.zeros(2*n, dtype=object)
        for i in range(n):
            for j in range(n):
                res[i+j] = (res[i+j] + int(a[i]) * int(b[j])) % q
        res = (res[:n] - res[n:]) % q
        return res.astype(np.int64)

    elif method == "ntt":
        a_padded = np.zeros(2*n, dtype=np.int64)
        a_padded[:n] = a
        b_padded = np.zeros(2*n, dtype=np.int64)
        b_padded[:n] = b
        root = pow(find_primitive_root(q), (q - 1) // (2 * n), q)
        A = iterative_ntt(a_padded, root, q)
        B = iterative_ntt(b_padded, root, q)
        C = mod_mul(A, B, q)
        res = iterative_intt(C, root, q)
        res = (res[:n] - res[n:]) % q
        return res.astype(np.int64)

    else:
        raise ValueError("method must be one of: naive, ntt")

def iterative_ntt(a: np.ndarray, root: int, q: int) -> np.ndarray:
    n = len(a)
    a = a.copy()
    t = n
    m = 1
    while m < n:
        t //= 2
        for i in range(m):
            j1 = 2 * i * t
            j2 = j1 + t - 1
            S = pow(root, m + i, q)
            for j in range(j1, j2 + 1):
                U = a[j]
                V = (a[j + t] * S) % q
                a[j] = (U + V) % q
                a[j + t] = (U - V) % q
        m *= 2
    return a

def iterative_intt(A: np.ndarray, root: int, q: int) -> np.ndarray:
    n = len(A)
    root_inv = pow(root, q-2, q)
    a = iterative_ntt(A, root_inv, q)
    inv_n = pow(n, q-2, q)
    return (a * inv_n) % q

def mod_mul(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    return ((a.astype(object) * b.astype(object)) % q).astype(np.int64)

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

def lwe_prf_expand(seed: bytes, out_n: int, vp: VeinnParams) -> np.ndarray:
    """Generate pseudorandom parameters with LWE noise, avoiding recursion."""
    n = vp.n
    # Use SHAKE-256 directly for s and a to prevent recursive calls
    s = np.frombuffer(shake(n * 8, seed, b"s"), dtype=np.int64)[:n] & (vp.q - 1)
    a = np.frombuffer(shake(n * 8, seed, b"A"), dtype=np.int64)[:n] & (vp.q - 1)
    raw = shake(n, seed, b"e")
    e = np.frombuffer(raw, dtype=np.uint8)[:n].astype(np.int64)
    e = ((e % 9) - 4).astype(np.int64) % vp.q
    assert s.shape == (n,) and a.shape == (n,) and e.shape == (n,), f"LWE parameter shape mismatch{e.shape, a.shape, s.shape}"
    b = ring_convolution(a, s, vp.q, 'ntt').astype(np.int64)
    b = (b + e) % vp.q
    out = np.zeros(out_n, dtype=np.int64)
    for i in range(out_n):
        out[i] = int(b[i % n]) & (vp.q - 1)
    assert out.shape == (out_n,), f"Expected output shape {(out_n,)}, got {out.shape}"
    return out

# -----------------------------
# Coupling Layer
# -----------------------------
@dataclass
class CouplingParams:
    mask_a: np.ndarray
    mask_b: np.ndarray

def coupling_forward(x: np.ndarray, cp: CouplingParams, key: VeinnParams) -> np.ndarray:
    n = x.shape[0]
    h = n // 2
    assert x.shape == (n,), f"Expected input shape {(n,)}, got {x.shape}"
    assert cp.mask_a.shape == (h,) and cp.mask_b.shape == (h,), f"Mask shape mismatch: expected {(h,)}, got {cp.mask_a.shape}, {cp.mask_b.shape}"
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    t = (x2.astype(np.int64) + cp.mask_a.astype(np.int64)) % key.q
    t = ring_convolution(t, np.ones(h, dtype=np.int64), key.q, 'ntt')
    x1 = (x1.astype(np.int64) + t) % key.q
    u = (x1.astype(np.int64) + cp.mask_b.astype(np.int64)) % key.q
    u = ring_convolution(u, np.ones(h, dtype=np.int64), key.q, 'ntt')
    x2 = (x2.astype(np.int64) + u) % key.q
    return np.concatenate([x1.astype(np.int64), x2.astype(np.int64)])

def coupling_inverse(x: np.ndarray, cp: CouplingParams, key: VeinnParams) -> np.ndarray:
    n = x.shape[0]
    h = n // 2
    assert x.shape == (n,), f"Expected input shape {(n,)}, got {x.shape}"
    assert cp.mask_a.shape == (h,) and cp.mask_b.shape == (h,), f"Mask shape mismatch: expected {(h,)}, got {cp.mask_a.shape}, {cp.mask_b.shape}"
    x1 = x[:h].copy()
    x2 = x[h:].copy()
    u = (x1.astype(np.int64) + cp.mask_b.astype(np.int64)) % key.q
    u = ring_convolution(u, np.ones(h, dtype=np.int64), key.q, 'ntt')
    x2 = (x2.astype(np.int64) - u) % key.q
    t = (x2.astype(np.int64) + cp.mask_a.astype(np.int64)) % key.q
    t = ring_convolution(t, np.ones(h, dtype=np.int64), key.q, 'ntt')
    x1 = (x1.astype(np.int64) - t) % key.q
    return np.concatenate([x1.astype(np.int64), x2.astype(np.int64)])

# -----------------------------
# Shuffle
# -----------------------------
def make_shuffle_indices(n: int, stride: int) -> np.ndarray:
    if math.gcd(stride, n) != 1:
        raise ValueError(f"{bcolors.FAIL}shuffle_stride must be coprime with n{bcolors.ENDC}")
    return np.array([(i * stride) % n for i in range(n)], dtype=np.int64)

def shuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    assert x.shape[0] == idx.shape[0], f"Shuffle shape mismatch: input {x.shape}, indices {idx.shape}"
    return x[idx].astype(np.int64)

def unshuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray:
    assert x.shape[0] == idx.shape[0], f"Unshuffle shape mismatch: input {x.shape}, indices {idx.shape}"
    inv = np.empty_like(idx)
    inv[idx] = np.arange(len(idx))
    return x[inv].astype(np.int64)

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
    out = np.zeros_like(arr, dtype=np.int64)
    for i, v in enumerate(arr.astype(int).tolist()):
        out[i] = modinv(v, VeinnParams.q)
    return out

def ensure_coprime_to_q_vec(vec, q):
    # Change any multiples of q to 1 to ensure invertibility
    vec = np.where(vec % q == 0, 1, vec)
    return vec

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
        # Convert to a signed integer type to prevent overflow
        scale = scale.astype(np.int64)
        # Ensure all elements are coprime to VeinnParams.q
        scale = ensure_coprime_to_q_vec(scale, VeinnParams.q)
        scale_inv = inv_vec_mod_q(scale)

        assert scale.shape == (n,), f"Ring scale shape mismatch: expected {(n,)}, got {scale.shape}"
        assert scale_inv.shape == (n,), f"Ring inv shape mismatch: expected {(n,)}, got {scale_inv.shape}"
        rounds.append(RoundParams(cpls, scale, scale_inv))
    return VeinnKey(seed=seed, params=vp, shuffle_idx=shuffle_idx, rounds=rounds)


# -----------------------------
# Permutation (updated to use invertible scaling)
# -----------------------------
def permute_forward(x: np.ndarray, key: VeinnParams) -> np.ndarray:
    vp = key.params    
    idx = key.shuffle_idx
    assert x.shape == (vp.n,), f"Expected input shape {(vp.n,)}, got {x.shape}"
    y = x.copy()
    for r in range(vp.rounds):
        for cp in key.rounds[r].cpls:
            y = coupling_forward(y, cp, vp)
        # Invertible elementwise scaling
        y = (y.astype(np.int64) * key.rounds[r].ring_scale.astype(np.int64)) % vp.q
        y = np.array(sbox_layer(y, vp.q), dtype=np.int64)
        y = shuffle(y, idx)
    return y.astype(np.int64)

def permute_inverse(x: np.ndarray, key: VeinnParams) -> np.ndarray:
    vp = key.params
    idx = key.shuffle_idx
    assert x.shape == (vp.n,), f"Expected input shape {(vp.n,)}, got {x.shape}"
    y = x.copy()
    for r in reversed(range(vp.rounds)):
        y = unshuffle(y, idx)
        y = np.array(inv_sbox_layer(y, vp.q), dtype=np.int64)
        # Apply precomputed inverse scaling
        y = (y.astype(np.int64) * key.rounds[r].ring_scale_inv.astype(np.int64)) % vp.q
        for cp in reversed(key.rounds[r].cpls):
            y = coupling_inverse(y, cp, vp)
    return y.astype(np.int64)

# -----------------------------
# Block Helpers
# -----------------------------
def bytes_to_block(b: bytes, n: int) -> np.ndarray:
    padded = b.ljust(2 * n, b'\x00')
    arr = np.frombuffer(padded, dtype='<u2')[:n].copy()    
    return arr.astype(np.int64)

def block_to_bytes(x: np.ndarray) -> bytes:
    return x.astype('<u2').tobytes()

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
# Kyber Key Generation
# -----------------------------
def generate_kyber_keypair() -> dict:
    ek, dk = ML_KEM_768.keygen()
    return {"ek": list(ek), "dk": list(dk)}  # Store as lists for JSON

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

def encrypt_with_pub(pubfile: str, file_type: str, message: Optional[str] = None, in_path: Optional[str] = None, vp: VeinnParams = VeinnParams(), seed_len: int = 32, nonce: Optional[bytes] = None, out_file: str = "enc_pub") -> str:
    with open(pubfile, "r") as f:
        pub = json.load(f)
    ek = bytes(pub["ek"])
    if in_path:
        with open(in_path, "rb") as f:
            message_bytes = f.read()
    else:
        if not message:
            raise ValueError(f"{bcolors.FAIL}Message required for text mode{bcolors.ENDC}")
        message_bytes = message.encode('utf-8')

    message_bytes = pad_iso7816(message_bytes, vp.n * 2)
    nonce = nonce or secrets.token_bytes(16)
    ephemeral_seed, ct = ML_KEM_768.encaps(ek)
    k = key_from_seed(ephemeral_seed, vp)
    blocks = [bytes_to_block(message_bytes[i:i + vp.n * 2], vp.n) for i in range(0, len(message_bytes), vp.n * 2)]
    for b in blocks:
        assert b.shape == (vp.n,)
    enc_blocks = [permute_forward(b, k) for b in blocks]
    metadata = {
        "n": vp.n,
        "rounds": vp.rounds,
        "layers_per_round": vp.layers_per_round,
        "shuffle_stride": vp.shuffle_stride,
        "use_lwe": vp.use_lwe,
        "bytes_per_number": vp.n * 2
    }
    timestamp = time.time()
    msg_for_hmac = ct + b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, 'big')
    hmac_value = hmac.new(ephemeral_seed, msg_for_hmac, hashlib.sha256).hexdigest()
    out_file = out_file + "." + file_type
    write_ciphertext(out_file, file_type, enc_blocks, metadata, ct, hmac_value, nonce, timestamp)
    return out_file

def decrypt_with_priv(keystore: Optional[str], privfile: Optional[str], encfile: str, passphrase: Optional[str], key_name: Optional[str], file_type: str, validity_window: int):
    if keystore and passphrase and key_name:
        privkey = retrieve_key_from_keystore(passphrase, key_name, keystore)
    else:
        with open(privfile, "r") as f:
            privkey = json.load(f)
    dk = bytes(privkey["dk"])
    metadata, enc_seed_bytes, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(encfile, file_type)
    assert isinstance(enc_seed_bytes, bytes), "Encrypted seed must be bytes"
    if nonce is not None:
        assert isinstance(nonce, bytes), "Nonce must be bytes"
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError(f"{bcolors.FAIL}Timestamp outside validity window{bcolors.ENDC}")
    ephemeral_seed = ML_KEM_768.decaps(dk, enc_seed_bytes)
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
    dec_bytes = unpad_iso7816(dec_bytes)
    
    print("Decrypted message:", dec_bytes.decode('utf-8'))    

def encrypt_with_public_veinn(seed_input: str, file_type: str, message: Optional[str] = None, in_path: Optional[str] = None, vp: VeinnParams = VeinnParams(), out_file: str = "enc_pub_veinn.json", mode: str = "t", bytes_per_number: Optional[int] = None, nonce: Optional[bytes] = None) -> str:
    seed = seed_input.encode('utf-8')
    k = key_from_seed(seed, vp)
    if in_path:
        with open(in_path, "rb") as f:
            message_bytes = f.read()
    else:
        if not message:
            raise ValueError(f"{bcolors.FAIL}Message required for text mode{bcolors.ENDC}")
        message_bytes = message.encode('utf-8')
            
    message_bytes = pad_iso7816(message_bytes, vp.n * 2)
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
        "use_lwe": vp.use_lwe        
    }
    timestamp = time.time()
    msg_for_hmac = b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, 'big')
    hmac_value = hmac.new(seed, msg_for_hmac, hashlib.sha256).hexdigest()
    out_file = out_file + "." + file_type
    write_ciphertext(out_file, file_type, enc_blocks, metadata, b"", hmac_value, nonce, timestamp)
    print(f"Encrypted to {out_file}")
    return out_file

def decrypt_with_public_veinn(seed_input: str, file_type: str, enc_file: str, validity_window: int):
    seed = seed_input.encode('utf-8')
    metadata, _, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file, file_type)
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
    dec_bytes = unpad_iso7816(dec_bytes)
    
    print("Decrypted message:", dec_bytes.decode('utf-8'))    

# -----------------------------
# Serialization Helpers
# -----------------------------
def write_ciphertext(path: str, file_type: str, encrypted_blocks: list, metadata: dict, enc_seed_bytes: bytes, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    key = {
        "veinn_metadata": metadata,
        "enc_seed_b64": b64encode(enc_seed_bytes).decode(),  # Kyber ciphertext as base64 
    }
    if hmac_value:
        key["hmac"] = hmac_value
    if nonce:
        key["nonce_b64"] = b64encode(nonce).decode()  # Nonce as base64
    if timestamp:
        key["timestamp"] = timestamp
    with open("key_"+path, "w") as f:
        json.dump(key, f)

    if file_type == "json":                
        payload = {
            "encrypted": [[int(x) for x in blk.tolist()] for blk in encrypted_blocks],                   
        }
        with open(path, "w") as f:
            json.dump(payload, f)
    elif file_type == "bin":
        with open(path, "wb") as f:
            # Magic number
            f.write(b"VEINN")
            
            # Number of blocks
            f.write(len(encrypted_blocks).to_bytes(4, 'big'))
            
            # Encrypted blocks (each block is n int64 values)
            for blk in encrypted_blocks:
                assert blk.dtype == np.int64, "Blocks must be int64 arrays"
                f.write(blk.tobytes())

def read_ciphertext(path: str, file_type: str):
    with open("key_"+path, "r") as f:
        key = json.load(f)
        hmac_value = key.get("hmac")
        nonce = b64decode(key.get("nonce_b64", "")) if key.get("nonce_b64") else None  # Decode nonce
        timestamp = key.get("timestamp")
        enc_seed = b64decode(key["enc_seed_b64"])  # Decode Kyber ciphertext
        metadata = key["veinn_metadata"]

    if file_type == "json":
        with open(path, "r") as f:
            encrypted = json.load(f)
        enc_blocks = [np.array([int(x) for x in blk], dtype=np.int64) for blk in encrypted["encrypted"]]

    elif file_type == "bin":
        
        with open(path, "rb") as f:
            # Check magic number
            magic = f.read(5)
            if magic != b"VEINN":
                raise ValueError(f"{bcolors.FAIL}Invalid file format: not a VEINN8 binary file{bcolors.ENDC}")
            
            # Read number of blocks
            num_blocks = int.from_bytes(f.read(4), 'big')
            
            # Read blocks
            n = metadata["n"]
            enc_blocks = []
            for _ in range(num_blocks):
                block_data = f.read(n * 8)  # Each int64 is 8 bytes
                if len(block_data) != n * 8:
                    raise ValueError(f"{bcolors.FAIL}Incomplete block data{bcolors.ENDC}")
                block = np.frombuffer(block_data, dtype=np.int64)
                assert block.shape == (n,), f"Block shape mismatch: expected {(n,)}, got {block.shape}"
                enc_blocks.append(block)
            
    return metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp

# -----------------------------
# CLI Main with Interactive Menu
# -----------------------------
def menu_generate_keystore():
    passphrase = input("Enter keystore passphrase: ")
    keystore_file = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
    create_keystore(passphrase, keystore_file)

def menu_generate_kyber_keypair():
    pubfile = input("Public key filename (default kyber_pub.json): ").strip() or "kyber_pub.json"
    use_keystore = input("Store private key in keystore? (y/n): ").strip().lower() or "y"
    privfile, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Key name in keystore: ")
    else:
        privfile = input("Private key filename (default kyber_priv.json): ").strip() or "kyber_priv.json"
    keypair = generate_kyber_keypair()
    with open(pubfile, "w") as f:
        json.dump({"ek": keypair["ek"]}, f)
    if use_keystore == "y":
        store_key_in_keystore(passphrase, key_name, keypair, keystore)
        print(f"Kyber keys generated: {pubfile} (public), private stored in keystore")
    else:
        with open(privfile, "w") as f:
            json.dump(keypair, f)
        print(f"Kyber keys generated: {pubfile} (public), {privfile} (private)")

def menu_encrypt_with_pub():
    pubfile = input("Recipient Kyber public key file (default kyber_pub.json): ").strip() or "kyber_pub.json"
    
    if not os.path.exists(pubfile):
        print("Public key not found. Generate Kyber keys first.")
        return
    inpath = input("Optional input file path (blank = prompt): ").strip() or None    
    file_type = input("Output file type (JSON/BIN) [json] : ").strip() or "json"
    n = int(input(f"Number of {np.int64} words per block (default {VeinnParams.n}): ").strip() or VeinnParams.n)
    rounds = int(input(f"Number of rounds (default {VeinnParams.rounds}): ").strip() or VeinnParams.rounds)
    layers_per_round = int(input(f"Layers per round (default {VeinnParams.layers_per_round}): ").strip() or VeinnParams.layers_per_round)
    shuffle_stride = int(input(f"Shuffle stride (default {VeinnParams.shuffle_stride}): ").strip() or VeinnParams.shuffle_stride)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    seed_len = int(input(f"Seed length (default {VeinnParams.seed_len}): ").strip() or VeinnParams.seed_len)
    nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
    nonce = b64decode(nonce_str) if nonce_str else None
    q = int(input(f"Modulus q (default {VeinnParams.q}): ").strip() or VeinnParams.q)
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe, q=q)
    message = None    
    if inpath is None:        
        message = input("Message to encrypt: ")        
    encrypt_with_pub(pubfile, file_type, message=message, in_path=inpath, vp=vp, seed_len=seed_len, nonce=nonce)

def menu_decrypt_with_priv():
    use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() or "y"
    privfile, keystore, passphrase, key_name = None, None, None, None
    if use_keystore == "y":
        keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
        passphrase = input("Keystore passphrase: ")
        key_name = input("Key name in keystore: ")
    else:
        privfile = input("Kyber private key file (default kyber_priv.json): ").strip() or "kyber_priv.json"
    encfile = input("Encrypted file to decrypt (default enc_pub): ").strip() or "enc_pub"
    file_type = input("Output file type (JSON/BIN) [json] : ").strip() or "json"
    encfile = encfile + "." + file_type
    validity_window = int(input(f"Timestamp validity window in seconds (default {VeinnParams.valid}): ").strip() or VeinnParams.valid)
    if not os.path.exists(encfile):
        print("Encrypted file not found.")
        return
    decrypt_with_priv(keystore, privfile, encfile, passphrase, key_name, file_type, validity_window)

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
    n = int(input(f"Number of {np.int64} words per block (default {VeinnParams.n}): ").strip() or VeinnParams.n)
    rounds = int(input(f"Number of rounds (default {VeinnParams.rounds}): ").strip() or VeinnParams.rounds)
    layers_per_round = int(input(f"Layers per round (default {VeinnParams.layers_per_round}): ").strip() or VeinnParams.layers_per_round)
    shuffle_stride = int(input(f"Shuffle stride (default {VeinnParams.shuffle_stride}): ").strip() or VeinnParams.shuffle_stride)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    q = int(input(f"Modulus q (default {VeinnParams.q}): ").strip() or VeinnParams.q)
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe, q=q)
    veinn_from_seed(seed_input, vp)

def menu_encrypt_with_public_veinn():
    message = None    
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
    inpath = input("Optional input file path (blank = prompt): ").strip() or None 
    if inpath == None:
        message = input("Message to encrypt: ")    

    n = int(input(f"Number of {np.int64} words per block (default {VeinnParams.n}): ").strip() or VeinnParams.n)
    rounds = int(input(f"Number of rounds (default {VeinnParams.rounds}): ").strip() or VeinnParams.rounds)
    layers_per_round = int(input(f"Layers per round (default {VeinnParams.layers_per_round}): ").strip() or VeinnParams.layers_per_round)
    shuffle_stride = int(input(f"Shuffle stride (default {VeinnParams.shuffle_stride}): ").strip() or VeinnParams.shuffle_stride)
    use_lwe = input("Use LWE PRF for key nonlinearity (y/n) [y]: ").strip().lower() or "y"
    use_lwe = use_lwe == "y"
    q = int(input(f"Modulus q (default {VeinnParams.q}): ").strip() or VeinnParams.q)
    out_file = input("Output encrypted filename (default enc_pub_veinn): ").strip() or "enc_pub_veinn"      
    file_type = input("Output file type (JSON/BIN) [json] : ").strip() or "json"
    nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
    nonce = b64decode(nonce_str) if nonce_str else None
    vp = VeinnParams(n=n, rounds=rounds, layers_per_round=layers_per_round, shuffle_stride=shuffle_stride, use_lwe=use_lwe, q=q)
    encrypt_with_public_veinn(seed_input, file_type, message, inpath, vp, out_file, nonce)

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
    enc_file = input("Encrypted file to decrypt (default enc_pub_veinn): ").strip() or "enc_pub_veinn"
    file_type = input("Output file type (JSON/BIN) [json] : ").strip() or "json"
    validity_window = int(input(f"Timestamp validity window in seconds (default {VeinnParams.valid}): ").strip() or VeinnParams.valid)
    enc_file = enc_file + "." + file_type
    if not os.path.exists(enc_file):
        print("Encrypted file not found.")
        return
    decrypt_with_public_veinn(seed_input, file_type, enc_file, validity_window)

def veinn_from_seed(seed_input: str, vp: VeinnParams):
    seed = seed_input.encode('utf-8')
    k = key_from_seed(seed, vp)
    print(f"Derived VEINN key with params: n={vp.n}, rounds={vp.rounds}, layers_per_round={vp.layers_per_round}, shuffle_stride={vp.shuffle_stride}, use_lwe={vp.use_lwe}, q={vp.q}")

def validate_timestamp(timestamp: float, validity_window: int) -> bool:
    current_time = time.time()
    return abs(current_time - timestamp) <= validity_window

def main():
    parser = argparse.ArgumentParser(description="VEINN - Vector Encrypted Invertible Neural Network")
    subparsers = parser.add_subparsers(dest="command")

    create_keystore_parser = subparsers.add_parser("create_keystore", help="Create encrypted keystore")
    create_keystore_parser.add_argument("--passphrase", required=True, help="Keystore passphrase")
    create_keystore_parser.add_argument("--keystore_file", default="keystore.json", help="Keystore filename")

    generate_kyber_parser = subparsers.add_parser("generate_kyber", help="Generate Kyber keypair")
    generate_kyber_parser.add_argument("--pubfile", default="kyber_pub.json", help="Public key filename")
    generate_kyber_parser.add_argument("--privfile", default="kyber_priv.json", help="Private key filename")
    generate_kyber_parser.add_argument("--keystore", default="keystore.json", help="Keystore filename")
    generate_kyber_parser.add_argument("--passphrase", help="Keystore passphrase")
    generate_kyber_parser.add_argument("--key_name", help="Key name in keystore")

    public_encrypt_parser = subparsers.add_parser("public_encrypt", help="Encrypt with Kyber public key")
    public_encrypt_parser.add_argument("--pubfile", default="kyber_pub.json", help="Kyber public key file")
    public_encrypt_parser.add_argument("--in_path", help="Input file path")
    public_encrypt_parser.add_argument("--mode", choices=["t", "n"], default="t", help="Input mode")
    public_encrypt_parser.add_argument("--n", type=int, default=VeinnParams.n)
    public_encrypt_parser.add_argument("--rounds", type=int, default=VeinnParams.rounds)
    public_encrypt_parser.add_argument("--layers_per_round", type=int, default=VeinnParams.layers_per_round)
    public_encrypt_parser.add_argument("--shuffle_stride", type=int, default=VeinnParams.shuffle_stride)
    public_encrypt_parser.add_argument("--use_lwe", type=bool, default=True)
    public_encrypt_parser.add_argument("--q", type=int, default=VeinnParams.q)
    public_encrypt_parser.add_argument("--seed_len", type=int, default=32)
    public_encrypt_parser.add_argument("--nonce", help="Custom nonce (base64)")
    public_encrypt_parser.add_argument("--out_file", default="enc_pub.json")

    public_decrypt_parser = subparsers.add_parser("public_decrypt", help="Decrypt with Kyber private key")
    public_decrypt_parser.add_argument("--keystore", default="keystore.json")
    public_decrypt_parser.add_argument("--privfile", default="kyber_priv.json")
    public_decrypt_parser.add_argument("--encfile", default="enc_pub.json")
    public_decrypt_parser.add_argument("--passphrase")
    public_decrypt_parser.add_argument("--key_name")
    public_decrypt_parser.add_argument("--validity_window", type=int, default=3600)

    public_veinn_parser = subparsers.add_parser("public_veinn", help="Derive public VEINN from seed")
    public_veinn_parser.add_argument("--seed", required=True)
    public_veinn_parser.add_argument("--n", type=int, default=VeinnParams.n)
    public_veinn_parser.add_argument("--rounds", type=int, default=VeinnParams.rounds)
    public_veinn_parser.add_argument("--layers_per_round", type=int, default=VeinnParams.layers_per_round)
    public_veinn_parser.add_argument("--shuffle_stride", type=int, default=VeinnParams.shuffle_stride)
    public_veinn_parser.add_argument("--use_lwe", type=bool, default=True)
    public_veinn_parser.add_argument("--q", type=int, default=VeinnParams.q)

    args = parser.parse_known_args()[0]

    try:
        match args.command:
            case "create_keystore":
                create_keystore(args.passphrase, args.keystore_file)
                print(f"Keystore created: {args.keystore_file}")
            case "generate_kyber":
                keypair = generate_kyber_keypair()
                with open(args.pubfile, "w") as f:
                    json.dump({"ek": keypair["ek"]}, f)
                if args.keystore and args.passphrase and args.key_name:
                    store_key_in_keystore(args.passphrase, args.key_name, keypair, args.keystore)
                    print(f"Kyber keys generated: {args.pubfile} (public), private stored in keystore")
                else:
                    with open(args.privfile, "w") as f:
                        json.dump(keypair, f)
                    print(f"Kyber keys generated: {args.pubfile} (public), {args.privfile} (private)")
            case "public_encrypt":
                vp = VeinnParams(
                    n=args.n,
                    rounds=args.rounds,
                    layers_per_round=args.layers_per_round,
                    shuffle_stride=args.shuffle_stride,
                    use_lwe=args.use_lwe,
                    q=args.q
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
                    use_lwe=args.use_lwe,
                    q=args.q
                )
                veinn_from_seed(args.seed, vp)
            case _:
                _=os.system("cls") | os.system("clear")
                while True:
                    print(f"{bcolors.WARNING}{bcolors.BOLD}VEINN - Vector Encrypted Invertible Neural Network{bcolors.ENDC}")
                    print(f"{bcolors.GREY}{bcolors.BOLD}(]≡≡≡≡ø‡»{bcolors.OKCYAN}========================================-{bcolors.ENDC}")
                    print("")
                    print(f"{bcolors.BOLD}1){bcolors.ENDC} Create encrypted keystore")
                    print(f"{bcolors.BOLD}2){bcolors.ENDC} Generate Kyber keypair (public/private)")
                    print(f"{bcolors.BOLD}3){bcolors.ENDC} Encrypt with recipient public key (Kyber + VEINN)")
                    print(f"{bcolors.BOLD}4){bcolors.ENDC} Decrypt with private key")
                    print(f"{bcolors.BOLD}5){bcolors.ENDC} Encrypt deterministically using public VEINN")
                    print(f"{bcolors.BOLD}6){bcolors.ENDC} Decrypt deterministically using public VEINN")
                    print(f"{bcolors.GREY}7) Derive public VEINN from seed{bcolors.ENDC}")
                    print(f"{bcolors.BOLD}0){bcolors.ENDC} Exit")
                    choice = input(f"{bcolors.BOLD}Choice: {bcolors.ENDC}").strip()
                    try:
                        match choice:
                            case "0":
                                break
                            case "1":
                                menu_generate_keystore()
                            case "2":
                                menu_generate_kyber_keypair()
                            case "3":
                                menu_encrypt_with_pub()
                            case "4":
                                menu_decrypt_with_priv()
                            case "5":
                                menu_encrypt_with_public_veinn()
                            case "6":
                                menu_decrypt_with_public_veinn()
                            case "7":
                                menu_veinn_from_seed()
                            case _:
                                print("Invalid choice")
                    except Exception as e:
                        print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC}", e)
                    _=input(f"{bcolors.OKGREEN}Enter to continue...{bcolors.ENDC}")
                    _=os.system("cls") | os.system("clear")
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC}", e)
        sys.exit(1)

if __name__ == "__main__":
    main()