#!/usr/bin/env python3
"""
VEINN CLI with seed-based hybrid public-key encryption (ephemeral INN seed)
- Generate RSA keys
- Encrypt with recipient public key (sender): encrypts small seed -> derive INN -> encrypt message
- Decrypt with private key (recipient): recover seed -> derive INN -> decrypt ciphertext
- Homomorphic ops on ciphertext JSON files (add, sub, scalar mul, avg, dot)
Updated with OAEP padding for RSA, better metadata handling, and improved error handling.
"""
import os
import sys
import json
import math
import hashlib
import secrets
import numpy as np
from typing import Callable

# -----------------------------
# OAEP Padding Functions (Pure Python, using SHA-256)
# -----------------------------
def bytewise_xor(data: bytes, mask: bytes) -> bytes:
    masked = bytearray()
    for i in range(max(len(data), len(mask))):
        if i < len(data) and i < len(mask):
            masked.append(data[i] ^ mask[i])
        elif i < len(data):
            masked.append(data[i])
        else:
            break
    return bytes(masked)

def sha256(m: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(m)
    return hasher.digest()

def mgf1(seed: bytes, mlen: int, f_hash: Callable = sha256) -> bytes:
    t = bytearray()
    hlen = len(f_hash(b''))
    for c in range(0, math.ceil(mlen / hlen)):
        _c = c.to_bytes(4, byteorder="big")
        t.extend(f_hash(seed + _c))
    return bytes(t[:mlen])

def oaep_encode(message: bytes, k: int, label: bytes = b"", hash_func: Callable = sha256, mgf: Callable = mgf1) -> bytes:
    hlen = len(hash_func(b''))
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("Message too long for OAEP encoding")
    lhash = hash_func(label)
    padding_string = (k - len(message) - 2 * hlen - 2) * b"\x00"
    data_block = lhash + padding_string + b"\x01" + message
    seed = os.urandom(hlen)
    data_block_mask = mgf(seed, k - hlen - 1, hash_func)
    masked_data_block = bytewise_xor(data_block, data_block_mask)
    seed_mask = mgf(masked_data_block, hlen, hash_func)
    masked_seed = bytewise_xor(seed, seed_mask)
    return b"\x00" + masked_seed + masked_data_block

def oaep_decode(encoded_message: bytes, k: int, label: bytes = b"", hash_func: Callable = sha256, mgf: Callable = mgf1) -> bytes:
    if len(encoded_message) != k:
        raise ValueError("Invalid encoded message length")
    hlen = len(hash_func(b''))
    if k < 2 * hlen + 2:
        raise ValueError("Key too small for OAEP")
    lhash = hash_func(label)
    masked_seed = encoded_message[1:1 + hlen]
    masked_data_block = encoded_message[1 + hlen:]
    seed_mask = mgf(masked_data_block, hlen, hash_func)
    seed = bytewise_xor(masked_seed, seed_mask)
    data_block_mask = mgf(seed, k - hlen - 1, hash_func)
    data_block = bytewise_xor(masked_data_block, data_block_mask)
    lhash_prime = data_block[:hlen]
    if lhash != lhash_prime:
        raise ValueError("OAEP decoding error: label hash mismatch")
    i = hlen
    while i < len(data_block):
        if data_block[i] == 0:
            i += 1
            continue
        elif data_block[i] == 1:
            i += 1
            break
        else:
            raise ValueError("OAEP decoding error: invalid padding")
    return data_block[i:]

# -----------------------------
# Small RSA utilities (Miller-Rabin / modinv)
# -----------------------------
def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
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

def gen_prime(bits):
    if bits < 16:
        raise ValueError("bits too small")
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

def generate_rsa_keypair(bits=2048):
    e = 65537
    half = bits // 2
    p = gen_prime(half)
    q = gen_prime(bits - half)
    while q == p:
        q = gen_prime(bits - half)
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return generate_rsa_keypair(bits)
    d = modinv(e, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}

def int_to_bytes_be(x: int, length: int) -> bytes:
    return int.to_bytes(x, length, byteorder="big", signed=False)

def bytes_be_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)

# -----------------------------
# Deterministic expansion: seed -> keystream (SHA256-CTR)
# -----------------------------
def expand_keystream(key_bytes: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        data = key_bytes + counter.to_bytes(8, "big")
        out.extend(hashlib.sha256(data).digest())
        counter += 1
    return bytes(out[:length])

# -----------------------------
# Utilities: text/vector/pad
# -----------------------------
def vectorize_text(msg: str) -> np.ndarray:
    return np.frombuffer(msg.encode("utf-8"), dtype=np.uint8)

def devectorize_text(vec: np.ndarray) -> str:
    return vec.tobytes().decode("utf-8", errors="ignore")

def pkcs7_pad(vec: np.ndarray, block_size: int) -> np.ndarray:
    pad_len = block_size - (len(vec) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return np.concatenate([vec, np.full(pad_len, pad_len, dtype=np.uint8)])

def pkcs7_unpad(vec: np.ndarray) -> np.ndarray:
    if len(vec) == 0:
        return vec
    pad_len = int(vec[-1])
    if 0 < pad_len <= len(vec) and all(vec[-pad_len:] == pad_len):
        return vec[:-pad_len]
    raise ValueError("Invalid PKCS7 padding")
    return vec

def split_blocks_flat(vec: np.ndarray, block_size: int):
    return [vec[i:i + block_size] for i in range(0, len(vec), block_size)]

# -----------------------------
# Integer coupling layer & INN (same as before)
# -----------------------------
class IntCouplingLayer:
    def __init__(self, block_size: int, modulus: int = 256, W: np.ndarray = None):
        assert block_size % 2 == 0, "block_size must be even"
        self.block_size = block_size
        self.modulus = modulus
        self.mid = block_size // 2
        if W is None:
            rng = np.random.default_rng()
            self.W = rng.integers(0, modulus, size=(self.mid, self.mid), dtype=np.int64)
        else:
            self.W = np.array(W, dtype=np.int64).reshape((self.mid, self.mid))

    def forward(self, x_block: np.ndarray) -> np.ndarray:
        x1 = x_block[:self.mid].astype(np.int64)
        x2 = x_block[self.mid:].astype(np.int64)
        y2 = (x2 + (self.W @ x1) % self.modulus) % self.modulus
        return np.concatenate([x1, y2]).astype(np.int64)

    def reverse(self, y_block: np.ndarray) -> np.ndarray:
        y1 = y_block[:self.mid].astype(np.int64)
        y2 = y_block[self.mid:].astype(np.int64)
        x2 = (y2 - (self.W @ y1) % self.modulus) % self.modulus
        return np.concatenate([y1, x2]).astype(np.int64)

class IntINN:
    def __init__(self, block_size: int, n_layers: int = 3, modulus: int = 256, layers_weights: list = None):
        self.block_size = block_size
        self.n_layers = n_layers
        self.modulus = modulus
        self.mid = block_size // 2
        self.layers = []
        for i in range(n_layers):
            W = None
            if layers_weights is not None:
                flat = layers_weights[i]
                if len(flat) != self.mid * self.mid:
                    raise ValueError("Invalid layer weight length")
                W = np.array(flat, dtype=np.int64).reshape((self.mid, self.mid))
            self.layers.append(IntCouplingLayer(block_size, modulus, W=W))

    def forward(self, block: np.ndarray) -> np.ndarray:
        b = block.astype(np.int64)
        for layer in self.layers:
            b = layer.forward(b)
        return b.astype(np.int64)

    def reverse(self, block: np.ndarray) -> np.ndarray:
        b = block.astype(np.int64)
        for layer in reversed(self.layers):
            b = layer.reverse(b)
        return b.astype(np.int64)

# -----------------------------
# Public INN derivation from known seed
# -----------------------------
def public_inn_from_seed(seed_str: str, block_size: int = 16, n_layers: int = 3, modulus: int = 256):
    """
    Deterministically generate a public INN from a seed string.
    Anyone with the seed can derive this INN and use it to encrypt messages.
    """
    seed_bytes = seed_str.encode("utf-8")  # simple UTF-8 encoding of seed
    inn, layers_flat = derive_inn_from_seed(seed_bytes, block_size, n_layers, modulus)
    print(f"Derived INN from seed '{seed_str}':")
    print(f"- block_size: {block_size}, n_layers: {n_layers}, modulus: {modulus}")
    print(f"- layers_flat (first layer sample 10 values): {layers_flat[0][:10]}")
    return inn, layers_flat

# -----------------------------
# Deterministic INN weight derivation from seed
# -----------------------------
def derive_inn_from_seed(seed: bytes, block_size: int, n_layers: int, modulus: int = 256):
    """
    Deterministically expand 'seed' into INN layers weights (list of flattened ints).
    We derive bytes via SHA256-CTR and map each byte to 0..modulus-1.
    """
    mid = block_size // 2
    per_layer = mid * mid
    total_bytes = per_layer * n_layers
    ks = expand_keystream(seed, total_bytes)
    layers_flat = []
    # map each byte to int in 0..modulus-1
    for i in range(n_layers):
        start = i * per_layer
        chunk = ks[start:start + per_layer]
        arr = np.frombuffer(chunk, dtype=np.uint8).astype(np.int64) % modulus
        layers_flat.append(arr.tolist())
    inn = IntINN(block_size, n_layers=n_layers, modulus=modulus, layers_weights=layers_flat)
    return inn, layers_flat

# -----------------------------
# Serialization helpers for ciphertexts (JSON-safe)
# -----------------------------
def write_ciphertext_json(path: str, encrypted_blocks: list, metadata: dict, enc_seed_bytes: bytes):
    payload = {
        "inn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed_bytes],  # RSA-encrypted seed bytes as ints
        "encrypted": [[int(x) for x in blk.tolist()] for blk in encrypted_blocks]
    }
    with open(path, "w") as f:
        json.dump(payload, f)

def read_ciphertext_json(path: str):
    with open(path, "r") as f:
        payload = json.load(f)
    enc_seed = bytes([int(b) for b in payload["enc_seed"]])
    metadata = payload["inn_metadata"]
    enc_blocks = [np.array([int(x) for x in blk], dtype=np.int64) for blk in payload["encrypted"]]
    return metadata, enc_seed, enc_blocks

# -----------------------------
# Deterministic encryption using public INN derived from seed
# -----------------------------
def encrypt_with_public_inn(seed_str: str, message: str = None, block_size: int = 16, n_layers: int = 3, modulus: int = 256, out_file: str = None):
    """
    Encrypt a message deterministically using a public INN derived from a known seed.
    """
    # Derive INN from seed
    inn, layers_flat = public_inn_from_seed(seed_str, block_size, n_layers, modulus)

    # Input message
    if message is None:
        message = input("Message to encrypt: ")

    # Vectorize, pad, split into blocks
    data = vectorize_text(message)
    padded = pkcs7_pad(data, block_size)
    blocks = split_blocks_flat(padded, block_size)

    # Encrypt blocks
    enc_blocks = []
    for blk in blocks:
        enc = inn.forward(blk.astype(np.int64))
        enc_blocks.append(enc.astype(np.int64))

    # Prepare metadata (no RSA seed needed)
    metadata = {
        "block_size": block_size,
        "n_layers": n_layers,
        "modulus": modulus,
        "mode": "text",
        "seed_str": seed_str  # store seed used for public deterministic encryption
    }

    # Output file
    if out_file is None:
        out_file = input("Output encrypted filename (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"

    # Write JSON (no RSA seed)
    payload = {
        "inn_metadata": metadata,
        "enc_seed": [],  # empty because no RSA seed
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks]
    }

    with open(out_file, "w") as f:
        json.dump(payload, f)

    print(f"Message encrypted deterministically with public INN -> {out_file}")
    return out_file

# -----------------------------
# Homomorphic helpers (operate on ciphertext JSON files)
# -----------------------------
def _load_encrypted_file(enc_file: str):
    with open(enc_file, "r") as f:
        payload = json.load(f)
    enc_blocks = [np.array([int(x) for x in blk], dtype=np.int64) for blk in payload["encrypted"]]
    meta = payload["inn_metadata"]
    # ensure types
    meta_parsed = {
        "block_size": int(meta["block_size"]),
        "n_layers": int(meta["n_layers"]),
        "modulus": int(meta["modulus"]),
        "seed_len": int(meta.get("seed_len", 32)),
        "mode": meta.get("mode", "raw"),
        "bytes_per_number": int(meta.get("bytes_per_number", meta["block_size"]))
    }
    return enc_blocks, meta_parsed, payload

def _write_encrypted_payload(out_file: str, enc_blocks, meta, extra_fields=None):
    out = {
        "inn_metadata": {
            "block_size": int(meta["block_size"]),
            "n_layers": int(meta["n_layers"]),
            "modulus": int(meta["modulus"]),
            "seed_len": int(meta.get("seed_len", 32)),
            "mode": meta.get("mode", "raw"),
            "bytes_per_number": int(meta.get("bytes_per_number", meta["block_size"]))
        },
        "enc_seed": [],  # placeholder: homomorphic outputs don't include seed
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks]
    }
    if extra_fields:
        out.update(extra_fields)
    with open(out_file, "w") as f:
        json.dump(out, f)

def homomorphic_add_files(f1: str, f2: str, out_file: str):
    enc1, meta1, _ = _load_encrypted_file(f1)
    enc2, meta2, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch (block_size/n_layers/modulus). They must match.")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    modulus = meta1["modulus"]
    summed = [((a + b) % modulus).astype(np.int64) for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, summed, meta1)
    print(f"Homomorphic sum saved to {out_file}")

def homomorphic_sub_files(f1: str, f2: str, out_file: str):
    enc1, meta1, _ = _load_encrypted_file(f1)
    enc2, meta2, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    modulus = meta1["modulus"]
    diff = [((a - b) % modulus).astype(np.int64) for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, diff, meta1)
    print(f"Homomorphic difference saved to {out_file}")

def homomorphic_scalar_mul_file(f: str, scalar: int, out_file: str):
    enc, meta, _ = _load_encrypted_file(f)
    modulus = meta["modulus"]
    prod = [((blk * int(scalar)) % modulus).astype(np.int64) for blk in enc]
    _write_encrypted_payload(out_file, prod, meta)
    print(f"Homomorphic scalar multiplication saved to {out_file}")

def homomorphic_average_files(files: list, out_file: str):
    encs = []
    metas = []
    for f in files:
        enc_blocks, meta, _ = _load_encrypted_file(f)
        encs.append(enc_blocks)
        metas.append(meta)
    if not all(m == metas[0] for m in metas):
        raise ValueError("All encrypted files must have identical metadata")
    meta = metas[0]
    n = len(encs)
    length = len(encs[0])
    modulus = meta["modulus"]
    avg_blocks = []
    for i in range(length):
        s = np.zeros_like(encs[0][i], dtype=np.int64)
        for enc in encs:
            s = (s + enc[i].astype(np.int64)) % (modulus * n)
        avg = ((s // n) % modulus).astype(np.int64)
        avg_blocks.append(avg)
    _write_encrypted_payload(out_file, avg_blocks, meta)
    print(f"Homomorphic average saved to {out_file}")

def homomorphic_dot_files(f1: str, f2: str, out_file: str):
    enc1, meta1, _ = _load_encrypted_file(f1)
    enc2, meta2, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    modulus = meta1["modulus"]
    flat1 = np.concatenate(enc1).astype(np.int64)
    flat2 = np.concatenate(enc2).astype(np.int64)
    if flat1.shape != flat2.shape:
        raise ValueError("Encrypted files flatten to different lengths")
    dot = int(np.dot(flat1 % modulus, flat2 % modulus) % modulus)
    result = {"dot_product": dot}
    with open(out_file, "w") as f:
        json.dump(result, f)
    print(f"Homomorphic dot product saved to {out_file}")

# -----------------------------
# Public-key hybrid encrypt / decrypt (seed-based with OAEP)
# -----------------------------
def generate_rsa_cli():
    bits = int(input("RSA key size in bits (default 2048): ").strip() or 2048)
    print("Generating RSA keypair (may take time)...")
    kp = generate_rsa_keypair(bits=bits)
    pubfile = input("Public key filename (default rsa_pub.json): ").strip() or "rsa_pub.json"
    privfile = input("Private key filename (default rsa_priv.json): ").strip() or "rsa_priv.json"
    pub = {"n": kp["n"], "e": kp["e"]}
    priv = {"n": kp["n"], "d": kp["d"]}
    with open(pubfile, "w") as f:
        json.dump(pub, f)
    with open(privfile, "w") as f:
        json.dump(priv, f)
    print(f"RSA public key -> {pubfile}")
    print(f"RSA private key -> {privfile} (KEEP SECRET)")
    return pubfile, privfile

def encrypt_with_pub(pubfile: str, in_path: str = None):
    if not os.path.exists(pubfile):
        raise FileNotFoundError("RSA public key file not found")
    with open(pubfile, "r") as f:
        pub = json.load(f)
    n = int(pub["n"])
    e = int(pub["e"])
    k = (n.bit_length() + 7) // 8

    # input message
    mode_choice = input("Encrypt mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "t"
    block_size = int(input("INN block_size to use (even, default 16): ").strip() or 16)
    if block_size % 2 != 0:
        raise ValueError("block_size must be even")
    n_layers = int(input("INN n_layers (default 3): ").strip() or 3)
    modulus = int(input("modulus (default 256): ").strip() or 256)
    seed_len = int(input("ephemeral seed length in bytes (default 32): ").strip() or 32)

    if mode_choice == "t":
        if in_path:
            with open(in_path, "r", encoding="utf-8") as f:
                text = f.read()
        else:
            text = input("Message to encrypt: ")
        data = vectorize_text(text)
        padded = pkcs7_pad(data, block_size)
        blocks = split_blocks_flat(padded, block_size)
        bytes_per_number = None
    else:
        bytes_per_number = int(input("Bytes per number (default 1): ").strip() or 1)
        if in_path:
            with open(in_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
        else:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
        raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
        nums = [int(x) for x in raw_nums]
        # pack each number to block_size (big-endian)
        blocks = []
        for v in nums:
            b = int_to_bytes_be(v, bytes_per_number)
            if len(b) > block_size:
                raise ValueError("Number too large for block_size")
            if len(b) < block_size:
                b = (b"\x00" * (block_size - len(b))) + b
            blocks.append(np.frombuffer(b, dtype=np.uint8))

    # generate ephemeral seed
    seed = secrets.token_bytes(seed_len)

    # derive INN from seed
    inn, layers_flat = derive_inn_from_seed(seed, block_size, n_layers, modulus)

    # encrypt blocks
    enc_blocks = []
    for blk in blocks:
        enc = inn.forward(blk.astype(np.int64))
        enc_blocks.append(enc.astype(np.int64))

    # RSA-encrypt seed with OAEP
    padded_seed = oaep_encode(seed, k, hash_func=sha256)
    enc_seed_int = pow(bytes_be_to_int(padded_seed), e, n)
    enc_seed_bytes = int_to_bytes_be(enc_seed_int, k)

    # write JSON
    metadata = {
        "block_size": block_size,
        "n_layers": n_layers,
        "modulus": modulus,
        "seed_len": seed_len,
        "mode": "text" if mode_choice == "t" else "numeric"
    }
    if mode_choice == "n":
        metadata["bytes_per_number"] = bytes_per_number
    out_file = input("Output encrypted filename (default enc_pub.json): ").strip() or "enc_pub.json"
    write_ciphertext_json(out_file, enc_blocks, metadata, enc_seed_bytes)
    print(f"Encrypted message (with RSA-encrypted seed) saved to {out_file}")
    return out_file

def decrypt_with_priv(keysfile: str, privfile: str, enc_file: str):
    if not os.path.exists(privfile):
        raise FileNotFoundError("RSA private key file not found")
    with open(privfile, "r") as f:
        priv = json.load(f)
    d = int(priv["d"])
    n = int(priv["n"])
    k = (n.bit_length() + 7) // 8

    metadata, enc_seed_bytes, enc_blocks = read_ciphertext_json(enc_file)
    # RSA-decrypt enc_seed with OAEP
    enc_seed_int = bytes_be_to_int(enc_seed_bytes)
    dec_padded_int = pow(enc_seed_int, d, n)
    dec_padded = int_to_bytes_be(dec_padded_int, k)
    seed_bytes = oaep_decode(dec_padded, k, hash_func=sha256)

    # derive INN from seed
    block_size = int(metadata["block_size"])
    n_layers = int(metadata["n_layers"])
    modulus = int(metadata["modulus"])
    inn, layers_flat = derive_inn_from_seed(seed_bytes, block_size, n_layers, modulus)

    # decrypt
    decrypted_blocks = []
    for blk in enc_blocks:
        dec = inn.reverse(blk.astype(np.int64)).astype(np.uint8)
        decrypted_blocks.append(dec)
    flat = np.concatenate(decrypted_blocks).astype(np.uint8)
    mode = metadata.get("mode", "text")
    if mode == "text":
        unpadded = pkcs7_unpad(flat)
        text = devectorize_text(unpadded)
        print("Decrypted (text):")
        print(text)
    else:  # numeric
        bytes_per_number = int(metadata.get("bytes_per_number", block_size))
        nums = []
        for dec_blk in decrypted_blocks:
            b = dec_blk.tobytes()[-bytes_per_number:]
            v = bytes_be_to_int(b)
            nums.append(v)
        print("Decrypted (numeric list):")
        print(nums)

def decrypt_with_public_inn(seed_str: str, enc_file: str):
    """
    Decrypt a message encrypted with a public INN using the shared seed string.
    """
    # Read encrypted file
    metadata, enc_seed, enc_blocks = read_ciphertext_json(enc_file)
    if enc_seed:
        raise ValueError("File was not encrypted with public INN (contains RSA seed)")
    if metadata.get("mode") != "text":
        raise ValueError("Public INN decryption supports text mode only")
    
    # Derive INN from seed
    seed_bytes = seed_str.encode("utf-8")
    block_size = int(metadata["block_size"])
    n_layers = int(metadata["n_layers"])
    modulus = int(metadata["modulus"])
    inn, layers_flat = derive_inn_from_seed(seed_bytes, block_size, n_layers, modulus)
    
    # Decrypt blocks
    decrypted_blocks = []
    for blk in enc_blocks:
        dec = inn.reverse(blk.astype(np.int64)).astype(np.uint8)
        decrypted_blocks.append(dec)
    flat = np.concatenate(decrypted_blocks).astype(np.uint8)
    
    # Unpad and decode
    unpadded = pkcs7_unpad(flat)
    text = devectorize_text(unpadded)
    print("Decrypted (text):")
    print(text)
    return text
# -----------------------------
# CLI main
# -----------------------------
def main():
    print("VEINN CLI — seed-based public-key hybrid (ephemeral INN seed) + homomorphic ops")
    while True:
        print("")
        print("1) Generate RSA keypair (public/private)")
        print("2) Encrypt with recipient public key (seed-based ephemeral INN)")
        print("3) Decrypt with private key")
        print("4) Homomorphic add (file1, file2 -> out)")
        print("5) Homomorphic subtract (file1, file2 -> out)")
        print("6) Homomorphic scalar multiply (file, scalar -> out)")
        print("7) Homomorphic average (file1,file2,... -> out)")
        print("8) Homomorphic dot product (file1, file2 -> out)")
        print("9) Derive public INN from seed (deterministic encryption without private key)")
        print("10) Encrypt deterministically using public INN (seed-based, no private key)")
        print("11) Decrypt deterministically using public INN (seed-based, no private key)")
        print("0) Exit")
        choice = input("Choice: ").strip()

        try:
            if choice == "0":
                break
            elif choice == "1":
                generate_rsa_cli()
            elif choice == "2":
                pubfile = input("Recipient RSA public key file (default rsa_pub.json): ").strip() or "rsa_pub.json"
                if not os.path.exists(pubfile):
                    print("Public key not found. Generate RSA keys first.")
                    continue
                inpath = input("Optional input file path (blank = prompt): ").strip() or None
                encrypt_with_pub(pubfile, in_path=inpath)
            elif choice == "3":
                privfile = input("Your RSA private key file (default rsa_priv.json): ").strip() or "rsa_priv.json"
                encfile = input("Encrypted file to decrypt (default enc_pub.json): ").strip() or "enc_pub.json"
                if not os.path.exists(privfile):
                    print("Private key not found.")
                    continue
                if not os.path.exists(encfile):
                    print("Encrypted file not found.")
                    continue
                decrypt_with_priv(None, privfile, encfile)
            elif choice == "4":
                f1 = input("Encrypted file 1: ").strip()
                f2 = input("Encrypted file 2: ").strip()
                out = input("Output filename (default hom_add.json): ").strip() or "hom_add.json"
                homomorphic_add_files(f1, f2, out)
            elif choice == "5":
                f1 = input("Encrypted file 1: ").strip()
                f2 = input("Encrypted file 2: ").strip()
                out = input("Output filename (default hom_sub.json): ").strip() or "hom_sub.json"
                homomorphic_sub_files(f1, f2, out)
            elif choice == "6":
                f = input("Encrypted file: ").strip()
                scalar = int(input("Scalar (integer): ").strip())
                out = input("Output filename (default hom_mul.json): ").strip() or "hom_mul.json"
                homomorphic_scalar_mul_file(f, scalar, out)
            elif choice == "7":
                files = input("Comma-separated encrypted files to average: ").strip().split(",")
                files = [s.strip() for s in files if s.strip()]
                out = input("Output filename (default hom_avg.json): ").strip() or "hom_avg.json"
                homomorphic_average_files(files, out)
            elif choice == "8":
                f1 = input("Encrypted file 1: ").strip()
                f2 = input("Encrypted file 2: ").strip()
                out = input("Output filename (default hom_dot.json): ").strip() or "hom_dot.json"
                homomorphic_dot_files(f1, f2, out)
            elif choice == "9":
                seed_input = input("Enter seed string (publicly shared): ").strip()
                block_size = int(input("Block size (even, default 16): ").strip() or 16)
                if block_size % 2 != 0:
                    print("Block size must be even")
                    continue
                n_layers = int(input("Number of INN layers (default 3): ").strip() or 3)
                modulus = int(input("Modulus (default 256): ").strip() or 256)
                inn, layers_flat = public_inn_from_seed(seed_input, block_size, n_layers, modulus)
                print("Public INN derived and ready for deterministic encryption.")
            elif choice == "10":
                seed_input = input("Enter public seed string: ").strip()
                in_message = input("Optional message to encrypt (leave blank to prompt): ").strip() or None
                block_size = int(input("Block size (even, default 16): ").strip() or 16)
                if block_size % 2 != 0:
                    print("Block size must be even")
                    continue
                n_layers = int(input("Number of INN layers (default 3): ").strip() or 3)
                modulus = int(input("Modulus (default 256): ").strip() or 256)
                out_file = input("Output encrypted filename (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"
                encrypt_with_public_inn(seed_input, in_message, block_size, n_layers, modulus, out_file)
            elif choice == "11":
                seed_input = input("Enter public seed string: ").strip()
                enc_file = input("Encrypted file to decrypt (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"
                if not os.path.exists(enc_file):
                    print("Encrypted file not found.")
                    continue
                decrypt_with_public_inn(seed_input, enc_file)
            else:
                print("Invalid choice")
        except Exception as e:
            print("ERROR:", e)

if __name__ == "__main__":
    main()