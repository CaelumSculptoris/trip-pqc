#!/usr/bin/env python3
"""
VEINN CLI with seed-based hybrid public-key encryption (ephemeral INN seed)
- Generate RSA keys
- Encrypt with recipient public key (sender): encrypts small seed -> derive INN -> encrypt message
- Decrypt with private key (recipient): recover seed -> derive INN -> decrypt ciphertext
- Homomorphic ops on ciphertext JSON/binary files (add, sub, scalar mul, avg, dot)
Updated with OAEP, HMAC, PBKDF2, numeric mode, batch mode, binary storage, nonce-based replay protection, and larger modulus.
Further updated with: timestamp-based nonces, flexible nonce handling, and encrypted keystore for key management.
"""
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
from typing import Callable
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode

# -----------------------------
# Key Management (Encrypted Keystore)
# -----------------------------
def create_keystore(passphrase: str, keystore_file: str = "keystore.json"):
    """Create or update an encrypted keystore with a passphrase."""
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = b64encode(kdf.derive(passphrase.encode()))
    fernet = Fernet(key)
    keystore = {"keys": {}, "salt": b64encode(salt).decode()}
    with open(keystore_file, "w") as f:
        json.dump(keystore, f)
    return fernet, keystore_file

def load_keystore(passphrase: str, keystore_file: str = "keystore.json"):
    """Load the keystore and return the Fernet object for encryption/decryption."""
    if not os.path.exists(keystore_file):
        raise FileNotFoundError("Keystore file not found. Create one first.")
    with open(keystore_file, "r") as f:
        keystore = json.load(f)
    salt = b64decode(keystore["salt"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = b64encode(kdf.derive(passphrase.encode()))
    return Fernet(key), keystore_file

def store_key_in_keystore(passphrase: str, key_name: str, key_data: dict, keystore_file: str = "keystore.json"):
    """Store a key (RSA private key or public INN seed) in the encrypted keystore."""
    fernet, keystore_file = load_keystore(passphrase, keystore_file) if os.path.exists(keystore_file) else create_keystore(passphrase, keystore_file)
    with open(keystore_file, "r") as f:
        keystore = json.load(f)
    key_str = json.dumps(key_data)
    encrypted_key = fernet.encrypt(key_str.encode()).decode()
    keystore["keys"][key_name] = encrypted_key
    with open(keystore_file, "w") as f:
        json.dump(keystore, f)
    print(f"Stored key '{key_name}' in keystore: {keystore_file}")

def retrieve_key_from_keystore(passphrase: str, key_name: str, keystore_file: str = "keystore.json"):
    """Retrieve a key from the encrypted keystore."""
    fernet, keystore_file = load_keystore(passphrase, keystore_file)
    with open(keystore_file, "r") as f:
        keystore = json.load(f)
    if key_name not in keystore["keys"]:
        raise ValueError(f"Key '{key_name}' not found in keystore")
    encrypted_key = keystore["keys"][key_name]
    try:
        key_str = fernet.decrypt(encrypted_key.encode()).decode()
        return json.loads(key_str)
    except Exception as e:
        raise ValueError("Failed to decrypt key: Wrong passphrase or corrupted keystore") from e

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
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
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

def split_blocks_flat(vec: np.ndarray, block_size: int):
    return [vec[i:i + block_size] for i in range(0, len(vec), block_size)]

# -----------------------------
# Integer coupling layer & INN
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
# Stronger seed derivation using PBKDF2
# -----------------------------
def derive_seed_bytes(seed_str: str, dklen: int = 32):
    salt = b'veinn_public_salt'
    iterations = 100000
    return hashlib.pbkdf2_hmac('sha256', seed_str.encode('utf-8'), salt, iterations, dklen=dklen)

# -----------------------------
# Public INN derivation from known seed
# -----------------------------
def public_inn_from_seed(seed_str: str, block_size: int = 16, n_layers: int = 3, modulus: int = 256):
    seed_bytes = derive_seed_bytes(seed_str)
    inn, layers_flat = derive_inn_from_seed(seed_bytes, block_size, n_layers, modulus)
    print(f"Derived INN from seed '{seed_str}':")
    print(f"- block_size: {block_size}, n_layers: {n_layers}, modulus: {modulus}")
    print(f"- layers_flat (first layer sample 10 values): {layers_flat[0][:10]}")
    return inn, layers_flat

# -----------------------------
# Deterministic INN weight derivation from seed
# -----------------------------
def derive_inn_from_seed(seed: bytes, block_size: int, n_layers: int, modulus: int = 256):
    mid = block_size // 2
    per_layer = mid * mid
    total_bytes = per_layer * n_layers
    ks = expand_keystream(seed, total_bytes)
    layers_flat = []
    for i in range(n_layers):
        start = i * per_layer
        chunk = ks[start:start + per_layer]
        arr = np.frombuffer(chunk, dtype=np.uint8).astype(np.int64) % modulus
        layers_flat.append(arr.tolist())
    inn = IntINN(block_size, n_layers=n_layers, modulus=modulus, layers_weights=layers_flat)
    return inn, layers_flat

# -----------------------------
# Serialization helpers for ciphertexts (JSON and binary)
# -----------------------------
def write_ciphertext_json(path: str, encrypted_blocks: list, metadata: dict, enc_seed_bytes: bytes, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    payload = {
        "inn_metadata": metadata,
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

def write_ciphertext_binary(path: str, encrypted_blocks: list, metadata: dict, enc_seed_bytes: bytes, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    payload = {
        "inn_metadata": metadata,
        "enc_seed": enc_seed_bytes,
        "encrypted": [blk.tobytes() for blk in encrypted_blocks],
        "hmac": hmac_value,
        "nonce": nonce,
        "timestamp": timestamp
    }
    with open(path, "wb") as f:
        pickle.dump(payload, f)

def read_ciphertext_json(path: str):
    with open(path, "r") as f:
        payload = json.load(f)
    enc_seed = bytes([int(b) for b in payload["enc_seed"]])
    metadata = payload["inn_metadata"]
    enc_blocks = [np.array([int(x) for x in blk], dtype=np.int64) for blk in payload["encrypted"]]
    hmac_value = payload.get("hmac")
    nonce = bytes([int(b) for b in payload.get("nonce", [])]) if "nonce" in payload else None
    timestamp = payload.get("timestamp")
    return metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp

def read_ciphertext_binary(path: str):
    with open(path, "rb") as f:
        payload = pickle.load(f)
    enc_seed = payload["enc_seed"]
    metadata = payload["inn_metadata"]
    enc_blocks = [np.frombuffer(blk, dtype=np.int64) for blk in payload["encrypted"]]
    hmac_value = payload.get("hmac")
    nonce = payload.get("nonce")
    timestamp = payload.get("timestamp")
    return metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp

def read_ciphertext(path: str):
    if path.endswith(".json"):
        return read_ciphertext_json(path)
    elif path.endswith(".bin"):
        return read_ciphertext_binary(path)
    else:
        raise ValueError("Unsupported file format: must be .json or .bin")

# -----------------------------
# Timestamp validation
# -----------------------------
def validate_timestamp(timestamp: float, validity_window: int = 3600):
    """Check if timestamp is within the validity window (in seconds)."""
    if timestamp is None:
        return True  # Backward compatibility
    current_time = time.time()
    return abs(current_time - timestamp) <= validity_window

# -----------------------------
# Deterministic encryption using public INN
# -----------------------------
def encrypt_with_public_inn(seed_str: str, message: str = None, numbers: list = None, block_size: int = 16, n_layers: int = 3, modulus: int = 256, out_file: str = None, mode: str = "text", bytes_per_number: int = None, binary: bool = False, nonce: bytes = None):
    inn, layers_flat = public_inn_from_seed(seed_str, block_size, n_layers, modulus)
    if mode == "text":
        if message is None:
            message = input("Message to encrypt: ")
        data = vectorize_text(message)
        padded = pkcs7_pad(data, block_size)
        blocks = split_blocks_flat(padded, block_size)
    elif mode == "numeric":
        if numbers is None:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
            numbers = [int(x) for x in raw_nums]
        if bytes_per_number is None:
            bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
        blocks = []
        for v in numbers:
            b = int_to_bytes_be(v, bytes_per_number)
            if len(b) > block_size:
                raise ValueError("Number too large for block_size")
            if len(b) < block_size:
                b = (b"\x00" * (block_size - len(b))) + b
            blocks.append(np.frombuffer(b, dtype=np.uint8))
    else:
        raise ValueError("Invalid mode: must be 'text' or 'numeric'")
    enc_blocks = [inn.forward(blk.astype(np.int64)) for blk in blocks]
    nonce = nonce or secrets.token_bytes(16)
    timestamp = time.time()
    metadata = {
        "block_size": block_size,
        "n_layers": n_layers,
        "modulus": modulus,
        "mode": mode,
        "seed_str": seed_str
    }
    if mode == "numeric":
        metadata["bytes_per_number"] = bytes_per_number
    seed_bytes = derive_seed_bytes(seed_str)
    hmac_key = expand_keystream(seed_bytes + b'hmac', 32)
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce],
        "timestamp": timestamp
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    hmac_value = hmac.new(hmac_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if out_file is None:
        out_file = input("Output encrypted filename (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"
    if binary and not out_file.endswith(".bin"):
        out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
    if binary:
        write_ciphertext_binary(out_file, enc_blocks, metadata, b'', hmac_value, nonce, timestamp)
    else:
        write_ciphertext_json(out_file, enc_blocks, metadata, b'', hmac_value, nonce, timestamp)
    print(f"Message encrypted deterministically with public INN -> {out_file}")
    return out_file

# -----------------------------
# Decrypt with public INN
# -----------------------------
def decrypt_with_public_inn(seed_str: str, enc_file: str, validity_window: int = 3600):
    metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file)
    if enc_seed:
        raise ValueError("File was not encrypted with public INN (contains RSA seed)")
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError("Timestamp expired or invalid")
    seed_bytes = derive_seed_bytes(seed_str)
    hmac_key = expand_keystream(seed_bytes + b'hmac', 32)
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce] if nonce else [],
        "timestamp": timestamp
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    computed_hmac = hmac.new(hmac_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if hmac_value != computed_hmac:
        raise ValueError("HMAC verification failed: Possibly tampered file, wrong seed, or invalid nonce/timestamp")
    block_size = int(metadata["block_size"])
    n_layers = int(metadata["n_layers"])
    modulus = int(metadata["modulus"])
    inn, layers_flat = derive_inn_from_seed(seed_bytes, block_size, n_layers, modulus)
    decrypted_blocks = [inn.reverse(blk.astype(np.int64)).astype(np.uint8) for blk in enc_blocks]
    flat = np.concatenate(decrypted_blocks).astype(np.uint8)
    mode = metadata.get("mode", "text")
    try:
        if mode == "text":
            unpadded = pkcs7_unpad(flat)
            text = devectorize_text(unpadded)
            print("Decrypted (text):")
            print(text)
            return text
        elif mode == "numeric":
            bytes_per_number = int(metadata.get("bytes_per_number", 4))
            nums = []
            for dec_blk in decrypted_blocks:
                b = dec_blk.tobytes()[-bytes_per_number:]
                v = bytes_be_to_int(b)
                nums.append(v)
            print("Decrypted (numeric list):")
            print(nums)
            return nums
        else:
            raise ValueError("Unsupported mode in metadata")
    except ValueError as e:
        print("Decryption failed:", e)
        print("Possibly wrong seed, corrupted file, or invalid padding.")
        raise

# -----------------------------
# Homomorphic helpers
# -----------------------------
def _load_encrypted_file(enc_file: str):
    metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file)
    meta_parsed = {
        "block_size": int(metadata["block_size"]),
        "n_layers": int(metadata["n_layers"]),
        "modulus": int(metadata["modulus"]),
        "seed_len": int(metadata.get("seed_len", 32)),
        "mode": metadata.get("mode", "raw"),
        "bytes_per_number": int(metadata.get("bytes_per_number", metadata.get("block_size", 4)))
    }
    return enc_blocks, meta_parsed, hmac_value, nonce, timestamp

def _write_encrypted_payload(out_file: str, enc_blocks, meta, binary: bool = False, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    out = {
        "inn_metadata": {
            "block_size": int(meta["block_size"]),
            "n_layers": int(meta["n_layers"]),
            "modulus": int(meta["modulus"]),
            "seed_len": int(meta.get("seed_len", 32)),
            "mode": meta.get("mode", "raw"),
            "bytes_per_number": int(meta.get("bytes_per_number", meta["block_size"]))
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
    if binary:
        if not out_file.endswith(".bin"):
            out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
        with open(out_file, "wb") as f:
            pickle.dump(out, f)
    else:
        with open(out_file, "w") as f:
            json.dump(out, f)

def homomorphic_add_files(f1: str, f2: str, out_file: str, binary: bool = False):
    enc1, meta1, _, _, _ = _load_encrypted_file(f1)
    enc2, meta2, _, _, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    modulus = meta1["modulus"]
    summed = [((a + b) % modulus).astype(np.int64) for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, summed, meta1, binary)
    print(f"Homomorphic sum saved to {out_file}")

def homomorphic_sub_files(f1: str, f2: str, out_file: str, binary: bool = False):
    enc1, meta1, _, _, _ = _load_encrypted_file(f1)
    enc2, meta2, _, _, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    modulus = meta1["modulus"]
    diff = [((a - b) % modulus).astype(np.int64) for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, diff, meta1, binary)
    print(f"Homomorphic difference saved to {out_file}")

def homomorphic_scalar_mul_file(f: str, scalar: int, out_file: str, binary: bool = False):
    enc, meta, _, _, _ = _load_encrypted_file(f)
    modulus = meta["modulus"]
    prod = [((blk * int(scalar)) % modulus).astype(np.int64) for blk in enc]
    _write_encrypted_payload(out_file, prod, meta, binary)
    print(f"Homomorphic scalar multiplication saved to {out_file}")

def homomorphic_average_files(files: list, out_file: str, binary: bool = False):
    encs = []
    metas = []
    for f in files:
        enc_blocks, meta, _, _, _ = _load_encrypted_file(f)
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
    _write_encrypted_payload(out_file, avg_blocks, meta, binary)
    print(f"Homomorphic average saved to {out_file}")

def homomorphic_dot_files(f1: str, f2: str, out_file: str, binary: bool = False):
    enc1, meta1, _, _, _ = _load_encrypted_file(f1)
    enc2, meta2, _, _, _ = _load_encrypted_file(f2)
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
    if binary:
        if not out_file.endswith(".bin"):
            out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
        with open(out_file, "wb") as f:
            pickle.dump(result, f)
    else:
        with open(out_file, "w") as f:
            json.dump(result, f)
    print(f"Homomorphic dot product saved to {out_file}")

# -----------------------------
# Public-key hybrid encrypt / decrypt
# -----------------------------
def generate_rsa_cli(bits: int = 2048, pubfile: str = "rsa_pub.json", privfile: str = "rsa_priv.json", keystore: str = None, passphrase: str = None, key_name: str = None):
    print("Generating RSA keypair (may take time)...")
    kp = generate_rsa_keypair(bits=bits)
    pub = {"n": kp["n"], "e": kp["e"]}
    priv = {"n": kp["n"], "d": kp["d"]}
    if keystore and passphrase and key_name:
        store_key_in_keystore(passphrase, key_name, priv, keystore)
        print(f"Private key stored in keystore: {keystore} (key: {key_name})")
    else:
        with open(privfile, "w") as f:
            json.dump(priv, f)
        print(f"RSA private key -> {privfile} (KEEP SECRET)")
    with open(pubfile, "w") as f:
        json.dump(pub, f)
    print(f"RSA public key -> {pubfile}")
    return pubfile, privfile

def encrypt_with_pub(pubfile: str, in_path: str = None, message: str = None, numbers: list = None, mode: str = "text", block_size: int = 16, n_layers: int = 3, modulus: int = 256, seed_len: int = 32, out_file: str = None, binary: bool = False, nonce: bytes = None):
    if not os.path.exists(pubfile):
        raise FileNotFoundError("RSA public key file not found")
    with open(pubfile, "r") as f:
        pub = json.load(f)
    n = int(pub["n"])
    e = int(pub["e"])
    k = (n.bit_length() + 7) // 8
    if in_path and message is None and numbers is None:
        with open(in_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if mode == "text":
            message = content
        else:
            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
            numbers = [int(x) for x in raw_nums]
    if mode == "text":
        if message is None:
            message = input("Message to encrypt: ")
        data = vectorize_text(message)
        padded = pkcs7_pad(data, block_size)
        blocks = split_blocks_flat(padded, block_size)
        bytes_per_number = None
    else:
        if numbers is None:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
            numbers = [int(x) for x in raw_nums]
        bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
        blocks = []
        for v in numbers:
            b = int_to_bytes_be(v, bytes_per_number)
            if len(b) > block_size:
                raise ValueError("Number too large for block_size")
            if len(b) < block_size:
                b = (b"\x00" * (block_size - len(b))) + b
            blocks.append(np.frombuffer(b, dtype=np.uint8))
    seed = secrets.token_bytes(seed_len)
    inn, layers_flat = derive_inn_from_seed(seed, block_size, n_layers, modulus)
    enc_blocks = [inn.forward(blk.astype(np.int64)) for blk in blocks]
    padded_seed = oaep_encode(seed, k, hash_func=sha256)
    enc_seed_int = pow(bytes_be_to_int(padded_seed), e, n)
    enc_seed_bytes = int_to_bytes_be(enc_seed_int, k)
    nonce = nonce or secrets.token_bytes(16)
    timestamp = time.time()
    metadata = {
        "block_size": block_size,
        "n_layers": n_layers,
        "modulus": modulus,
        "seed_len": seed_len,
        "mode": mode
    }
    if mode == "numeric":
        metadata["bytes_per_number"] = bytes_per_number
    hmac_key = expand_keystream(seed + b'hmac', 32)
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed_bytes],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce],
        "timestamp": timestamp
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    hmac_value = hmac.new(hmac_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if out_file is None:
        out_file = input("Output encrypted filename (default enc_pub.json): ").strip() or "enc_pub.json"
    if binary and not out_file.endswith(".bin"):
        out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
    if binary:
        write_ciphertext_binary(out_file, enc_blocks, metadata, enc_seed_bytes, hmac_value, nonce, timestamp)
    else:
        write_ciphertext_json(out_file, enc_blocks, metadata, enc_seed_bytes, hmac_value, nonce, timestamp)
    print(f"Encrypted message (with RSA-encrypted seed) saved to {out_file}")
    return out_file

def decrypt_with_priv(keysfile: str, privfile: str, enc_file: str, passphrase: str = None, key_name: str = None, validity_window: int = 3600):
    if keysfile or (passphrase and key_name):
        if not keysfile:
            keysfile = "keystore.json"
        priv = retrieve_key_from_keystore(passphrase, key_name, keysfile)
    else:
        if not os.path.exists(privfile):
            raise FileNotFoundError("RSA private key file not found")
        with open(privfile, "r") as f:
            priv = json.load(f)
    d = int(priv["d"])
    n = int(priv["n"])
    k = (n.bit_length() + 7) // 8
    metadata, enc_seed_bytes, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file)
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError("Timestamp expired or invalid")
    seed_bytes = oaep_decode(int_to_bytes_be(pow(bytes_be_to_int(enc_seed_bytes), d, n), k), k, hash_func=sha256)
    hmac_key = expand_keystream(seed_bytes + b'hmac', 32)
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed_bytes],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce] if nonce else [],
        "timestamp": timestamp
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    computed_hmac = hmac.new(hmac_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if hmac_value != computed_hmac:
        raise ValueError("HMAC verification failed: Possibly tampered file, wrong private key, or invalid nonce/timestamp")
    block_size = int(metadata["block_size"])
    n_layers = int(metadata["n_layers"])
    modulus = int(metadata["modulus"])
    inn, layers_flat = derive_inn_from_seed(seed_bytes, block_size, n_layers, modulus)
    decrypted_blocks = [inn.reverse(blk.astype(np.int64)).astype(np.uint8) for blk in enc_blocks]
    flat = np.concatenate(decrypted_blocks).astype(np.uint8)
    mode = metadata.get("mode", "text")
    try:
        if mode == "text":
            unpadded = pkcs7_unpad(flat)
            text = devectorize_text(unpadded)
            print("Decrypted (text):")
            print(text)
        else:
            bytes_per_number = int(metadata.get("bytes_per_number", 4))
            nums = []
            for dec_blk in decrypted_blocks:
                b = dec_blk.tobytes()[-bytes_per_number:]
                v = bytes_be_to_int(b)
                nums.append(v)
            print("Decrypted (numeric list):")
            print(nums)
    except ValueError as e:
        print("Decryption failed:", e)
        print("Possibly corrupted file or invalid padding.")
        raise

# -----------------------------
# CLI main with full batch mode support
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="VEINN CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Keystore management
    keystore_parser = subparsers.add_parser("create_keystore", help="Create a new encrypted keystore")
    keystore_parser.add_argument("--passphrase", required=True, help="Keystore passphrase")
    keystore_parser.add_argument("--keystore_file", default="keystore.json", help="Keystore file path")

    # RSA key generation
    rsa_parser = subparsers.add_parser("generate_rsa", help="Generate RSA keypair")
    rsa_parser.add_argument("--bits", type=int, default=2048, help="RSA key size in bits")
    rsa_parser.add_argument("--pubfile", default="rsa_pub.json", help="Public key output file")
    rsa_parser.add_argument("--privfile", default="rsa_priv.json", help="Private key output file")
    rsa_parser.add_argument("--keystore", help="Store private key in keystore")
    rsa_parser.add_argument("--passphrase", help="Keystore passphrase")
    rsa_parser.add_argument("--key_name", help="Key name in keystore")

    # Public encrypt
    pub_enc_parser = subparsers.add_parser("public_encrypt", help="Encrypt with public INN")
    pub_enc_parser.add_argument("--seed", required=True, help="Public seed string")
    pub_enc_parser.add_argument("--message", help="Message to encrypt (text mode)")
    pub_enc_parser.add_argument("--numbers", nargs="+", type=int, help="Numbers to encrypt (numeric mode)")
    pub_enc_parser.add_argument("--mode", default="text", choices=["text", "numeric"], help="Mode: text or numeric")
    pub_enc_parser.add_argument("--bytes_per_number", type=int, default=4, help="Bytes per number (numeric mode)")
    pub_enc_parser.add_argument("--block_size", type=int, default=16, help="Block size (even)")
    pub_enc_parser.add_argument("--n_layers", type=int, default=3, help="Number of layers")
    pub_enc_parser.add_argument("--modulus", type=int, default=256, help="Modulus")
    pub_enc_parser.add_argument("--out_file", default="enc_pub_inn.json", help="Output file")
    pub_enc_parser.add_argument("--binary", action="store_true", help="Use binary output format")
    pub_enc_parser.add_argument("--nonce", help="Custom nonce (base64-encoded)")
    pub_enc_parser.add_argument("--keystore", help="Store seed in keystore")
    pub_enc_parser.add_argument("--passphrase", help="Keystore passphrase")
    pub_enc_parser.add_argument("--key_name", help="Seed name in keystore")

    # Public decrypt
    pub_dec_parser = subparsers.add_parser("public_decrypt", help="Decrypt with public INN")
    pub_dec_parser.add_argument("--seed", help="Public seed string")
    pub_dec_parser.add_argument("--keystore", help="Retrieve seed from keystore")
    pub_dec_parser.add_argument("--passphrase", help="Keystore passphrase")
    pub_dec_parser.add_argument("--key_name", help="Seed name in keystore")
    pub_dec_parser.add_argument("--enc_file", default="enc_pub_inn.json", help="Encrypted file")
    pub_dec_parser.add_argument("--validity_window", type=int, default=3600, help="Timestamp validity window (seconds)")

    # RSA encrypt
    rsa_enc_parser = subparsers.add_parser("rsa_encrypt", help="Encrypt with RSA public key")
    rsa_enc_parser.add_argument("--pubfile", default="rsa_pub.json", help="RSA public key file")
    rsa_enc_parser.add_argument("--in_path", help="Input file path")
    rsa_enc_parser.add_argument("--message", help="Message to encrypt (text mode)")
    rsa_enc_parser.add_argument("--numbers", nargs="+", type=int, help="Numbers to encrypt (numeric mode)")
    rsa_enc_parser.add_argument("--mode", default="text", choices=["text", "numeric"], help="Mode: text or numeric")
    rsa_enc_parser.add_argument("--bytes_per_number", type=int, default=4, help="Bytes per number (numeric mode)")
    rsa_enc_parser.add_argument("--block_size", type=int, default=16, help="Block size (even)")
    rsa_enc_parser.add_argument("--n_layers", type=int, default=3, help="Number of layers")
    rsa_enc_parser.add_argument("--modulus", type=int, default=256, help="Modulus")
    rsa_enc_parser.add_argument("--seed_len", type=int, default=32, help="Ephemeral seed length")
    rsa_enc_parser.add_argument("--out_file", default="enc_pub.json", help="Output file")
    rsa_enc_parser.add_argument("--binary", action="store_true", help="Use binary output format")
    rsa_enc_parser.add_argument("--nonce", help="Custom nonce (base64-encoded)")

    # RSA decrypt
    rsa_dec_parser = subparsers.add_parser("rsa_decrypt", help="Decrypt with RSA private key")
    rsa_dec_parser.add_argument("--privfile", default="rsa_priv.json", help="RSA private key file")
    rsa_dec_parser.add_argument("--keystore", help="Retrieve private key from keystore")
    rsa_dec_parser.add_argument("--passphrase", help="Keystore passphrase")
    rsa_dec_parser.add_argument("--key_name", help="Key name in keystore")
    rsa_dec_parser.add_argument("--enc_file", default="enc_pub.json", help="Encrypted file")
    rsa_dec_parser.add_argument("--validity_window", type=int, default=3600, help="Timestamp validity window (seconds)")

    # Homomorphic operations
    hom_add_parser = subparsers.add_parser("hom_add", help="Homomorphic addition")
    hom_add_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_add_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_add_parser.add_argument("--out_file", default="hom_add.json", help="Output file")
    hom_add_parser.add_argument("--binary", action="store_true", help="Use binary output format")

    hom_sub_parser = subparsers.add_parser("hom_sub", help="Homomorphic subtraction")
    hom_sub_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_sub_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_sub_parser.add_argument("--out_file", default="hom_sub.json", help="Output file")
    hom_sub_parser.add_argument("--binary", action="store_true", help="Use binary output format")

    hom_mul_parser = subparsers.add_parser("hom_scalar_mul", help="Homomorphic scalar multiplication")
    hom_mul_parser.add_argument("--file", required=True, help="Encrypted file")
    hom_mul_parser.add_argument("--scalar", type=int, required=True, help="Scalar integer")
    hom_mul_parser.add_argument("--out_file", default="hom_mul.json", help="Output file")
    hom_mul_parser.add_argument("--binary", action="store_true", help="Use binary output format")

    hom_avg_parser = subparsers.add_parser("hom_avg", help="Homomorphic average")
    hom_avg_parser.add_argument("--files", nargs="+", required=True, help="Encrypted files")
    hom_avg_parser.add_argument("--out_file", default="hom_avg.json", help="Output file")
    hom_avg_parser.add_argument("--binary", action="store_true", help="Use binary output format")

    hom_dot_parser = subparsers.add_parser("hom_dot", help="Homomorphic dot product")
    hom_dot_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_dot_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_dot_parser.add_argument("--out_file", default="hom_dot.json", help="Output file")
    hom_dot_parser.add_argument("--binary", action="store_true", help="Use binary output format")

    # Public INN derivation
    pub_inn_parser = subparsers.add_parser("public_inn", help="Derive public INN from seed")
    pub_inn_parser.add_argument("--seed", help="Public seed string")
    pub_inn_parser.add_argument("--keystore", help="Retrieve seed from keystore")
    pub_inn_parser.add_argument("--passphrase", help="Keystore passphrase")
    pub_inn_parser.add_argument("--key_name", help="Seed name in keystore")
    pub_inn_parser.add_argument("--block_size", type=int, default=16, help="Block size (even)")
    pub_inn_parser.add_argument("--n_layers", type=int, default=3, help="Number of layers")
    pub_inn_parser.add_argument("--modulus", type=int, default=256, help="Modulus")

    args = parser.parse_known_args()[0]

    try:
        if args.command == "create_keystore":
            create_keystore(args.passphrase, args.keystore_file)
            print(f"Keystore created: {args.keystore_file}")
        elif args.command == "generate_rsa":
            pubfile, privfile = generate_rsa_cli(args.bits, args.pubfile, args.privfile, args.keystore, args.passphrase, args.key_name)
        elif args.command == "public_encrypt":
            if args.keystore and args.passphrase and args.key_name:
                seed_data = retrieve_key_from_keystore(args.passphrase, args.key_name, args.keystore)
                args.seed = seed_data["seed"]
            nonce = b64decode(args.nonce) if args.nonce else None
            out_file = encrypt_with_public_inn(args.seed, args.message, args.numbers, args.block_size, args.n_layers, args.modulus, args.out_file, args.mode, args.bytes_per_number, args.binary, nonce)
            if args.keystore and args.passphrase and args.key_name:
                store_key_in_keystore(args.passphrase, args.key_name, {"seed": args.seed}, args.keystore)
        elif args.command == "public_decrypt":
            if args.keystore and args.passphrase and args.key_name:
                seed_data = retrieve_key_from_keystore(args.passphrase, args.key_name, args.keystore)
                args.seed = seed_data["seed"]
            decrypt_with_public_inn(args.seed, args.enc_file, args.validity_window)
        elif args.command == "rsa_encrypt":
            nonce = b64decode(args.nonce) if args.nonce else None
            encrypt_with_pub(args.pubfile, args.in_path, args.message, args.numbers, args.mode, args.block_size, args.n_layers, args.modulus, args.seed_len, args.out_file, args.binary, nonce)
        elif args.command == "rsa_decrypt":
            decrypt_with_priv(args.keystore, args.privfile, args.enc_file, args.passphrase, args.key_name, args.validity_window)
        elif args.command == "hom_add":
            homomorphic_add_files(args.file1, args.file2, args.out_file, args.binary)
        elif args.command == "hom_sub":
            homomorphic_sub_files(args.file1, args.file2, args.out_file, args.binary)
        elif args.command == "hom_scalar_mul":
            homomorphic_scalar_mul_file(args.file, args.scalar, args.out_file, args.binary)
        elif args.command == "hom_avg":
            homomorphic_average_files(args.files, args.out_file, args.binary)
        elif args.command == "hom_dot":
            homomorphic_dot_files(args.file1, args.file2, args.out_file, args.binary)
        elif args.command == "public_inn":
            if args.keystore and args.passphrase and args.key_name:
                seed_data = retrieve_key_from_keystore(args.passphrase, args.key_name, args.keystore)
                args.seed = seed_data["seed"]
            public_inn_from_seed(args.seed, args.block_size, args.n_layers, args.modulus)
        else:
            # Interactive mode
            print("VEINN CLI — seed-based public-key hybrid (ephemeral INN seed) + homomorphic ops")
            while True:
                print("")
                print("1) Create encrypted keystore")
                print("2) Generate RSA keypair (public/private)")
                print("3) Encrypt with recipient public key (seed-based ephemeral INN)")
                print("4) Decrypt with private key")
                print("5) Homomorphic add (file1, file2 -> out)")
                print("6) Homomorphic subtract (file1, file2 -> out)")
                print("7) Homomorphic scalar multiply (file, scalar -> out)")
                print("8) Homomorphic average (file1,file2,... -> out)")
                print("9) Homomorphic dot product (file1, file2 -> out)")
                print("10) Derive public INN from seed (deterministic encryption without private key)")
                print("11) Encrypt deterministically using public INN (seed-based, no private key)")
                print("12) Decrypt deterministically using public INN (seed-based, no private key)")
                print("0) Exit")
                choice = input("Choice: ").strip()

                try:
                    if choice == "0":
                        break
                    elif choice == "1":
                        passphrase = input("Enter keystore passphrase: ")
                        keystore_file = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                        create_keystore(passphrase, keystore_file)
                        print(f"Keystore created: {keystore_file}")
                    elif choice == "2":
                        bits = int(input("RSA key size in bits (default 2048): ").strip() or 2048)
                        pubfile = input("Public key filename (default rsa_pub.json): ").strip() or "rsa_pub.json"
                        use_keystore = input("Store private key in keystore? (y/n): ").strip().lower() == "y"
                        privfile, passphrase, key_name = None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("Private key filename (default rsa_priv.json): ").strip() or "rsa_priv.json"
                        generate_rsa_cli(bits, pubfile, privfile, keystore, passphrase, key_name)
                    elif choice == "3":
                        pubfile = input("Recipient RSA public key file (default rsa_pub.json): ").strip() or "rsa_pub.json"
                        if not os.path.exists(pubfile):
                            print("Public key not found. Generate RSA keys first.")
                            continue
                        inpath = input("Optional input file path (blank = prompt): ").strip() or None
                        mode = input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "text"
                        block_size = int(input("Block size (even, default 16): ").strip() or 16)
                        if block_size % 2 != 0:
                            print("Block size must be even")
                            continue
                        n_layers = int(input("Number of layers (default 3): ").strip() or 3)
                        modulus = int(input("Modulus (default 256): ").strip() or 256)
                        seed_len = int(input("Seed length (default 32): ").strip() or 32)
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
                        nonce = b64decode(nonce_str) if nonce_str else None
                        encrypt_with_pub(pubfile, in_path=inpath, mode=mode, block_size=block_size, n_layers=n_layers, modulus=modulus, seed_len=seed_len, binary=binary, nonce=nonce)
                    elif choice == "4":
                        use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() == "y"
                        privfile, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("RSA private key file (default rsa_priv.json): ").strip() or "rsa_priv.json"
                        encfile = input("Encrypted file to decrypt (default enc_pub.json): ").strip() or "enc_pub.json"
                        validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
                        if not (privfile and os.path.exists(privfile)) and not (keystore and passphrase and key_name):
                            print("Invalid private key source.")
                            continue
                        if not os.path.exists(encfile):
                            print("Encrypted file not found.")
                            continue
                        decrypt_with_priv(keystore, privfile, encfile, passphrase, key_name, validity_window)
                    elif choice == "5":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_add.json): ").strip() or "hom_add.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_add_files(f1, f2, out, binary)
                    elif choice == "6":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_sub.json): ").strip() or "hom_sub.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_sub_files(f1, f2, out, binary)
                    elif choice == "7":
                        f = input("Encrypted file: ").strip()
                        scalar = int(input("Scalar (integer): ").strip())
                        out = input("Output filename (default hom_mul.json): ").strip() or "hom_mul.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_scalar_mul_file(f, scalar, out, binary)
                    elif choice == "8":
                        files = input("Comma-separated encrypted files to average: ").strip().split(",")
                        files = [s.strip() for s in files if s.strip()]
                        out = input("Output filename (default hom_avg.json): ").strip() or "hom_avg.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_average_files(files, out, binary)
                    elif choice == "9":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_dot.json): ").strip() or "hom_dot.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_dot_files(f1, f2, out, binary)
                    elif choice == "10":
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
                        block_size = int(input("Block size (even, default 16): ").strip() or 16)
                        if block_size % 2 != 0:
                            print("Block size must be even")
                            continue
                        n_layers = int(input("Number of layers (default 3): ").strip() or 3)
                        modulus = int(input("Modulus (default 256): ").strip() or 256)
                        public_inn_from_seed(seed_input, block_size, n_layers, modulus)
                    elif choice == "11":
                        use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() == "y"
                        seed_input, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Seed name in keystore: ")
                            seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
                            seed_input = seed_data["seed"]
                        else:
                            seed_input = input("Enter public seed string: ").strip()
                        mode = input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "text"
                        message = None
                        numbers = None
                        bytes_per_number = None
                        if mode == "text":
                            message = input("Message to encrypt: ")
                        else:
                            content = input("Enter numbers (comma or whitespace separated): ").strip()
                            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
                            numbers = [int(x) for x in raw_nums]
                            bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
                        block_size = int(input("Block size (even, default 16): ").strip() or 16)
                        if block_size % 2 != 0:
                            print("Block size must be even")
                            continue
                        n_layers = int(input("Number of layers (default 3): ").strip() or 3)
                        modulus = int(input("Modulus (default 256): ").strip() or 256)
                        out_file = input("Output encrypted filename (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
                        nonce = b64decode(nonce_str) if nonce_str else None
                        out_file = encrypt_with_public_inn(seed_input, message, numbers, block_size, n_layers, modulus, out_file, mode, bytes_per_number, binary, nonce)
                        if use_keystore:
                            store_key_in_keystore(passphrase, key_name, {"seed": seed_input}, keystore)
                    elif choice == "12":
                        use_keystore = input("Use keystore for seed? (y/n): ").strip().lower() == "y"
                        seed_input, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Seed name in keystore: ")
                            seed_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
                            seed_input = seed_data["seed"]
                        else:
                            seed_input = input("Enter public seed string: ").strip()
                        enc_file = input("Encrypted file to decrypt (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"
                        validity_window = int(input("Timestamp validity window in seconds (default 3600): ").strip() or 3600)
                        if not os.path.exists(enc_file):
                            print("Encrypted file not found.")
                            continue
                        decrypt_with_public_inn(seed_input, enc_file, validity_window)
                    else:
                        print("Invalid choice")
                except Exception as e:
                    print("ERROR:", e)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()