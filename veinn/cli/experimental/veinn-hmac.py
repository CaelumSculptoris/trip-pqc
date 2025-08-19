#!/usr/bin/env python3
"""
VEINN CLI (v3 Hybrid) with non-linear INN + ChaCha20-Poly1305 + HMAC
- RSA for key exchange, non-linear INN for data encryption, ChaCha20-Poly1305 for seed encryption
- HMAC for ciphertext authentication, Paillier for homomorphic operations
- HKDF for key derivation, timestamped nonces, and full CLI menu
"""
import os
import sys
import json
import math
import hashlib
import hmac
import secrets
import time
import argparse
import pickle
import numpy as np
from typing import Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from phe import paillier

# -----------------------------
# Key Management (Encrypted Keystore)
# -----------------------------
def create_keystore(passphrase: str, keystore_file: str = "keystore.json"):
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = b64encode(kdf.derive(passphrase.encode()))
    fernet = Fernet(key)
    keystore = {"keys": {}, "salt": b64encode(salt).decode()}
    with open(keystore_file, "w") as f:
        json.dump(keystore, f)
    return fernet, keystore_file

def load_keystore(passphrase: str, keystore_file: str = "keystore.json"):
    if not os.path.exists(keystore_file):
        raise FileNotFoundError("Keystore file not found. Create one first.")
    with open(keystore_file, "r") as f:
        keystore = json.load(f)
    salt = b64decode(keystore["salt"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = b64encode(kdf.derive(passphrase.encode()))
    return Fernet(key), keystore_file

def store_key_in_keystore(passphrase: str, key_name: str, key_data: dict, keystore_file: str = "keystore.json"):
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
# RSA Utilities
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
        raise ValueError("Modular inverse does not exist")
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
# ChaCha20-Poly1305 for Seed Encryption
# -----------------------------
def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, b""  # Tag is included in ciphertext

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# -----------------------------
# Non-linear INN
# -----------------------------
def generate_large_prime(bits: int = 256) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

class NonLinearCouplingLayer:
    def __init__(self, block_size: int, prime: int, seed: bytes, layer_idx: int):
        self.block_size = block_size
        self.prime = prime
        self.mid = block_size // 2
        hkdf = HKDF(algorithm=hashes.SHA256(), length=4 * self.mid * (self.mid + 2), salt=None, info=f"layer_{layer_idx}".encode())
        derived = hkdf.derive(seed)
        offset = 0
        W_flat = [int(x) % self.prime for x in np.frombuffer(derived[offset:offset + self.mid * self.mid * 4], dtype=np.uint32)]
        if len(W_flat) != self.mid * self.mid:
            raise ValueError(f"W_flat length {len(W_flat)} does not match expected {self.mid * self.mid}")
        self.W = np.array(W_flat, dtype=np.int64).reshape(self.mid, self.mid)
        if self.W.shape != (self.mid, self.mid):
            raise ValueError(f"W shape {self.W.shape} does not match expected {(self.mid, self.mid)}")
        offset += self.mid * self.mid * 4
        scalars = [int(x) % (self.prime - 1) + 1 for x in np.frombuffer(derived[offset:offset + self.mid * 4], dtype=np.uint32)]
        if len(scalars) != self.mid:
            raise ValueError(f"scalars length {len(scalars)} does not match expected {self.mid}")
        self.scalars = np.array(scalars, dtype=np.int64)
        if self.scalars.shape != (self.mid,):
            raise ValueError(f"scalars shape {self.scalars.shape} does not match expected {(self.mid,)}")
        offset += self.mid * 4
        perm = [int(x) % self.mid for x in np.frombuffer(derived[offset:offset + self.mid * 4], dtype=np.uint32)]
        if len(perm) != self.mid:
            raise ValueError(f"perm length {len(perm)} does not match expected {self.mid}")
        perm = np.array(perm, dtype=np.int64)
        self.perm = np.argsort(perm)
        self.inv_perm = np.argsort(self.perm)

    def forward(self, x: np.ndarray) -> np.ndarray:
        x = [int(xi) % self.prime for xi in x]
        x = np.array(x, dtype=np.int64)
        if len(x) != self.block_size:
            raise ValueError(f"Input block size {len(x)} does not match expected {self.block_size}")
        x1 = x[:self.mid]
        x2 = x[self.mid:]
        if len(x1) != self.mid or len(x2) != self.mid:
            raise ValueError(f"x1 or x2 length mismatch: x1={len(x1)}, x2={len(x2)}, expected {self.mid}")
        s = [int((int(s) * int(x2i)) % self.prime) for s, x2i in zip(self.scalars, x2)]
        s = np.array(s, dtype=np.int64)
        if s.shape != (self.mid,):
            raise ValueError(f"s shape {s.shape} does not match expected {(self.mid,)}")
        w = [int(sum((int(wi) * int(x1i)) % self.prime for wi, x1i in zip(w_row, x1)) % self.prime) for w_row in self.W]
        w = np.array(w, dtype=np.int64)
        if w.shape != (self.mid,):
            raise ValueError(f"w shape {w.shape} does not match expected {(self.mid,)}")
        y2 = [int((int(si) + int(wi)) % self.prime) for si, wi in zip(s, w)]  # Compute in Python
        y2 = np.array(y2, dtype=np.int64)
        if y2.shape != (self.mid,):
            raise ValueError(f"y2 shape {y2.shape} does not match expected {(self.mid,)}")
        y2 = y2[self.perm]
        return np.concatenate([x1, y2])

    def reverse(self, y: np.ndarray) -> np.ndarray:
        y = [int(yi) % self.prime for yi in y]
        y = np.array(y, dtype=np.int64)
        if len(y) != self.block_size:
            raise ValueError(f"Input block size {len(y)} does not match expected {self.block_size}")
        y1 = y[:self.mid]
        y2 = y[self.mid:]
        if len(y1) != self.mid or len(y2) != self.mid:
            raise ValueError(f"y1 or y2 length mismatch: y1={len(y1)}, y2={len(y2)}, expected {self.mid}")
        y2 = y2[self.inv_perm]
        w = [int(sum((int(wi) * int(y1i)) % self.prime for wi, y1i in zip(w_row, y1)) % self.prime) for w_row in self.W]
        w = np.array(w, dtype=np.int64)
        if w.shape != (self.mid,):
            raise ValueError(f"w shape {w.shape} does not match expected {(self.mid,)}")
        x2 = [int(((int(y2i) - int(wi)) * modinv(int(s), self.prime)) % self.prime) for y2i, wi, s in zip(y2, w, self.scalars)]
        x2 = np.array(x2, dtype=np.int64)
        if x2.shape != (self.mid,):
            raise ValueError(f"x2 shape {x2.shape} does not match expected {(self.mid,)}")
        return np.concatenate([y1, x2])

class NonLinearINN:
    def __init__(self, block_size: int, n_layers: int, prime: int, seed: bytes):
        self.block_size = block_size
        self.prime = prime or generate_large_prime(256)
        if self.block_size % 2 != 0:
            raise ValueError(f"Block size {self.block_size} must be even")
        self.layers = []
        for i in range(n_layers):
            layer_seed = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=f"inn_layer_{i}".encode()
            ).derive(seed)
            layer = NonLinearCouplingLayer(block_size, self.prime, layer_seed, i)
            self.layers.append(layer)
        if len(self.layers) != n_layers:
            raise ValueError(f"Created {len(self.layers)} layers, expected {n_layers}")

    def forward(self, block: np.ndarray) -> np.ndarray:
        if len(block) != self.block_size:
            raise ValueError(f"Input block size {len(block)} does not match expected {self.block_size}")
        x = [int(b) % self.prime for b in block]
        x = np.array(x, dtype=np.int64)
        if x.shape != (self.block_size,):
            raise ValueError(f"Input block shape {x.shape} does not match expected {(self.block_size,)}")
        for i, layer in enumerate(self.layers):
            x = layer.forward(x)
            if x.shape != (self.block_size,):
                raise ValueError(f"Layer {i} output shape {x.shape} does not match expected {(self.block_size,)}")
        return x % self.prime

    def reverse(self, block: np.ndarray) -> np.ndarray:
        if len(block) != self.block_size:
            raise ValueError(f"Input block size {len(block)} does not match expected {self.block_size}")
        y = [int(b) % self.prime for b in block]
        y = np.array(y, dtype=np.int64)
        if y.shape != (self.block_size,):
            raise ValueError(f"Input block shape {y.shape} does not match expected {(self.block_size,)}")
        for i, layer in enumerate(reversed(self.layers)):
            y = layer.reverse(y)
            if y.shape != (self.block_size,):
                raise ValueError(f"Layer {i} reverse output shape {y.shape} does not match expected {(self.block_size,)}")
        return y % self.prime

# -----------------------------
# Key Derivation
# -----------------------------
def derive_keys(seed: bytes, info: bytes = b"veinn") -> Tuple[bytes, bytes, bytes]:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=96, salt=None, info=info)
    derived = hkdf.derive(seed)
    return derived[:32], derived[32:64], derived[64:]  # enc_key, auth_key, chacha_key

# -----------------------------
# Utilities
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
    blocks = [vec[i:i + block_size] for i in range(0, len(vec), block_size)]
    # Pad the last block with zeros if it's too short
    if blocks and len(blocks[-1]) < block_size:
        blocks[-1] = np.pad(blocks[-1], (0, block_size - len(blocks[-1])), mode='constant', constant_values=0)
    return blocks

def pad_numeric_block(block: np.ndarray, block_size: int, prime: int) -> np.ndarray:
    block = [int(b) % prime for b in block]
    block = np.array(block, dtype=np.int64)
    if len(block) < block_size:
        return np.pad(block, (0, block_size - len(block)), mode='constant', constant_values=0)
    return block[:block_size]

# -----------------------------
# Serialization
# -----------------------------
def write_ciphertext_json(path: str, encrypted_blocks: list, metadata: dict, enc_seed: bytes, hmac_value: str, nonce: bytes, timestamp: float, chacha_seed: bytes = b""):
    payload = {
        "inn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in encrypted_blocks],
        "hmac": hmac_value,
        "nonce": [int(b) for b in nonce],
        "timestamp": timestamp,
        "chacha_seed": [int(b) for b in chacha_seed]
    }
    with open(path, "w") as f:
        json.dump(payload, f)

def write_ciphertext_binary(path: str, encrypted_blocks: list, metadata: dict, enc_seed: bytes, hmac_value: str, nonce: bytes, timestamp: float, chacha_seed: bytes = b""):
    payload = {
        "inn_metadata": metadata,
        "enc_seed": enc_seed,
        "encrypted": [blk.tobytes() for blk in encrypted_blocks],
        "hmac": hmac_value,
        "nonce": nonce,
        "timestamp": timestamp,
        "chacha_seed": chacha_seed
    }
    with open(path, "wb") as f:
        pickle.dump(payload, f)

def read_ciphertext_json(path: str):
    with open(path, "r") as f:
        payload = json.load(f)
    enc_seed = bytes([int(b) for b in payload["enc_seed"]])
    metadata = payload["inn_metadata"]
    enc_blocks = [np.array([int(x) for x in blk], dtype=np.int64) for blk in payload["encrypted"]]
    hmac_value = payload["hmac"]
    nonce = bytes([int(b) for b in payload["nonce"]])
    timestamp = payload["timestamp"]
    chacha_seed = bytes([int(b) for b in payload.get("chacha_seed", [])])
    return metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp, chacha_seed

def read_ciphertext_binary(path: str):
    with open(path, "rb") as f:
        payload = pickle.load(f)
    return payload["inn_metadata"], payload["enc_seed"], [np.frombuffer(blk, dtype=np.int64) for blk in payload["encrypted"]], payload["hmac"], payload["nonce"], payload["timestamp"], payload.get("chacha_seed", b"")

def read_ciphertext(path: str):
    if path.endswith(".json"):
        return read_ciphertext_json(path)
    elif path.endswith(".bin"):
        return read_ciphertext_binary(path)
    else:
        raise ValueError("Unsupported file format: must be .json or .bin")

# -----------------------------
# Timestamp Validation
# -----------------------------
def validate_timestamp(timestamp: float, validity_window: int = 3600):
    if timestamp is None:
        return True
    current_time = time.time()
    return abs(current_time - timestamp) <= validity_window

# -----------------------------
# Paillier Homomorphic Encryption
# -----------------------------
def generate_paillier_keypair(bits: int = 2048):
    public_key, private_key = paillier.generate_paillier_keypair(n_length=bits)
    return public_key, private_key

def paillier_encrypt(public_key, numbers: list) -> list:
    return [public_key.encrypt(n) for n in numbers]

def paillier_decrypt(private_key, ciphertexts: list) -> list:
    return [private_key.decrypt(c) for c in ciphertexts]

def paillier_homomorphic_add(ciphertexts1: list, ciphertexts2: list, public_key) -> list:
    if len(ciphertexts1) != len(ciphertexts2):
        raise ValueError("Ciphertext lists must have equal length")
    return [c1 + c2 for c1, c2 in zip(ciphertexts1, ciphertexts2)]

# -----------------------------
# Public INN Encryption
# -----------------------------
def encrypt_with_public_inn(seed: str, message: str = None, numbers: list = None, block_size: int = 16, n_layers: int = 8, prime: int = None, out_file: str = None, mode: str = "text", bytes_per_number: int = None, binary: bool = False, nonce: bytes = None):
    seed_bytes = hashlib.sha256(seed.encode()).digest()
    enc_key, auth_key, _ = derive_keys(seed_bytes, b"public_inn")
    inn = NonLinearINN(block_size=block_size, n_layers=n_layers, prime=prime, seed=enc_key)
    nonce = nonce or secrets.token_bytes(16)
    timestamp = time.time()
    
    if mode == "text":
        if message is None:
            message = input("Message to encrypt: ")
        data = vectorize_text(message)
        padded = pkcs7_pad(data, block_size)
        blocks = split_blocks_flat(padded, block_size)
    else:
        if numbers is None:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
            numbers = [int(x) for x in content.replace(",", " ").split() if x]
        if bytes_per_number is None:
            bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
        blocks = [pad_numeric_block(np.frombuffer(int.to_bytes(n % inn.prime, bytes_per_number, "big"), dtype=np.uint8), block_size, inn.prime) for n in numbers]
    
    enc_blocks = [inn.forward(blk) for blk in blocks]
    metadata = {
        "block_size": block_size,
        "n_layers": n_layers,
        "prime": int(inn.prime),
        "mode": mode
    }
    if mode == "numeric":
        metadata["bytes_per_number"] = bytes_per_number
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce],
        "timestamp": timestamp,
        "chacha_seed": []
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    hmac_value = hmac.new(auth_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if out_file is None:
        out_file = input("Output encrypted filename (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"
    if binary and not out_file.endswith(".bin"):
        out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
    if binary:
        write_ciphertext_binary(out_file, enc_blocks, metadata, b"", hmac_value, nonce, timestamp)
    else:
        write_ciphertext_json(out_file, enc_blocks, metadata, b"", hmac_value, nonce, timestamp)
    print(f"Message encrypted with public INN -> {out_file}")
    return out_file

# -----------------------------
# Public INN Decryption
# -----------------------------
def decrypt_with_public_inn(seed: str, enc_file: str, validity_window: int = 3600):
    metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp, chacha_seed = read_ciphertext(enc_file)
    if enc_seed or chacha_seed:
        raise ValueError("File was not encrypted with public INN")
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError("Timestamp expired or invalid")
    seed_bytes = hashlib.sha256(seed.encode()).digest()
    enc_key, auth_key, _ = derive_keys(seed_bytes, b"public_inn")
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce],
        "timestamp": timestamp,
        "chacha_seed": []
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    computed_hmac = hmac.new(auth_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if hmac_value != computed_hmac:
        raise ValueError("HMAC verification failed")
    inn = NonLinearINN(block_size=int(metadata["block_size"]), n_layers=int(metadata["n_layers"]), prime=int(metadata["prime"]), seed=enc_key)
    decrypted_blocks = [inn.reverse(blk) for blk in enc_blocks]
    flat = np.concatenate(decrypted_blocks).astype(np.uint8)
    mode = metadata.get("mode", "text")
    try:
        if mode == "text":
            unpadded = pkcs7_unpad(flat)
            text = devectorize_text(unpadded)
            print("Decrypted (text):")
            print(text)
            return text
        else:
            bytes_per_number = int(metadata.get("bytes_per_number", 4))
            nums = [int.from_bytes(blk.tobytes()[-bytes_per_number:], "big") for blk in decrypted_blocks]
            print("Decrypted (numeric list):")
            print(nums)
            return nums
    except ValueError as e:
        print("Decryption failed:", e)
        raise

# -----------------------------
# RSA Hybrid Encryption with ChaCha20-Poly1305
# -----------------------------
def generate_rsa_cli(bits: int = 2048, pubfile: str = "rsa_pub.json", privfile: str = "rsa_priv.json", keystore: str = None, passphrase: str = None, key_name: str = None):
    print("Generating RSA keypair...")
    kp = generate_rsa_keypair(bits)
    pub = {"n": kp["n"], "e": kp["e"]}
    priv = {"n": kp["n"], "d": kp["d"], "chacha_key": b64encode(secrets.token_bytes(32)).decode()}  # ChaCha20 key
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

def encrypt_with_pub(pubfile: str, in_path: str = None, message: str = None, numbers: list = None, mode: str = "text", block_size: int = 16, n_layers: int = 8, prime: int = None, seed_len: int = 32, out_file: str = None, binary: bool = False, nonce: bytes = None, bytes_per_number: int = None):
    if not os.path.exists(pubfile):
        raise FileNotFoundError("RSA public key file not found")
    with open(pubfile, "r") as f:
        pub = json.load(f)
    n = int(pub["n"])
    e = int(pub["e"])
    k = (n.bit_length() + 7) // 8
    seed = secrets.token_bytes(seed_len)
    enc_key, auth_key, chacha_key = derive_keys(seed, b"rsa_hybrid")
    inn = NonLinearINN(block_size=block_size, n_layers=n_layers, prime=prime, seed=enc_key)
    nonce = nonce or secrets.token_bytes(16)
    chacha_nonce = secrets.token_bytes(12)  # 12 bytes for ChaCha20
    timestamp = time.time()
    
    if in_path and message is None and numbers is None:
        with open(in_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if mode == "text":
            message = content
        else:
            numbers = [int(x) for x in content.replace(",", " ").split() if x]
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
            numbers = [int(x) for x in content.replace(",", " ").split() if x]
        if bytes_per_number is None:
            bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
        blocks = [pad_numeric_block(np.frombuffer(int.to_bytes(n % inn.prime, bytes_per_number, "big"), dtype=np.uint8), block_size, inn.prime) for n in numbers]
    
    enc_blocks = [inn.forward(blk) for blk in blocks]
    # Encrypt seed with ChaCha20-Poly1305
    chacha_seed, _ = chacha20_poly1305_encrypt(chacha_key, chacha_nonce, seed)
    enc_seed_int = pow(bytes_be_to_int(chacha_seed), e, n)
    enc_seed_bytes = int_to_bytes_be(enc_seed_int, k)
    metadata = {
        "block_size": block_size,
        "n_layers": n_layers,
        "prime": int(inn.prime),
        "mode": mode,
        "seed_len": seed_len,
        "chacha_nonce": [int(b) for b in chacha_nonce]
    }
    if mode == "numeric":
        metadata["bytes_per_number"] = bytes_per_number
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed_bytes],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce],
        "timestamp": timestamp,
        "chacha_seed": [int(b) for b in chacha_seed]
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    hmac_value = hmac.new(auth_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if out_file is None:
        out_file = input("Output encrypted filename (default enc_pub.json): ").strip() or "enc_pub.json"
    if binary and not out_file.endswith(".bin"):
        out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
    if binary:
        write_ciphertext_binary(out_file, enc_blocks, metadata, enc_seed_bytes, hmac_value, nonce, timestamp, chacha_seed)
    else:
        write_ciphertext_json(out_file, enc_blocks, metadata, enc_seed_bytes, hmac_value, nonce, timestamp, chacha_seed)
    print(f"Encrypted message saved to {out_file}")
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
    chacha_key = b64decode(priv["chacha_key"])
    k = (n.bit_length() + 7) // 8
    metadata, enc_seed_bytes, enc_blocks, hmac_value, nonce, timestamp, chacha_seed = read_ciphertext(enc_file)
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError("Timestamp expired or invalid")
    chacha_nonce = bytes([int(b) for b in metadata["chacha_nonce"]])
    chacha_seed_int = pow(bytes_be_to_int(enc_seed_bytes), d, n)
    seed = chacha20_poly1305_decrypt(chacha_key, chacha_nonce, int_to_bytes_be(chacha_seed_int, k))
    enc_key, auth_key, _ = derive_keys(seed, b"rsa_hybrid")
    temp_payload = {
        "inn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed_bytes],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
        "nonce": [int(b) for b in nonce],
        "timestamp": timestamp,
        "chacha_seed": [int(b) for b in chacha_seed]
    }
    payload_str = json.dumps(temp_payload, sort_keys=True)
    computed_hmac = hmac.new(auth_key, payload_str.encode(), hashlib.sha256).hexdigest()
    if hmac_value != computed_hmac:
        raise ValueError("HMAC verification failed")
    inn = NonLinearINN(block_size=int(metadata["block_size"]), n_layers=int(metadata["n_layers"]), prime=int(metadata["prime"]), seed=enc_key)
    decrypted_blocks = [inn.reverse(blk) for blk in enc_blocks]
    flat = np.concatenate(decrypted_blocks).astype(np.uint8)
    mode = metadata.get("mode", "text")
    try:
        if mode == "text":
            unpadded = pkcs7_unpad(flat)
            text = devectorize_text(unpadded)
            print("Decrypted (text):")
            print(text)
            return text
        else:
            bytes_per_number = int(metadata.get("bytes_per_number", 4))
            nums = [int.from_bytes(blk.tobytes()[-bytes_per_number:], "big") for blk in decrypted_blocks]
            print("Decrypted (numeric list):")
            print(nums)
            return nums
    except ValueError as e:
        print("Decryption failed:", e)
        raise

# -----------------------------
# Paillier Homomorphic Operations
# -----------------------------
def homomorphic_add_files(f1: str, f2: str, paillier_pubfile: str, out_file: str, binary: bool = False):
    with open(paillier_pubfile, "rb") as f:
        public_key = pickle.load(f)
    with open(f1, "rb") as f:
        ct1 = pickle.load(f)
    with open(f2, "rb") as f:
        ct2 = pickle.load(f)
    result = paillier_homomorphic_add(ct1, ct2, public_key)
    if binary:
        if not out_file.endswith(".bin"):
            out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
        with open(out_file, "wb") as f:
            pickle.dump(result, f)
    else:
        with open(out_file, "w") as f:
            json.dump([c.ciphertext() for c in result], f)
    print(f"Homomorphic sum saved to {out_file}")

# -----------------------------
# CLI Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="VEINN CLI (v3 Hybrid)")
    subparsers = parser.add_subparsers(dest="command")

    # Keystore
    keystore_parser = subparsers.add_parser("create_keystore", help="Create encrypted keystore")
    keystore_parser.add_argument("--passphrase", required=True)
    keystore_parser.add_argument("--keystore_file", default="keystore.json")

    # RSA key generation
    rsa_parser = subparsers.add_parser("generate_rsa", help="Generate RSA keypair")
    rsa_parser.add_argument("--bits", type=int, default=2048)
    rsa_parser.add_argument("--pubfile", default="rsa_pub.json")
    rsa_parser.add_argument("--privfile", default="rsa_priv.json")
    rsa_parser.add_argument("--keystore")
    rsa_parser.add_argument("--passphrase")
    rsa_parser.add_argument("--key_name")

    # Paillier key generation
    paillier_parser = subparsers.add_parser("generate_paillier", help="Generate Paillier keypair")
    paillier_parser.add_argument("--bits", type=int, default=2048)
    paillier_parser.add_argument("--pubfile", default="paillier_pub.bin")
    paillier_parser.add_argument("--privfile", default="paillier_priv.bin")
    paillier_parser.add_argument("--keystore")
    paillier_parser.add_argument("--passphrase")
    paillier_parser.add_argument("--key_name")

    # Public INN encryption
    pub_enc_parser = subparsers.add_parser("public_encrypt", help="Encrypt with public INN")
    pub_enc_parser.add_argument("--seed")
    pub_enc_parser.add_argument("--message")
    pub_enc_parser.add_argument("--numbers", nargs="+", type=int)
    pub_enc_parser.add_argument("--mode", default="text", choices=["text", "numeric"])
    pub_enc_parser.add_argument("--bytes_per_number", type=int, default=4)
    pub_enc_parser.add_argument("--block_size", type=int, default=16)
    pub_enc_parser.add_argument("--n_layers", type=int, default=8)
    pub_enc_parser.add_argument("--prime", type=int)
    pub_enc_parser.add_argument("--out_file", default="enc_pub_inn.json")
    pub_enc_parser.add_argument("--binary", action="store_true")
    pub_enc_parser.add_argument("--nonce")
    pub_enc_parser.add_argument("--keystore")
    pub_enc_parser.add_argument("--passphrase")
    pub_enc_parser.add_argument("--key_name")

    # Public INN decryption
    pub_dec_parser = subparsers.add_parser("public_decrypt", help="Decrypt with public INN")
    pub_dec_parser.add_argument("--seed")
    pub_dec_parser.add_argument("--keystore")
    pub_dec_parser.add_argument("--passphrase")
    pub_dec_parser.add_argument("--key_name")
    pub_dec_parser.add_argument("--enc_file", default="enc_pub_inn.json")
    pub_dec_parser.add_argument("--validity_window", type=int, default=3600)

    # RSA encryption
    rsa_enc_parser = subparsers.add_parser("rsa_encrypt", help="Encrypt with RSA public key")
    rsa_enc_parser.add_argument("--pubfile", default="rsa_pub.json")
    rsa_enc_parser.add_argument("--in_path")
    rsa_enc_parser.add_argument("--message")
    rsa_enc_parser.add_argument("--numbers", nargs="+", type=int)
    rsa_enc_parser.add_argument("--mode", default="text", choices=["text", "numeric"])
    rsa_enc_parser.add_argument("--bytes_per_number", type=int, default=4)
    rsa_enc_parser.add_argument("--block_size", type=int, default=16)
    rsa_enc_parser.add_argument("--n_layers", type=int, default=8)
    rsa_enc_parser.add_argument("--prime", type=int)
    rsa_enc_parser.add_argument("--seed_len", type=int, default=32)
    rsa_enc_parser.add_argument("--out_file", default="enc_pub.json")
    rsa_enc_parser.add_argument("--binary", action="store_true")
    rsa_enc_parser.add_argument("--nonce")

    # RSA decryption
    rsa_dec_parser = subparsers.add_parser("rsa_decrypt", help="Decrypt with RSA private key")
    rsa_dec_parser.add_argument("--privfile", default="rsa_priv.json")
    rsa_dec_parser.add_argument("--keystore")
    rsa_dec_parser.add_argument("--passphrase")
    rsa_dec_parser.add_argument("--key_name")
    rsa_dec_parser.add_argument("--enc_file", default="enc_pub.json")
    rsa_dec_parser.add_argument("--validity_window", type=int, default=3600)

    # Paillier encryption
    paillier_enc_parser = subparsers.add_parser("paillier_encrypt", help="Encrypt numbers with Paillier")
    paillier_enc_parser.add_argument("--pubfile", default="paillier_pub.bin")
    paillier_enc_parser.add_argument("--numbers", nargs="+", type=int, required=True)
    paillier_enc_parser.add_argument("--out_file", default="paillier_enc.bin")
    paillier_enc_parser.add_argument("--binary", action="store_true")

    # Paillier decryption
    paillier_dec_parser = subparsers.add_parser("paillier_decrypt", help="Decrypt with Paillier private key")
    paillier_dec_parser.add_argument("--privfile", default="paillier_priv.bin")
    paillier_dec_parser.add_argument("--keystore")
    paillier_dec_parser.add_argument("--passphrase")
    paillier_dec_parser.add_argument("--key_name")
    paillier_dec_parser.add_argument("--enc_file", default="paillier_enc.bin")

    # Homomorphic addition
    hom_add_parser = subparsers.add_parser("hom_add", help="Paillier homomorphic addition")
    hom_add_parser.add_argument("--file1", required=True)
    hom_add_parser.add_argument("--file2", required=True)
    hom_add_parser.add_argument("--paillier_pubfile", default="paillier_pub.bin")
    hom_add_parser.add_argument("--out_file", default="hom_add.bin")
    hom_add_parser.add_argument("--binary", action="store_true")

    args = parser.parse_args()

    try:
        if args.command == "create_keystore":
            create_keystore(args.passphrase, args.keystore_file)
            print(f"Keystore created: {args.keystore_file}")
        elif args.command == "generate_rsa":
            generate_rsa_cli(args.bits, args.pubfile, args.privfile, args.keystore, args.passphrase, args.key_name)
        elif args.command == "generate_paillier":
            public_key, private_key = generate_paillier_keypair(args.bits)
            if args.keystore and args.passphrase and args.key_name:
                store_key_in_keystore(args.passphrase, args.key_name, {"private_key": pickle.dumps(private_key)}, args.keystore)
                print(f"Private key stored in keystore: {args.keystore} (key: {args.key_name})")
            else:
                with open(args.privfile, "wb") as f:
                    pickle.dump(private_key, f)
                print(f"Paillier private key -> {args.privfile} (KEEP SECRET)")
            with open(args.pubfile, "wb") as f:
                pickle.dump(public_key, f)
            print(f"Paillier public key -> {args.pubfile}")
        elif args.command == "public_encrypt":
            if args.keystore and args.passphrase and args.key_name:
                seed_data = retrieve_key_from_keystore(args.passphrase, args.key_name, args.keystore)
                args.seed = seed_data["seed"]
            nonce = b64decode(args.nonce) if args.nonce else None
            out_file = encrypt_with_public_inn(args.seed, args.message, args.numbers, args.block_size, args.n_layers, args.prime, args.out_file, args.mode, args.bytes_per_number, args.binary, nonce)
            if args.keystore and args.passphrase and args.key_name:
                store_key_in_keystore(args.passphrase, args.key_name, {"seed": args.seed}, args.keystore)
        elif args.command == "public_decrypt":
            if args.keystore and args.passphrase and args.key_name:
                seed_data = retrieve_key_from_keystore(args.passphrase, args.key_name, args.keystore)
                args.seed = seed_data["seed"]
            decrypt_with_public_inn(args.seed, args.enc_file, args.validity_window)
        elif args.command == "rsa_encrypt":
            nonce = b64decode(args.nonce) if args.nonce else None
            encrypt_with_pub(args.pubfile, args.in_path, args.message, args.numbers, args.mode, args.block_size, args.n_layers, args.prime, args.seed_len, args.out_file, args.binary, nonce, args.bytes_per_number)
        elif args.command == "rsa_decrypt":
            decrypt_with_priv(args.keystore, args.privfile, args.enc_file, args.passphrase, args.key_name, args.validity_window)
        elif args.command == "paillier_encrypt":
            with open(args.pubfile, "rb") as f:
                public_key = pickle.load(f)
            ciphertexts = paillier_encrypt(public_key, args.numbers)
            if args.binary:
                if not args.out_file.endswith(".bin"):
                    out_file = args.out_file.replace(".json", ".bin") if args.out_file.endswith(".json") else args.out_file + ".bin"
                with open(out_file, "wb") as f:
                    pickle.dump(ciphertexts, f)
            else:
                with open(args.out_file, "w") as f:
                    json.dump([c.ciphertext() for c in ciphertexts], f)
            print(f"Paillier encrypted numbers saved to {args.out_file}")
        elif args.command == "paillier_decrypt":
            if args.keystore and args.passphrase and args.key_name:
                priv_data = retrieve_key_from_keystore(args.passphrase, args.key_name, args.keystore)
                private_key = pickle.loads(priv_data["private_key"])
            else:
                with open(args.privfile, "rb") as f:
                    private_key = pickle.load(f)
            with open(args.enc_file, "rb") as f:
                ciphertexts = pickle.load(f)
            numbers = paillier_decrypt(private_key, ciphertexts)
            print("Decrypted numbers:")
            print(numbers)
        elif args.command == "hom_add":
            homomorphic_add_files(args.file1, args.file2, args.paillier_pubfile, args.out_file, args.binary)
        else:
            print("VEINN CLI (v3 Hybrid) — RSA + Non-linear INN + ChaCha20-Poly1305 + HMAC + Paillier")
            while True:
                print("")
                print("1) Create encrypted keystore")
                print("2) Generate RSA keypair (public/private)")
                print("3) Generate Paillier keypair")
                print("4) Encrypt with recipient public key (RSA + INN + ChaCha20)")
                print("5) Decrypt with private key (RSA + INN + ChaCha20)")
                print("6) Encrypt with public INN (seed-based)")
                print("7) Decrypt with public INN (seed-based)")
                print("8) Paillier encrypt numbers")
                print("9) Paillier decrypt numbers")
                print("10) Homomorphic add (Paillier)")
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
                        bits = int(input("Paillier key size in bits (default 2048): ").strip() or 2048)
                        pubfile = input("Public key filename (default paillier_pub.bin): ").strip() or "paillier_pub.bin"
                        use_keystore = input("Store private key in keystore? (y/n): ").strip().lower() == "y"
                        privfile, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("Private key filename (default paillier_priv.bin): ").strip() or "paillier_priv.bin"
                        public_key, private_key = generate_paillier_keypair(bits)
                        if use_keystore:
                            store_key_in_keystore(passphrase, key_name, {"private_key": pickle.dumps(private_key)}, keystore)
                            print(f"Private key stored in keystore: {keystore} (key: {key_name})")
                        else:
                            with open(privfile, "wb") as f:
                                pickle.dump(private_key, f)
                            print(f"Paillier private key -> {privfile} (KEEP SECRET)")
                        with open(pubfile, "wb") as f:
                            pickle.dump(public_key, f)
                        print(f"Paillier public key -> {pubfile}")
                    elif choice == "4":
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
                        n_layers = int(input("Number of layers (default 8): ").strip() or 8)
                        prime = int(input("Prime modulus (default 256-bit prime): ").strip() or 0) or None
                        seed_len = int(input("Seed length (default 32): ").strip() or 32)
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
                        nonce = b64decode(nonce_str) if nonce_str else None
                        bytes_per_number = None
                        if mode == "numeric":
                            bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
                        encrypt_with_pub(pubfile, in_path=inpath, mode=mode, block_size=block_size, n_layers=n_layers, prime=prime, seed_len=seed_len, binary=binary, nonce=nonce, bytes_per_number=bytes_per_number)
                    elif choice == "5":
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
                    elif choice == "6":
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
                            numbers = [int(x) for x in content.replace(",", " ").split() if x]
                            bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
                        block_size = int(input("Block size (even, default 16): ").strip() or 16)
                        if block_size % 2 != 0:
                            print("Block size must be even")
                            continue
                        n_layers = int(input("Number of layers (default 8): ").strip() or 8)
                        prime = int(input("Prime modulus (default 256-bit prime): ").strip() or 0) or None
                        out_file = input("Output encrypted filename (default enc_pub_inn.json): ").strip() or "enc_pub_inn.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        nonce_str = input("Custom nonce (base64, blank for random): ").strip() or None
                        nonce = b64decode(nonce_str) if nonce_str else None
                        out_file = encrypt_with_public_inn(seed_input, message, numbers, block_size, n_layers, prime, out_file, mode, bytes_per_number, binary, nonce)
                        if use_keystore:
                            store_key_in_keystore(passphrase, key_name, {"seed": seed_input}, keystore)
                    elif choice == "7":
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
                    elif choice == "8":
                        pubfile = input("Paillier public key file (default paillier_pub.bin): ").strip() or "paillier_pub.bin"
                        if not os.path.exists(pubfile):
                            print("Public key not found. Generate Paillier keys first.")
                            continue
                        content = input("Enter numbers (comma or whitespace separated): ").strip()
                        numbers = [int(x) for x in content.replace(",", " ").split() if x]
                        out_file = input("Output encrypted filename (default paillier_enc.bin): ").strip() or "paillier_enc.bin"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        with open(pubfile, "rb") as f:
                            public_key = pickle.load(f)
                        ciphertexts = paillier_encrypt(public_key, numbers)
                        if binary:
                            if not out_file.endswith(".bin"):
                                out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
                            with open(out_file, "wb") as f:
                                pickle.dump(ciphertexts, f)
                        else:
                            with open(out_file, "w") as f:
                                json.dump([c.ciphertext() for c in ciphertexts], f)
                        print(f"Paillier encrypted numbers saved to {out_file}")
                    elif choice == "9":
                        use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() == "y"
                        privfile, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("Paillier private key file (default paillier_priv.bin): ").strip() or "paillier_priv.bin"
                        enc_file = input("Encrypted file to decrypt (default paillier_enc.bin): ").strip() or "paillier_enc.bin"
                        if not os.path.exists(enc_file):
                            print("Encrypted file not found.")
                            continue
                        if use_keystore:
                            priv_data = retrieve_key_from_keystore(passphrase, key_name, keystore)
                            private_key = pickle.loads(priv_data["private_key"])
                        else:
                            with open(privfile, "rb") as f:
                                private_key = pickle.load(f)
                        with open(enc_file, "rb") as f:
                            ciphertexts = pickle.load(f)
                        numbers = paillier_decrypt(private_key, ciphertexts)
                        print("Decrypted numbers:")
                        print(numbers)
                    elif choice == "10":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        pubfile = input("Paillier public key file (default paillier_pub.bin): ").strip() or "paillier_pub.bin"
                        out = input("Output filename (default hom_add.bin): ").strip() or "hom_add.bin"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_add_files(f1, f2, pubfile, out, binary)
                    else:
                        print("Invalid choice")
                except Exception as e:
                    print("ERROR:", e)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()