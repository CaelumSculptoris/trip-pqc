#!/usr/bin/env python3
"""
Lattice-based VEINN CLI with CKKS scheme
- Generate LWE keys
- Encrypt with recipient public key
- Decrypt with private key
- Homomorphic ops on ciphertext JSON/binary files (add, sub, scalar mul, avg, elementwise mul for dot)
"""
import os
import sys
import json
import math
import secrets
import numpy as np
import argparse
import pickle
import time
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from numpy.polynomial.polynomial import Polynomial

# Constants
N = 64
Q = 16777217
SIGMA = 3.2
SCALE = 2**30
M = 128
W = 4096

# CKKS Encoder
class CKKSEncoder:
    def __init__(self, M: int, scale: float):
        self.xi = np.exp(2 * np.pi * 1j / M)
        self.M = M
        self.scale = scale
        self.create_sigma_R_basis()

    def vandermonde(self, xi, M):
        N = M // 2
        matrix = []
        for i in range(N):
            root = xi ** (2 * i + 1)
            row = [root ** j for j in range(N)]
            matrix.append(row)
        return np.array(matrix)

    def create_sigma_R_basis(self):
        self.sigma_R_basis = np.array(self.vandermonde(self.xi, self.M)).T

    def sigma_inverse(self, b):
        A = self.vandermonde(self.xi, self.M)
        coeffs = np.linalg.solve(A, b)
        p = Polynomial(coeffs)
        return p

    def sigma(self, p):
        N = self.M // 2
        outputs = []
        for i in range(N):
            root = self.xi ** (2 * i + 1)
            output = p(root)
            outputs.append(output)
        return np.array(outputs)

    def pi(self, z):
        N = self.M // 4
        return z[:N]

    def pi_inverse(self, z):
        z_conj = np.conjugate(z[::-1])
        return np.concatenate([z, z_conj])

    def compute_basis_coordinates(self, z):
        output = np.array([np.real(np.vdot(z, b) / np.vdot(b, b)) for b in self.sigma_R_basis])
        return output

    def round_coordinates(self, coordinates):
        return coordinates - np.floor(coordinates)

    def coordinate_wise_random_rounding(self, coordinates):
        r = self.round_coordinates(coordinates)
        f = np.array([np.random.choice([c, c-1], 1, p=[1-c, c]) for c in r]).reshape(-1)
        rounded = coordinates - f
        rounded = np.round(rounded, decimals=0).astype(int)
        return rounded

    def sigma_R_discretization(self, z):
        coordinates = self.compute_basis_coordinates(z)
        rounded_coordinates = self.coordinate_wise_random_rounding(coordinates)
        y = np.matmul(self.sigma_R_basis.T, rounded_coordinates)
        return y

    def encode(self, z):
        pi_z = self.pi_inverse(z)
        scaled_pi_z = self.scale * pi_z
        rounded_scale_pi_zi = self.sigma_R_discretization(scaled_pi_z)
        p = self.sigma_inverse(rounded_scale_pi_zi)
        coef = np.round(np.real(p.coef)).astype(int)
        p = Polynomial(coef)
        return p

    def decode(self, p, power=1):
        rescaled_p = p / (self.scale ** power)
        z = self.sigma(rescaled_p)
        pi_z = self.pi(z)
        return pi_z

# Polynomial class
class Poly:
    def __init__(self, coeffs, n=N, q=Q):
        self.n = n
        self.q = q
        self.coeffs = np.array(coeffs, dtype=object) % q

    @classmethod
    def random(cls, n=N, q=Q):
        return cls(np.random.randint(0, q, n), n, q)

    @classmethod
    def from_list(cls, lst, n=N, q=Q):
        return cls(lst, n, q)

    def add(self, other):
        return Poly(self.coeffs + other.coeffs, self.n, self.q)

    def sub(self, other):
        return Poly(self.coeffs - other.coeffs, self.n, self.q)

    def neg(self):
        return Poly((-self.coeffs % self.q), self.n, self.q)

    def mul_scalar(self, scal):
        return Poly(self.coeffs * scal, self.n, self.q)

    def mul(self, other):
        c = np.zeros(2 * self.n, dtype=object)
        for i in range(self.n):
            for j in range(other.n):
                c[i + j] += self.coeffs[i] * other.coeffs[j]
        for i in range(self.n):
            c[i] -= c[i + self.n]
        coeffs = c[:self.n] % self.q
        return Poly(coeffs, self.n, self.q)

    def decompose(self, i, w):
        pow_w = w ** i
        coeffs_i = (self.coeffs // pow_w) % w
        return Poly(coeffs_i, self.n, self.q)

    def to_list(self):
        return [int(c) for c in self.coeffs]

# Sample small polynomial
def sample_poly_gaussian(n=N, q=Q, sigma=SIGMA):
    coeffs = np.round(np.random.normal(0, sigma, n)).astype(int)
    return Poly(coeffs, n, q)

# Key management (Encrypted Keystore)
def create_keystore(passphrase: str, keystore_file: str = "keystore.json"):
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

# Utilities
def int_to_bytes_be(x: int, length: int) -> bytes:
    return int.to_bytes(x, length, byteorder="big", signed=False)

def bytes_be_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)

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
    if 0 < pad_len <= len(vec) and np.all(vec[-pad_len:] == pad_len):
        return vec[:-pad_len]
    raise ValueError("Invalid PKCS7 padding")

# Generate CKKS keypair
def generate_ckks_keypair(n=N, q=Q):
    s = sample_poly_gaussian(n, q)
    a = Poly.random(n, q)
    e = sample_poly_gaussian(n, q)
    b = a.mul(s).add(e)
    # Generate evk
    evk = []
    w = W
    l = math.ceil(math.log(q, w))
    for i in range(l):
        a_prime = Poly.random(n, q)
        e_prime = sample_poly_gaussian(n, q)
        s2_wi = s.mul(s).mul_scalar(w ** i)
        evk0 = a_prime.mul(s).add(e_prime).neg().add(s2_wi)
        evk1 = a_prime
        evk.append({"evk0": evk0, "evk1": evk1})
    public_key = {"a": {"coeffs": a.to_list()}, "b": {"coeffs": b.to_list()}, "evk": [{"evk0": {"coeffs": e["evk0"].to_list()}, "evk1": {"coeffs": e["evk1"].to_list()}} for e in evk], "n": n, "q": q, "w": w, "scale": SCALE, "m": M}
    private_key = {"s": {"coeffs": s.to_list()}, "n": n, "q": q}
    return public_key, private_key

# Serialization helpers for ciphertexts (JSON and binary)
def write_ciphertext_json(path: str, enc_blocks: list, metadata: dict):
    encrypted = []
    for blk in enc_blocks:
        encrypted.append({
            "c1": blk["c1"].to_list(),
            "c2": blk["c2"].to_list()
        })
    payload = {
        "metadata": metadata,
        "encrypted": encrypted
    }
    with open(path, "w") as f:
        json.dump(payload, f)

def write_ciphertext_binary(path: str, enc_blocks: list, metadata: dict):
    encrypted = []
    for blk in enc_blocks:
        encrypted.append({
            "c1": blk["c1"].to_list(),
            "c2": blk["c2"].to_list()
        })
    payload = {
        "metadata": metadata,
        "encrypted": encrypted
    }
    with open(path, "wb") as f:
        pickle.dump(payload, f)

def read_ciphertext(path: str):
    if path.endswith(".json"):
        with open(path, "r") as f:
            payload = json.load(f)
        metadata = payload["metadata"]
        enc_blocks = [{"c1": Poly.from_list(eb["c1"], metadata["n"], metadata["q"]), "c2": Poly.from_list(eb["c2"], metadata["n"], metadata["q"])} for eb in payload["encrypted"]]
    elif path.endswith(".bin"):
        with open(path, "rb") as f:
            payload = pickle.load(f)
        metadata = payload["metadata"]
        enc_blocks = [{"c1": Poly.from_list(eb["c1"], metadata["n"], metadata["q"]), "c2": Poly.from_list(eb["c2"], metadata["n"], metadata["q"])} for eb in payload["encrypted"]]
    else:
        raise ValueError("Unsupported file format: must be .json or .bin")
    return metadata, enc_blocks

# Encryption
def encrypt_with_pub_ckks(pubfile: str, message: str = None, numbers: list = None, mode: str = "text", out_file: str = None, binary: bool = False, bytes_per_number: int = 4):
    if not os.path.exists(pubfile):
        raise FileNotFoundError("Public key file not found")
    with open(pubfile, "r") as f:
        pub = json.load(f)
    a = Poly.from_list(pub["a"]["coeffs"], pub["n"], pub["q"])
    b = Poly.from_list(pub["b"]["coeffs"], pub["n"], pub["q"])
    n = pub["n"]
    q = pub["q"]
    scale = pub["scale"]
    m = pub["m"]
    encoder = CKKSEncoder(m, scale)
    slots = n // 2
    if mode == "text":
        if message is None:
            message = input("Message to encrypt: ")
        data = vectorize_text(message)
        num_blocks = math.ceil(len(data) / slots)
        padded_len = num_blocks * slots
        padded = pkcs7_pad(data, padded_len)
        blocks = [padded[i * slots : (i + 1) * slots] for i in range(num_blocks)]
        data_len = len(data)
    elif mode == "numeric":
        if numbers is None:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
            numbers = [int(x) for x in raw_nums]
        num_blocks = math.ceil(len(numbers) / slots)
        padded_len = num_blocks * slots
        padded_numbers = numbers + [0] * (padded_len - len(numbers))
        blocks = [padded_numbers[i * slots : (i + 1) * slots] for i in range(num_blocks)]
        data_len = len(numbers)
    enc_blocks = []
    for block in blocks:
        z = np.array(block, dtype=float)
        m_poly = encoder.encode(z)
        coef = np.round(np.real(m_poly.coef)).astype(int)
        if len(coef) < n:
            coef = np.pad(coef, (0, n - len(coef)))
        m = pub["m"]
        r = sample_poly_gaussian(n, q)
        e1 = sample_poly_gaussian(n, q)
        e2 = sample_poly_gaussian(n, q)
        c1 = a.mul(r).add(e1)
        c2 = b.mul(r).add(e2).add(m)
        enc_blocks.append({"c1": c1, "c2": c2})
    metadata = {
        "n": n,
        "q": q,
        "scale": scale,
        "scale_power": 1,
        "m": m,
        "mode": mode,
        "slots": slots,
        "data_len": data_len
    }
    if mode == "numeric":
        metadata["bytes_per_number"] = bytes_per_number
    if out_file is None:
        out_file = input("Output encrypted filename (default enc_pub.json): ").strip() or "enc_pub.json"
    if binary and not out_file.endswith(".bin"):
        out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
    if binary:
        write_ciphertext_binary(out_file, enc_blocks, metadata)
    else:
        write_ciphertext_json(out_file, enc_blocks, metadata)
    print(f"Message encrypted with CKKS -> {out_file}")
    return out_file

# Decryption
def decrypt_with_priv_ckks(keysfile: str, privfile: str, enc_file: str, passphrase: str = None, key_name: str = None):
    if keysfile or (passphrase and key_name):
        if not keysfile:
            keysfile = "keystore.json"
        priv = retrieve_key_from_keystore(passphrase, key_name, keysfile)
    else:
        if not os.path.exists(privfile):
            raise FileNotFoundError("Private key file not found")
        with open(privfile, "r") as f:
            priv = json.load(f)
    s = Poly.from_list(priv["s"]["coeffs"], priv["n"], priv["q"])
    metadata, enc_blocks = read_ciphertext(enc_file)
    n = metadata["n"]
    q = metadata["q"]
    scale = metadata["scale"]
    m = metadata["m"]
    encoder = CKKSEncoder(m, scale)
    scale_power = metadata.get("scale_power", 1)
    dec_values = []
    for eb in enc_blocks:
        c1 = eb["c1"]
        c2 = eb["c2"]
        approx_poly = c2.sub(c1.mul(s))
        approx = Polynomial(approx_poly.coeffs)
        z = encoder.decode(approx, scale_power)
        values = np.round(np.real(z)).astype(int)
        dec_values.append(values)
    flat = np.concatenate(dec_values)
    mode = metadata.get("mode", "text")
    data_len = metadata.get("data_len", len(flat))
    flat = flat[:data_len]
    try:
        if mode == "text":
            unpadded = pkcs7_unpad(flat)
            text = ''.join(chr(int(c)) for c in unpadded)
            print("Decrypted (text):")
            print(text)
            return text
        elif mode == "numeric":
            nums = list(flat)
            print("Decrypted (numeric list):")
            print(nums)
            return nums
        else:
            raise ValueError("Unsupported mode in metadata")
    except ValueError as e:
        print("Decryption failed:", e)
        raise

# Homomorphic multiplication
def hom_mul(ct1, ct2, evk, w, q, n):
    d0 = ct1["c2"].mul(ct2["c2"])
    d1 = ct1["c2"].mul(ct2["c1"]).add(ct1["c1"].mul(ct2["c2"]))
    d2 = ct1["c1"].mul(ct2["c1"])
    new_c0 = d0
    new_c1 = d1
    l = len(evk)
    for i in range(l):
        d2_i = d2.decompose(i, w)
        new_c0 = new_c0.add(d2_i.mul(evk[i]["evk0"]))
        new_c1 = new_c1.add(d2_i.mul(evk[i]["evk1"]))
    return {"c1": new_c1, "c2": new_c0}

# Homomorphic helpers
def _load_encrypted_file(enc_file: str):
    metadata, enc_blocks = read_ciphertext(enc_file)
    return enc_blocks, metadata

def _write_encrypted_payload(out_file: str, enc_blocks, meta, binary: bool = False):
    if binary:
        if not out_file.endswith(".bin"):
            out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
        write_ciphertext_binary(out_file, enc_blocks, meta)
    else:
        write_ciphertext_json(out_file, enc_blocks, meta)

def homomorphic_add_files_ckks(f1: str, f2: str, out_file: str, binary: bool = False):
    enc1, meta1 = _load_encrypted_file(f1)
    enc2, meta2 = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    summed = []
    for a, b in zip(enc1, enc2):
        c1 = a["c1"].add(b["c1"])
        c2 = a["c2"].add(b["c2"])
        summed.append({"c1": c1, "c2": c2})
    meta = meta1.copy()
    meta["scale_power"] = max(meta1["scale_power"], meta2["scale_power"])
    _write_encrypted_payload(out_file, summed, meta, binary)
    print(f"Homomorphic sum saved to {out_file}")

def homomorphic_sub_files_ckks(f1: str, f2: str, out_file: str, binary: bool = False):
    enc1, meta1 = _load_encrypted_file(f1)
    enc2, meta2 = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    diff = []
    for a, b in zip(enc1, enc2):
        c1 = a["c1"].sub(b["c1"])
        c2 = a["c2"].sub(b["c2"])
        diff.append({"c1": c1, "c2": c2})
    meta = meta1.copy()
    meta["scale_power"] = max(meta1["scale_power"], meta2["scale_power"])
    _write_encrypted_payload(out_file, diff, meta, binary)
    print(f"Homomorphic difference saved to {out_file}")

def homomorphic_scalar_mul_file_ckks(f: str, scalar: int, out_file: str, binary: bool = False):
    enc, meta = _load_encrypted_file(f)
    prod = []
    for blk in enc:
        c1 = blk["c1"].mul_scalar(scalar)
        c2 = blk["c2"].mul_scalar(scalar)
        prod.append({"c1": c1, "c2": c2})
    _write_encrypted_payload(out_file, prod, meta, binary)
    print(f"Homomorphic scalar multiplication saved to {out_file}")

def homomorphic_average_files_ckks(files: list, out_file: str, binary: bool = False):
    encs = []
    metas = []
    for f in files:
        enc_blocks, meta = _load_encrypted_file(f)
        encs.append(enc_blocks)
        metas.append(meta)
    if not all(m == metas[0] for m in metas):
        raise ValueError("All encrypted files must have identical metadata")
    meta = metas[0]
    num = len(encs)
    length = len(encs[0])
    max_power = max(m["scale_power"] for m in metas)
    avg_blocks = []
    for i in range(length):
        s_c1_coeffs = np.zeros(meta["n"], dtype=object)
        s_c2_coeffs = np.zeros(meta["n"], dtype=object)
        for enc in encs:
            s_c1_coeffs += enc[i]["c1"].coeffs
            s_c2_coeffs += enc[i]["c2"].coeffs
        avg_c1_coeffs = (s_c1_coeffs // num) % meta["q"]
        avg_c2_coeffs = (s_c2_coeffs // num) % meta["q"]
        avg_c1 = Poly(avg_c1_coeffs, meta["n"], meta["q"])
        avg_c2 = Poly(avg_c2_coeffs, meta["n"], meta["q"])
        avg_blocks.append({"c1": avg_c1, "c2": avg_c2})
    meta = meta.copy()
    meta["scale_power"] = max_power
    _write_encrypted_payload(out_file, avg_blocks, meta, binary)
    print(f"Homomorphic average saved to {out_file}")

def homomorphic_dot_files_ckks(f1: str, f2: str, out_file: str, binary: bool = False, pubfile: str = "lwe_pub.json"):
    enc1, meta1 = _load_encrypted_file(f1)
    enc2, meta2 = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    with open(pubfile, "r") as f:
        pub = json.load(f)
    evk = [{"evk0": Poly.from_list(e["evk0"]["coeffs"], pub["n"], pub["q"]), "evk1": Poly.from_list(e["evk1"]["coeffs"], pub["n"], pub["q"])} for e in pub["evk"]]
    w = pub["w"]
    q = meta1["q"]
    n = meta1["n"]
    enc_mul = []
    for a, b in zip(enc1, enc2):
        ct_mul = hom_mul(a, b, evk, w, q, n)
        enc_mul.append(ct_mul)
    meta = meta1.copy()
    meta["scale_power"] = meta1["scale_power"] + meta2["scale_power"]
    _write_encrypted_payload(out_file, enc_mul, meta, binary)
    print(f"Homomorphic elementwise multiplication saved to {out_file} (decrypt and sum all values to get the dot product)")

# CLI for key generation
def generate_ckks_cli(pubfile: str = "ckks_pub.json", privfile: str = "ckks_priv.json", keystore: str = None, passphrase: str = None, key_name: str = None):
    print("Generating CKKS keypair...")
    pub, priv = generate_ckks_keypair()
    if keystore and passphrase and key_name:
        store_key_in_keystore(passphrase, key_name, priv, keystore)
        print(f"Private key stored in keystore: {keystore} (key: {key_name})")
    else:
        with open(privfile, "w") as f:
            json.dump(priv, f)
        print(f"CKKS private key -> {privfile} (KEEP SECRET)")
    with open(pubfile, "w") as f:
        json.dump(pub, f)
    print(f"CKKS public key -> {pubfile}")
    return pubfile, privfile

# Main CLI
def main():
    parser = argparse.ArgumentParser(description="CKKS VEINN CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Keystore
    keystore_parser = subparsers.add_parser("create_keystore", help="Create a new encrypted keystore")
    keystore_parser.add_argument("--passphrase", required=True, help="Keystore passphrase")
    keystore_parser.add_argument("--keystore_file", default="keystore.json", help="Keystore file path")

    # Generate CKKS keypair
    ckks_parser = subparsers.add_parser("generate_ckks", help="Generate CKKS keypair")
    ckks_parser.add_argument("--pubfile", default="ckks_pub.json", help="Public key output file")
    ckks_parser.add_argument("--privfile", default="ckks_priv.json", help="Private key output file")
    ckks_parser.add_argument("--keystore", help="Store private key in keystore")
    ckks_parser.add_argument("--passphrase", help="Keystore passphrase")
    ckks_parser.add_argument("--key_name", help="Key name in keystore")

    # CKKS encrypt
    ckks_enc_parser = subparsers.add_parser("ckks_encrypt", help="Encrypt with CKKS public key")
    ckks_enc_parser.add_argument("--pubfile", default="ckks_pub.json", help="CKKS public key file")
    ckks_enc_parser.add_argument("--message", help="Message to encrypt (text mode)")
    ckks_enc_parser.add_argument("--numbers", nargs="+", type=int, help="Numbers to encrypt (numeric mode)")
    ckks_enc_parser.add_argument("--mode", default="text", choices=["text", "numeric"], help="Mode: text or numeric")
    ckks_enc_parser.add_argument("--bytes_per_number", type=int, default=4, help="Bytes per number (numeric mode)")
    ckks_enc_parser.add_argument("--out_file", default="enc_ckks.json", help="Output file")
    ckks_enc_parser.add_argument("--binary", action="store_true", help="Use binary output format")

    # CKKS decrypt
    ckks_dec_parser = subparsers.add_parser("ckks_decrypt", help="Decrypt with CKKS private key")
    ckks_dec_parser.add_argument("--privfile", default="ckks_priv.json", help="CKKS private key file")
    ckks_dec_parser.add_argument("--keystore", help="Retrieve private key from keystore")
    ckks_dec_parser.add_argument("--passphrase", help="Keystore passphrase")
    ckks_dec_parser.add_argument("--key_name", help="Key name in keystore")
    ckks_dec_parser.add_argument("--enc_file", default="enc_ckks.json", help="Encrypted file")

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

    hom_dot_parser = subparsers.add_parser("hom_dot", help="Homomorphic elementwise multiplication (for dot product components)")
    hom_dot_parser.add_argument("--file1", required=True, help="First encrypted file")
    hom_dot_parser.add_argument("--file2", required=True, help="Second encrypted file")
    hom_dot_parser.add_argument("--out_file", default="hom_dot.json", help="Output file")
    hom_dot_parser.add_argument("--binary", action="store_true", help="Use binary output format")
    hom_dot_parser.add_argument("--pubfile", default="ckks_pub.json", help="Public key file for relinearization")

    args = parser.parse_args()

    try:
        if args.command == "create_keystore":
            create_keystore(args.passphrase, args.keystore_file)
            print(f"Keystore created: {args.keystore_file}")
        elif args.command == "generate_ckks":
            pubfile, privfile = generate_ckks_cli(args.pubfile, args.privfile, args.keystore, args.passphrase, args.key_name)
        elif args.command == "ckks_encrypt":
            encrypt_with_pub_ckks(args.pubfile, args.message, args.numbers, args.mode, args.out_file, args.binary, args.bytes_per_number)
        elif args.command == "ckks_decrypt":
            decrypt_with_priv_ckks(args.keystore, args.privfile, args.enc_file, args.passphrase, args.key_name)
        elif args.command == "hom_add":
            homomorphic_add_files_ckks(args.file1, args.file2, args.out_file, args.binary)
        elif args.command == "hom_sub":
            homomorphic_sub_files_ckks(args.file1, args.file2, args.out_file, args.binary)
        elif args.command == "hom_scalar_mul":
            homomorphic_scalar_mul_file_ckks(args.file, args.scalar, args.out_file, args.binary)
        elif args.command == "hom_avg":
            homomorphic_average_files_ckks(args.files, args.out_file, args.binary)
        elif args.command == "hom_dot":
            homomorphic_dot_files_ckks(args.file1, args.file2, args.out_file, args.binary, args.pubfile)
        else:
            # Interactive mode
            print("CKKS VEINN CLI")
            while True:
                print("")
                print("1) Create encrypted keystore")
                print("2) Generate CKKS keypair (public/private)")
                print("3) Encrypt with public key")
                print("4) Decrypt with private key")
                print("5) Homomorphic add (file1, file2 -> out)")
                print("6) Homomorphic subtract (file1, file2 -> out)")
                print("7) Homomorphic scalar multiply (file, scalar -> out)")
                print("8) Homomorphic average (file1,file2,... -> out)")
                print("9) Homomorphic elementwise multiplication (file1, file2 -> out) (decrypt and sum for dot)")
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
                        pubfile = input("Public key filename (default ckks_pub.json): ").strip() or "ckks_pub.json"
                        use_keystore = input("Store private key in keystore? (y/n): ").strip().lower() == "y"
                        privfile, passphrase, key_name = None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("Private key filename (default ckks_priv.json): ").strip() or "ckks_priv.json"
                        generate_ckks_cli(pubfile, privfile, keystore, passphrase, key_name)
                    elif choice == "3":
                        pubfile = input("Public key file (default ckks_pub.json): ").strip() or "ckks_pub.json"
                        if not os.path.exists(pubfile):
                            print("Public key not found. Generate keys first.")
                            continue
                        mode = input("Mode: (t)ext or (n)umeric? [t]: ").strip().lower() or "text"
                        message = None
                        numbers = None
                        bytes_per_number = 4
                        if mode == "text":
                            message = input("Message to encrypt: ")
                        else:
                            content = input("Enter numbers (comma or whitespace separated): ").strip()
                            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
                            numbers = [int(x) for x in raw_nums]
                            bytes_per_number = int(input("Bytes per number (default 4): ").strip() or 4)
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        out_file = input("Output encrypted filename (default enc_ckks.json): ").strip() or "enc_ckks.json"
                        encrypt_with_pub_ckks(pubfile, message, numbers, mode, out_file, binary, bytes_per_number)
                    elif choice == "4":
                        use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() == "y"
                        privfile, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("Private key file (default ckks_priv.json): ").strip() or "ckks_priv.json"
                        encfile = input("Encrypted file to decrypt (default enc_ckks.json): ").strip() or "enc_ckks.json"
                        if not os.path.exists(encfile):
                            print("Encrypted file not found.")
                            continue
                        decrypt_with_priv_ckks(keystore, privfile, encfile, passphrase, key_name)
                    elif choice == "5":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_add.json): ").strip() or "hom_add.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_add_files_ckks(f1, f2, out, binary)
                    elif choice == "6":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_sub.json): ").strip() or "hom_sub.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_sub_files_ckks(f1, f2, out, binary)
                    elif choice == "7":
                        f = input("Encrypted file: ").strip()
                        scalar = int(input("Scalar (integer): ").strip())
                        out = input("Output filename (default hom_mul.json): ").strip() or "hom_mul.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_scalar_mul_file_ckks(f, scalar, out, binary)
                    elif choice == "8":
                        files = input("Comma-separated encrypted files to average: ").strip().split(",")
                        files = [s.strip() for s in files if s.strip()]
                        out = input("Output filename (default hom_avg.json): ").strip() or "hom_avg.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_average_files_ckks(files, out, binary)
                    elif choice == "9":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_dot.json): ").strip() or "hom_dot.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        pubfile = input("Public key file (default ckks_pub.json): ").strip() or "ckks_pub.json"
                        homomorphic_dot_files_ckks(f1, f2, out, binary, pubfile)
                    else:
                        print("Invalid choice")
                except Exception as e:
                    print("ERROR:", e)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()