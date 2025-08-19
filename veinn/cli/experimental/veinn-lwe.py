#!/usr/bin/env python3
"""
Lattice-based VEINN CLI
- Generate LWE keys
- Encrypt with recipient public key
- Decrypt with private key
- Homomorphic ops on ciphertext JSON/binary files (add, sub, scalar mul, avg, dot)
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

# Constants
N = 64
Q = 16777217
T = 256
DELTA = Q // T
BINOM_K = 4

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

    def mul_scalar(self, scal):
        return Poly(self.coeffs * scal, self.n, self.q)

    def mul(self, other):
        c = np.zeros(2 * self.n - 1, dtype=object)
        for i in range(self.n):
            for j in range(other.n):
                c[i + j] += self.coeffs[i] * other.coeffs[j]
        for i in range(self.n - 1, -1, -1):
            if i + self.n < len(c):
                c[i] -= c[i + self.n]
        coeffs = c[:self.n] % self.q
        return Poly(coeffs, self.n, self.q)

    def to_list(self):
        return [int(c) for c in self.coeffs]

# Sample small polynomial
def sample_small_poly(n=N, q=Q, k=BINOM_K):
    pos = np.sum(np.random.binomial(1, 0.5, (n, k)), axis=1)
    neg = np.sum(np.random.binomial(1, 0.5, (n, k)), axis=1)
    coeffs = pos - neg
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

# Generate LWE keypair
def generate_lwe_keypair(n=N, q=Q):
    s = sample_small_poly(n, q, BINOM_K)
    a = Poly.random(n, q)
    e = sample_small_poly(n, q, BINOM_K)
    b = a.mul(s).add(e)
    public_key = {"a": {"coeffs": a.to_list()}, "b": {"coeffs": b.to_list()}, "n": n, "q": q, "t": T}
    private_key = {"s": {"coeffs": s.to_list()}, "n": n, "q": q, "t": T}
    return public_key, private_key

# Serialization
def write_ciphertext_json(path: str, enc_blocks: list, metadata: dict):
    payload = {
        "metadata": metadata,
        "encrypted": [{"c1": blk["c1"].to_list(), "c2": blk["c2"].to_list()} for blk in enc_blocks]
    }
    with open(path, "w") as f:
        json.dump(payload, f)

def write_ciphertext_binary(path: str, enc_blocks: list, metadata: dict):
    payload = {
        "metadata": metadata,
        "encrypted": [{"c1": blk["c1"].to_list(), "c2": blk["c2"].to_list()} for blk in enc_blocks]
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
def encrypt_with_pub_lwe(pubfile: str, message: str = None, numbers: list = None, mode: str = "text", out_file: str = None, binary: bool = False, bytes_per_number: int = 4):
    if not os.path.exists(pubfile):
        raise FileNotFoundError("Public key file not found")
    with open(pubfile, "r") as f:
        pub = json.load(f)
    a = Poly.from_list(pub["a"]["coeffs"], pub["n"], pub["q"])
    b = Poly.from_list(pub["b"]["coeffs"], pub["n"], pub["q"])
    n = pub["n"]
    q = pub["q"]
    t = pub["t"]
    delta = q // t
    if mode == "text":
        if message is None:
            message = input("Message to encrypt: ")
        data = vectorize_text(message)
        padded = pkcs7_pad(data, n)
        data_len = len(data)
    elif mode == "numeric":
        if numbers is None:
            content = input("Enter numbers (comma or whitespace separated): ").strip()
            raw_nums = [s for s in content.replace(",", " ").split() if s != ""]
            numbers = [int(x) for x in raw_nums]
        data_bytes = b''.join(int_to_bytes_be(v, bytes_per_number) for v in numbers)
        data = np.frombuffer(data_bytes, dtype=np.uint8)
        pad_len = (n - len(data) % n) % n
        padded = np.concatenate((data, np.zeros(pad_len, dtype=np.uint8)))
        data_len = len(data)
    num_blocks = len(padded) // n
    enc_blocks = []
    for i in range(num_blocks):
        chunk = padded[i * n : (i + 1) * n]
        m_coeffs = chunk.astype(object)
        m = Poly(m_coeffs, n, q)
        r = sample_small_poly(n, q, BINOM_K)
        e1 = sample_small_poly(n, q, BINOM_K)
        e2 = sample_small_poly(n, q, BINOM_K)
        c1 = a.mul(r).add(e1)
        c2 = b.mul(r).add(e2).add(m.mul_scalar(delta))
        enc_blocks.append({"c1": c1, "c2": c2})
    metadata = {
        "n": n,
        "q": q,
        "t": t,
        "mode": mode
    }
    if mode == "text":
        metadata["data_len"] = data_len  # Not strictly needed for text due to pkcs7
    elif mode == "numeric":
        metadata["data_len"] = data_len
        metadata["bytes_per_number"] = bytes_per_number
        metadata["num_numbers"] = len(numbers)
    if out_file is None:
        out_file = input("Output encrypted filename (default enc_lwe.json): ").strip() or "enc_lwe.json"
    if binary and not out_file.endswith(".bin"):
        out_file = out_file.replace(".json", ".bin") if out_file.endswith(".json") else out_file + ".bin"
    if binary:
        write_ciphertext_binary(out_file, enc_blocks, metadata)
    else:
        write_ciphertext_json(out_file, enc_blocks, metadata)
    print(f"Message encrypted with lattice-based INN -> {out_file}")
    return out_file

# Decryption
def decrypt_with_priv_lwe(keysfile: str, privfile: str, enc_file: str, passphrase: str = None, key_name: str = None):
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
    t = metadata["t"]
    delta = q // t
    dec_chunks = []
    for eb in enc_blocks:
        c1 = eb["c1"]
        c2 = eb["c2"]
        approx = c2.sub(c1.mul(s)).coeffs
        m_coeffs = np.round(approx / delta).astype(int) % t
        dec_chunks.append(m_coeffs.astype(np.uint8))
    flat = np.concatenate(dec_chunks)
    mode = metadata.get("mode", "text")
    try:
        if mode == "text":
            unpadded = pkcs7_unpad(flat)
            text = devectorize_text(unpadded)
            print("Decrypted (text):")
            print(text)
            return text
        elif mode == "numeric":
            data_len = metadata["data_len"]
            bytes_per_number = metadata["bytes_per_number"]
            flat = flat[:data_len]
            data = flat.tobytes()
            nums = []
            for i in range(0, data_len, bytes_per_number):
                b = data[i:i + bytes_per_number]
                v = bytes_be_to_int(b)
                nums.append(v)
            print("Decrypted (numeric list):")
            print(nums)
            return nums
        else:
            raise ValueError("Unsupported mode in metadata")
    except ValueError as e:
        print("Decryption failed:", e)
        raise

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

def homomorphic_add_files_lwe(f1: str, f2: str, out_file: str, binary: bool = False):
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
    _write_encrypted_payload(out_file, summed, meta1, binary)
    print(f"Homomorphic sum saved to {out_file}")

def homomorphic_sub_files_lwe(f1: str, f2: str, out_file: str, binary: bool = False):
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
    _write_encrypted_payload(out_file, diff, meta1, binary)
    print(f"Homomorphic difference saved to {out_file}")

def homomorphic_scalar_mul_file_lwe(f: str, scalar: int, out_file: str, binary: bool = False):
    enc, meta = _load_encrypted_file(f)
    prod = []
    for blk in enc:
        c1 = blk["c1"].mul_scalar(scalar)
        c2 = blk["c2"].mul_scalar(scalar)
        prod.append({"c1": c1, "c2": c2})
    _write_encrypted_payload(out_file, prod, meta, binary)
    print(f"Homomorphic scalar multiplication saved to {out_file}")

def homomorphic_average_files_lwe(files: list, out_file: str, binary: bool = False):
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
    _write_encrypted_payload(out_file, avg_blocks, meta, binary)
    print(f"Homomorphic average saved to {out_file}")

def homomorphic_dot_files_lwe(f1: str, f2: str, out_file: str, binary: bool = False):
    enc1, meta1 = _load_encrypted_file(f1)
    enc2, meta2 = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    q = meta1["q"]
    flat1 = np.concatenate([blk["c2"].coeffs for blk in enc1])
    flat2 = np.concatenate([blk["c2"].coeffs for blk in enc2])
    if flat1.shape != flat2.shape:
        raise ValueError("Encrypted files flatten to different lengths")
    dot = int(sum(f1 * f2 for f1, f2 in zip(flat1, flat2)) % q)
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

# CLI for key generation
def generate_lwe_cli(pubfile: str = "lwe_pub.json", privfile: str = "lwe_priv.json", keystore: str = None, passphrase: str = None, key_name: str = None):
    print("Generating LWE keypair...")
    pub, priv = generate_lwe_keypair()
    if keystore and passphrase and key_name:
        store_key_in_keystore(passphrase, key_name, priv, keystore)
        print(f"Private key stored in keystore: {keystore} (key: {key_name})")
    else:
        with open(privfile, "w") as f:
            json.dump(priv, f)
        print(f"LWE private key -> {privfile} (KEEP SECRET)")
    with open(pubfile, "w") as f:
        json.dump(pub, f)
    print(f"LWE public key -> {pubfile}")
    return pubfile, privfile

# Main CLI
def main():
    parser = argparse.ArgumentParser(description="Lattice-based VEINN CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Keystore
    keystore_parser = subparsers.add_parser("create_keystore", help="Create a new encrypted keystore")
    keystore_parser.add_argument("--passphrase", required=True, help="Keystore passphrase")
    keystore_parser.add_argument("--keystore_file", default="keystore.json", help="Keystore file path")

    # Generate LWE keypair
    lwe_parser = subparsers.add_parser("generate_lwe", help="Generate LWE keypair")
    lwe_parser.add_argument("--pubfile", default="lwe_pub.json", help="Public key output file")
    lwe_parser.add_argument("--privfile", default="lwe_priv.json", help="Private key output file")
    lwe_parser.add_argument("--keystore", help="Store private key in keystore")
    lwe_parser.add_argument("--passphrase", help="Keystore passphrase")
    lwe_parser.add_argument("--key_name", help="Key name in keystore")

    # LWE encrypt
    lwe_enc_parser = subparsers.add_parser("lwe_encrypt", help="Encrypt with LWE public key")
    lwe_enc_parser.add_argument("--pubfile", default="lwe_pub.json", help="LWE public key file")
    lwe_enc_parser.add_argument("--message", help="Message to encrypt (text mode)")
    lwe_enc_parser.add_argument("--numbers", nargs="+", type=int, help="Numbers to encrypt (numeric mode)")
    lwe_enc_parser.add_argument("--mode", default="text", choices=["text", "numeric"], help="Mode: text or numeric")
    lwe_enc_parser.add_argument("--bytes_per_number", type=int, default=4, help="Bytes per number (numeric mode)")
    lwe_enc_parser.add_argument("--out_file", default="enc_lwe.json", help="Output file")
    lwe_enc_parser.add_argument("--binary", action="store_true", help="Use binary output format")

    # LWE decrypt
    lwe_dec_parser = subparsers.add_parser("lwe_decrypt", help="Decrypt with LWE private key")
    lwe_dec_parser.add_argument("--privfile", default="lwe_priv.json", help="LWE private key file")
    lwe_dec_parser.add_argument("--keystore", help="Retrieve private key from keystore")
    lwe_dec_parser.add_argument("--passphrase", help="Keystore passphrase")
    lwe_dec_parser.add_argument("--key_name", help="Key name in keystore")
    lwe_dec_parser.add_argument("--enc_file", default="enc_lwe.json", help="Encrypted file")

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

    args = parser.parse_args()

    try:
        if args.command == "create_keystore":
            create_keystore(args.passphrase, args.keystore_file)
            print(f"Keystore created: {args.keystore_file}")
        elif args.command == "generate_lwe":
            pubfile, privfile = generate_lwe_cli(args.pubfile, args.privfile, args.keystore, args.passphrase, args.key_name)
        elif args.command == "lwe_encrypt":
            encrypt_with_pub_lwe(args.pubfile, args.message, args.numbers, args.mode, args.out_file, args.binary, args.bytes_per_number)
        elif args.command == "lwe_decrypt":
            decrypt_with_priv_lwe(args.keystore, args.privfile, args.enc_file, args.passphrase, args.key_name)
        elif args.command == "hom_add":
            homomorphic_add_files_lwe(args.file1, args.file2, args.out_file, args.binary)
        elif args.command == "hom_sub":
            homomorphic_sub_files_lwe(args.file1, args.file2, args.out_file, args.binary)
        elif args.command == "hom_scalar_mul":
            homomorphic_scalar_mul_file_lwe(args.file, args.scalar, args.out_file, args.binary)
        elif args.command == "hom_avg":
            homomorphic_average_files_lwe(args.files, args.out_file, args.binary)
        elif args.command == "hom_dot":
            homomorphic_dot_files_lwe(args.file1, args.file2, args.out_file, args.binary)
        else:
            # Interactive mode
            print("Lattice-based VEINN CLI")
            while True:
                print("")
                print("1) Create encrypted keystore")
                print("2) Generate LWE keypair (public/private)")
                print("3) Encrypt with public key")
                print("4) Decrypt with private key")
                print("5) Homomorphic add (file1, file2 -> out)")
                print("6) Homomorphic subtract (file1, file2 -> out)")
                print("7) Homomorphic scalar multiply (file, scalar -> out)")
                print("8) Homomorphic average (file1,file2,... -> out)")
                print("9) Homomorphic dot product (file1, file2 -> out)")
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
                        pubfile = input("Public key filename (default lwe_pub.json): ").strip() or "lwe_pub.json"
                        use_keystore = input("Store private key in keystore? (y/n): ").strip().lower() == "y"
                        privfile, passphrase, key_name = None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("Private key filename (default lwe_priv.json): ").strip() or "lwe_priv.json"
                        generate_lwe_cli(pubfile, privfile, keystore, passphrase, key_name)
                    elif choice == "3":
                        pubfile = input("Public key file (default lwe_pub.json): ").strip() or "lwe_pub.json"
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
                        out_file = input("Output encrypted filename (default enc_lwe.json): ").strip() or "enc_lwe.json"
                        encrypt_with_pub_lwe(pubfile, message, numbers, mode, out_file, binary, bytes_per_number)
                    elif choice == "4":
                        use_keystore = input("Use keystore for private key? (y/n): ").strip().lower() or "y"
                        privfile, keystore, passphrase, key_name = None, None, None, None
                        if use_keystore:
                            keystore = input("Keystore filename (default keystore.json): ").strip() or "keystore.json"
                            passphrase = input("Keystore passphrase: ")
                            key_name = input("Key name in keystore: ")
                        else:
                            privfile = input("Private key file (default lwe_priv.json): ").strip() or "lwe_priv.json"
                        encfile = input("Encrypted file to decrypt (default enc_lwe.json): ").strip() or "enc_lwe.json"
                        if not os.path.exists(encfile):
                            print("Encrypted file not found.")
                            continue
                        decrypt_with_priv_lwe(keystore, privfile, encfile, passphrase, key_name)
                    elif choice == "5":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_add.json): ").strip() or "hom_add.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_add_files_lwe(f1, f2, out, binary)
                    elif choice == "6":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_sub.json): ").strip() or "hom_sub.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_sub_files_lwe(f1, f2, out, binary)
                    elif choice == "7":
                        f = input("Encrypted file: ").strip()
                        scalar = int(input("Scalar (integer): ").strip())
                        out = input("Output filename (default hom_mul.json): ").strip() or "hom_mul.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_scalar_mul_file_lwe(f, scalar, out, binary)
                    elif choice == "8":
                        files = input("Comma-separated encrypted files to average: ").strip().split(",")
                        files = [s.strip() for s in files if s.strip()]
                        out = input("Output filename (default hom_avg.json): ").strip() or "hom_avg.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_average_files_lwe(files, out, binary)
                    elif choice == "9":
                        f1 = input("Encrypted file 1: ").strip()
                        f2 = input("Encrypted file 2: ").strip()
                        out = input("Output filename (default hom_dot.json): ").strip() or "hom_dot.json"
                        binary = input("Use binary output? (y/n, default n): ").strip().lower() == "y"
                        homomorphic_dot_files_lwe(f1, f2, out, binary)
                    else:
                        print("Invalid choice")
                except Exception as e:
                    print("ERROR:", e)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()