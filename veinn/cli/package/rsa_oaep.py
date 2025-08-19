# veinn/rsa_oaep.py
import math
import secrets
import time
from .utils import shake, int_to_bytes_be_fixed

def is_probable_prime(n: int, trials: int = 5) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
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
        if x in (1, n - 1):
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

def egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

def generate_rsa_keypair(bits: int) -> dict:
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}

def _i2osp_fixed_len(x: int, length: int) -> bytes:
    """Integer-to-bytes, left-padded to exactly `length` bytes."""
    return x.to_bytes(length, "big")

def oaep_encode(message: bytes, n: int, seed: bytes) -> int:
    k = (n.bit_length() + 7) // 8
    mlen = len(message)
    if mlen > k - 2 * 32 - 2:
        raise ValueError("Message too long for OAEP")
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
        raise ValueError("Invalid OAEP format")
    hlen = 32
    masked_seed = c[1:1 + hlen]
    masked_db = c[1 + hlen:]
    seed_mask = shake(hlen, masked_db)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = shake(k - hlen - 1, seed)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    lhash = shake(hlen, b"")
    if db[:hlen] != lhash:
        raise ValueError("Invalid OAEP lhash")
    i = hlen
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 1:
        raise ValueError("Invalid OAEP padding")
    return db[i + 1:]

def validate_timestamp(timestamp: float, validity_window: int) -> bool:
    return abs(time.time() - timestamp) <= validity_window
