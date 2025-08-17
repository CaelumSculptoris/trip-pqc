import numpy as np
import secrets
import hashlib
import base64
import json
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ----------------- Utilities & key schedule -----------------
def rng_from_key(key: bytes, tag: bytes):
    seed = hashlib.sha256(key + tag).digest()
    # Use 8 uint32s to seed PCG64
    return np.random.default_rng(np.frombuffer(seed, dtype=np.uint32))

def key_to_params_mod(key: bytes, size: int, layer_idx: int, which: str):
    """
    Produce per-position parameters (a,b,c) for modular affine coupling:
        y = (a * x + b * cond + c) mod 256
    with gcd(a,256)=1 (i.e., a is odd) so inverse exists.
    'which' disambiguates params for updating first or second half.
    """
    rng = rng_from_key(key, b"params|" + which.encode() + layer_idx.to_bytes(4, "big"))
    # a must be odd in [1..255]
    a = rng.integers(0, 128, size=size, dtype=np.uint8) * 2 + 1
    b = rng.integers(0, 256, size=size, dtype=np.uint8)
    c = rng.integers(0, 256, size=size, dtype=np.uint8)
    return a, b, c

def key_to_perm(key: bytes, d: int, layer_idx: int):
    """Keyed permutation per layer."""
    rng = rng_from_key(key, b"perm|" + layer_idx.to_bytes(4, "big"))
    perm = np.arange(d, dtype=np.int32)
    rng.shuffle(perm)
    inv = np.empty_like(perm)
    inv[perm] = np.arange(d, dtype=np.int32)
    return perm, inv

def modinv_256(a_vec: np.ndarray) -> np.ndarray:
    """Per-element modular inverse modulo 256 (only defined for odd a)."""
    # Python's pow supports modular inverse for ints; vectorize it.
    inv_list = [pow(int(a), -1, 256) for a in a_vec.tolist()]
    return np.array(inv_list, dtype=np.uint8)

# ----------------- Affijne coupling -----------------
def affine_coupling_mod(x: np.ndarray, a: np.ndarray, b: np.ndarray, c: np.ndarray,
                        update_first: bool, invert: bool) -> np.ndarray:
    """
    Byte-wise affine coupling with modulo arithmetic.
    If update_first=False: update second half using first half as condition.
    If update_first=True:  update first half using second half as condition.
    """
    d = x.shape[0]
    assert d % 2 == 0, "Input length must be even"
    h = d // 2
    x = x.copy()
    x1, x2 = x[:h], x[h:]

    if not invert:
        if update_first:
            # y1 = a*x1 + b*x2 + c ; y2 = x2
            y1 = (a * x1 + b * x2 + c).astype(np.uint16) % 256
            out = np.concatenate([y1.astype(np.uint8), x2])
        else:
            # y2 = a*x2 + b*x1 + c ; y1 = x1
            y2 = (a * x2 + b * x1 + c).astype(np.uint16) % 256
            out = np.concatenate([x1, y2.astype(np.uint8)])
    else:
        ainv = modinv_256(a)
        if update_first:
            # x1 = ainv * (y1 - b*x2 - c)
            x1_rec = (ainv.astype(np.uint16) *
                      ((x1.astype(np.int16) - (b * x2).astype(np.int16) - c.astype(np.int16)) % 256)
                      ).astype(np.uint16) % 256
            out = np.concatenate([x1_rec.astype(np.uint8), x2])
        else:
            # x2 = ainv * (y2 - b*x1 - c)
            x2_rec = (ainv.astype(np.uint16) *
                      ((x2.astype(np.int16) - (b * x1).astype(np.int16) - c.astype(np.int16)) % 256)
                      ).astype(np.uint16) % 256
            out = np.concatenate([x1, x2_rec.astype(np.uint8)])
    return out

# ----------------- Noise -----------------
def sample_latent_bytes(key: bytes, length: int) -> np.ndarray:
    """
    Deterministic 'noise' z ~ Uniform({0..255}^length) from the key.
    This is appended to x, then the bijection acts on [x; z].
    """
    rng = rng_from_key(key, b"latent")
    return rng.integers(0, 256, size=length, dtype=np.uint8)

# ----------------- Vectorization -----------------
def vectorize_message_bytes(message_str: str):
    """
    Encode to base64 bytes so we stay in 7-bit-clean space, then to uint8.
    Return (vec, orig_len, pad).
    """
    b64 = base64.b64encode(message_str.encode("utf-8"))
    vec = np.frombuffer(b64, dtype=np.uint8)
    orig_len = vec.shape[0]
    pad = (orig_len % 2)  # ensure even length for coupling
    if pad:
        vec = np.append(vec, np.array([0], dtype=np.uint8))
    return vec.copy(), orig_len, pad

def devectorize_message_bytes(vec: np.ndarray, orig_len: int):
    vec = vec[:orig_len].tobytes()
    try:
        decoded = base64.b64decode(vec)
        return decoded.decode("utf-8")
    except Exception as e:
        print(f"{bcolors.FAIL}Decoding error: {e}{bcolors.ENDC}")
        return None

# ----------------- File Persistence -----------------
def save_encrypted(filename, encrypted_vec, key, meta, orig_len):
    data = {
        "vector": encrypted_vec.tolist(),
        "key": key.hex(),
        "meta": meta,
        "orig_len": int(orig_len),
    }
    with open(filename, "w") as f:
        json.dump(data, f)

def load_encrypted(filename):
    with open(filename, "r") as f:
        data = json.load(f)
    encrypted_vec = np.array(data["vector"], dtype=np.uint8)
    key = bytes.fromhex(data["key"])
    meta = data.get("meta", {})
    orig_len = int(data.get("orig_len"))
    return encrypted_vec, key, meta, orig_len

# ----------------- Encrypt / Decrypt -----------------
def encrypt(vec: np.ndarray, key: bytes, layers: int = 10, latent_len: int = 16):
    """
    Bijective map over bytes with modular affine coupling + permutations.
    We append latent bytes z (deterministic from key) so you get 'noise'
    in the output without breaking invertibility.
    """
    assert vec.dtype == np.uint8
    # Append latent bytes
    z = sample_latent_bytes(key, latent_len) if latent_len > 0 else np.array([], dtype=np.uint8)
    x = np.concatenate([vec, z])

    # Ensure even length after appending z
    if x.shape[0] % 2 != 0:
        x = np.append(x, np.array([0], dtype=np.uint8))
        z_pad = 1
    else:
        z_pad = 0

    d = x.shape[0]
    for i in range(layers):
        # Alternate which half is updated: even -> second half, odd -> first half
        update_first = bool(i % 2)
        size = d // 2
        which = "first" if update_first else "second"
        a, b, c = key_to_params_mod(key, size, i, which)
        x = affine_coupling_mod(x, a, b, c, update_first=update_first, invert=False)
        # Keyed permutation for mixing
        perm, _inv = key_to_perm(key, d, i)
        x = x[perm]
    meta = {"layers": layers, "latent_len": int(latent_len), "z_pad": int(z_pad), "total_len": int(d)}
    return x, meta

def decrypt(y: np.ndarray, key: bytes, meta: dict, orig_len: int):
    """
    Invert the exact sequence: inverse perms (reverse order) + inverse couplings,
    then remove padding and latent bytes, then devectorize to message.
    """
    assert y.dtype == np.uint8
    layers = int(meta["layers"])
    latent_len = int(meta["latent_len"])
    z_pad = int(meta["z_pad"])
    d = int(meta["total_len"])
    x = y.copy()

    # Inverse through layers (reverse order)
    for i in reversed(range(layers)):
        perm, inv = key_to_perm(key, d, i)
        x = x[inv]  # undo permutation
        update_first = bool(i % 2)
        size = d // 2
        which = "first" if update_first else "second"
        a, b, c = key_to_params_mod(key, size, i, which)
        x = affine_coupling_mod(x, a, b, c, update_first=update_first, invert=True)

    # Remove any final pad added after z
    if z_pad:
        x = x[:-1]
    # Remove latent bytes
    if latent_len > 0:
        x_core = x[:-latent_len]
    else:
        x_core = x
    # Now x_core includes the original 1-byte pad (if any) done before encrypt;
    # devectorize will slice to orig_len.
    return x_core


# ----------------- CLI -----------------
if __name__ == "__main__":
    print(f"{bcolors.BOLD}Choose action:{bcolors.ENDC}")
    print(f"{bcolors.BOLD}1) Encrypt & save{bcolors.ENDC}")
    print(f"{bcolors.BOLD}2) Load & decrypt{bcolors.ENDC}")
    choice = input("Enter 1 or 2: ").strip()

    layers_input = input("Number of flow layers (default 10): ").strip()
    layers = int(layers_input) if layers_input else 10

    latent_input = input("Latent bytes to append (default 16): ").strip()
    latent_len = int(latent_input) if latent_input else 16

    if choice == "1":
        message = input("Message to encrypt: ")
        vec, orig_len, pad = vectorize_message_bytes(message)

        key = secrets.token_bytes(32)  # 256-bit key
        encrypted_vec, meta = encrypt(vec, key, layers=layers, latent_len=latent_len)

        filename = input("Save encrypted data to filename: ").strip()
        save_encrypted(filename, encrypted_vec, key, meta | {"pad": int(pad)}, orig_len)
        print(f"Encrypted vector saved to {bcolors.OKCYAN}{filename}{bcolors.ENDC}")
        print(f"Key (hex): {bcolors.OKCYAN}{key.hex()}{bcolors.ENDC}")
        print(f"Layers: {bcolors.OKGREEN}{layers}{bcolors.ENDC} | Latent bytes: {bcolors.OKGREEN}{latent_len}{bcolors.ENDC}")
        print(f"Vector (len {len(encrypted_vec)}): {bcolors.OKGREEN}{encrypted_vec}{bcolors.ENDC}")

    elif choice == "2":
        filename = input(f"{bcolors.BOLD}Enter encrypted vector file to load: {bcolors.ENDC}").strip()
        if not os.path.exists(filename):
            print(f"{bcolors.FAIL}File not found: {filename}{bcolors.ENDC}")
            exit(1)
        encrypted_vec, key, meta, orig_len = load_encrypted(filename)
        x_core = decrypt(encrypted_vec, key, meta, orig_len=orig_len)
        msg = devectorize_message_bytes(x_core, orig_len=orig_len)
        print(f"Decrypted message: {bcolors.OKCYAN}{msg}{bcolors.ENDC}")
        print(f"Layers: {bcolors.OKGREEN}{meta['layers']}{bcolors.ENDC} | Latent bytes: {bcolors.OKGREEN}{meta['latent_len']}{bcolors.ENDC}")
        print(f"Recovered vector (len {len(x_core)}): {bcolors.OKGREEN}{x_core}{bcolors.ENDC}")

    else:
        print(f"{bcolors.FAIL}Invalid choice{bcolors.ENDC}")