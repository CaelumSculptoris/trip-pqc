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

# ----------------- INN Functions -----------------
def key_to_params(key, size, layer_idx=0):
    seed = hashlib.sha256(key + layer_idx.to_bytes(4,'big')).digest()
    rng = np.random.default_rng(np.frombuffer(seed, dtype=np.uint32))
    scale = rng.uniform(0.8, 1.2, size).astype(np.float64)
    shift = rng.uniform(-0.2, 0.2, size).astype(np.float64)
    return scale, shift

def key_to_noise(key, size, noise_level=1e-5):
    seed = hashlib.sha256(key + b"noise").digest()
    rng = np.random.default_rng(np.frombuffer(seed, dtype=np.uint32))
    noise = rng.normal(0, noise_level, size=size).astype(np.float64)
    return noise

def affine_coupling_layer(x, scale, shift, invert=False):
    x = np.asarray(x, dtype=np.float64)
    d = len(x)
    assert d % 2 == 0, "Input dimension must be even"
    x1, x2 = x[:d//2], x[d//2:]
    if not invert:
        y1 = x1
        y2 = x2 * scale + shift * x1
    else:
        y1 = x1
        y2 = (x2 - shift * x1) / scale
    return np.concatenate([y1, y2])

def add_noise(vec, key, noise_level=1e-5):
    return vec + key_to_noise(key, vec.shape[0], noise_level)

def denoise(vec, key, noise_level=1e-5):
    return vec - key_to_noise(key, vec.shape[0], noise_level)

def encrypt(vec, key, layers=10):
    vec = np.asarray(vec, dtype=np.float64)
    for i in range(layers):
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=False)
    vec = add_noise(vec, key)
    return vec

def decrypt(vec, key, layers=10):
    vec = denoise(vec, key)
    for i in range(layers-1, -1, -1):        
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=True)
    return vec

# ----------------- Vectorization -----------------
def vectorize_message(message_str):
    b64_bytes = base64.b64encode(message_str.encode('utf-8'))
    vec = np.frombuffer(b64_bytes, dtype=np.uint8).astype(np.float64)
    vec = vec / 127.5 - 1.0  # Normalize to [-1, 1]
    if len(vec) % 2 != 0:
        vec = np.append(vec, 0.0)
    return vec

def devectorize_message(vec):
    vec = np.asarray(vec, dtype=np.float64)
    bytes_vec = np.round((vec + 1.0) * 127.5).clip(0, 255).astype(np.uint8)
    bytes_vec = bytes_vec.tobytes().rstrip(b'\x00')
    try:
        decoded = base64.b64decode(bytes_vec)
        return decoded.decode('utf-8')
    except Exception as e:
        print(f"{bcolors.FAIL}Decoding error: {e}{bcolors.ENDC}")
        print(f"{bcolors.OKGREEN}Raw Base64 bytes: {bytes_vec}{bcolors.ENDC}")
        return None

# ----------------- File Persistence -----------------
def save_encrypted(filename, encrypted_vec, key):
    data = {"vector": encrypted_vec.tolist(), "key": key.hex()}
    with open(filename, 'w') as f:
        json.dump(data, f)

def load_encrypted(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    encrypted_vec = np.array(data["vector"], dtype=np.float64)
    key = bytes.fromhex(data["key"])
    return encrypted_vec, key

# ----------------- CLI -----------------
if __name__ == "__main__":
    print(f"{bcolors.BOLD}Choose action:{bcolors.ENDC}")
    print(f"{bcolors.BOLD}1) Encrypt & save{bcolors.ENDC}")
    print(f"{bcolors.BOLD}2) Load & decrypt{bcolors.ENDC}")
    choice = input("Enter 1 or 2: ").strip()

    layers_input = input("Number of INN layers (default 10): ").strip()
    layers = int(layers_input) if layers_input else 10

    if choice == "1":
        message = input("Message to encrypt: ")
        vec = vectorize_message(message)
        key = secrets.token_bytes(32)
        encrypted_vec = encrypt(vec, key, layers=layers)

        filename = input("Save encrypted data to filename: ").strip()
        save_encrypted(filename, encrypted_vec, key)
        print(f"Encrypted vector saved to {bcolors.OKCYAN}{filename}{bcolors.ENDC}")
        print(f"Encryption key (hex): {bcolors.OKCYAN}{key.hex()}{bcolors.ENDC}")
        print(f"Layers: {bcolors.OKGREEN}{layers}{bcolors.ENDC}")
        print(f"Vector: {bcolors.OKGREEN}{encrypted_vec}{bcolors.ENDC}")

    elif choice == "2":
        filename = input(f"{bcolors.BOLD}Enter encrypted vector file to load: {bcolors.ENDC}").strip()
        if not os.path.exists(filename):
            print(f"{bcolors.FAIL}File not found: {filename}{bcolors.ENDC}")
            exit(1)
        encrypted_vec, key = load_encrypted(filename)
        decrypted_vec = decrypt(encrypted_vec, key, layers=layers)
        decrypted_msg = devectorize_message(decrypted_vec)
        print(f"Decrypted message: {bcolors.OKCYAN}{decrypted_msg}{bcolors.ENDC}")
        print(f"Layers: {bcolors.OKGREEN}{layers}{bcolors.ENDC}")
        print(f"Vector: {bcolors.OKGREEN}{decrypted_vec}{bcolors.ENDC}")

    else:
        print(f"{bcolors.FAIL}Invalid choice{bcolors.ENDC}")
