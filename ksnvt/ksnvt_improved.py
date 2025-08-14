import numpy as np
import secrets
import hashlib
import base64

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

# --- INN helper functions ---

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
    vec = np.asarray(vec, dtype=np.float64)
    noise = key_to_noise(key, vec.shape[0], noise_level)
    return vec + noise, noise

def denoise(vec, noise):
    return vec - noise

def encrypt(vec, key, layers=10):
    vec = np.asarray(vec, dtype=np.float64)
    for i in range(layers):
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=False)
    vec, noise = add_noise(vec, key)
    return vec, noise

def decrypt(vec, noise, key, layers=10):
    vec = denoise(vec, noise)
    for i in range(layers-1, -1, -1):
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=True)
    return vec

# --- Base64-safe vectorization ---

def vectorize_message(message_str):
    """Convert message to float vector in [-1,1] using Base64-safe encoding."""
    b64_bytes = base64.b64encode(message_str.encode('utf-8'))
    vec = np.frombuffer(b64_bytes, dtype=np.uint8).astype(np.float64)
    vec = vec / 127.5 - 1.0  # map 0-255 → -1 to 1
    if len(vec) % 2 != 0:
        vec = np.append(vec, 0.0)  # pad to even length
    return vec

def devectorize_message(vec):
    """Convert float vector back to string via Base64 decoding."""
    vec = np.asarray(vec, dtype=np.float64)
    bytes_vec = np.round((vec + 1.0) * 127.5).clip(0,255).astype(np.uint8)
    # remove padding 0 if added
    bytes_vec = bytes_vec.tobytes().rstrip(b'\x00')
    try:
        decoded = base64.b64decode(bytes_vec)
        return decoded.decode('utf-8')
    except Exception as e:
        print(f"{bcolors.FAIL}Decoding error: {e}{bcolors.ENDC}")
        print(f"Raw Base64 bytes: {bytes_vec}")
        return None

# --- Example usage ---

if __name__ == "__main__":
    key = secrets.token_bytes(32)
    message = input(f"{bcolors.BOLD}Message to encrypt: ")
    vec = vectorize_message(message)
    layers = 10

    print(f"{bcolors.OKBLUE}Original message: {message}{bcolors.ENDC}")

    encrypted_vec, noise = encrypt(vec, key, layers=layers)
    print(f"{bcolors.OKGREEN}Encrypted vector: {encrypted_vec}{bcolors.ENDC}")

    decrypted_vec = decrypt(encrypted_vec, noise, key, layers=layers)
    decrypted_msg = devectorize_message(decrypted_vec)
    print(f"{bcolors.OKCYAN}Decrypted message: {decrypted_msg}{bcolors.ENDC}")

    if decrypted_msg == message:
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}Success: exact recovery!{bcolors.ENDC}")
    else:
        print(f"{bcolors.BOLD}{bcolors.FAIL}Error: recovery failed.{bcolors.ENDC}")
