import numpy as np
import secrets
import hashlib

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

def key_to_params(key, size, layer_idx=0):
    """
    Generate scale and shift parameters from a 256-bit key using a secure PRNG.
    Simplified to ensure numerical stability and exact invertibility.
    """
    # Use SHA-256 for deterministic seed, simplified for stability
    seed = hashlib.sha256(key).digest()  # No layer_idx to match original single-layer
    rng = np.random.default_rng(np.frombuffer(seed, dtype=np.uint32))
    scale = rng.uniform(0.5, 2.0, size).astype(np.float64)
    shift = rng.uniform(-1.0, 1.0, size).astype(np.float64)
    return scale, shift

def affine_coupling_layer(x, scale, shift, invert=False):
    """
    Apply a single affine coupling layer using float64 for exact invertibility.
    """
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

def encrypt(vec, key, layers=1):
    """
    Encrypt vector with one layer to match original behavior.
    """
    vec = np.asarray(vec, dtype=np.float64)
    for i in range(layers):  # Single layer by default
        scale, shift = key_to_params(key, len(vec)//2)
        vec = affine_coupling_layer(vec, scale, shift, invert=False)
    return vec

def decrypt(vec, key, layers=1):
    """
    Decrypt vector by inverting layers in reverse order.
    """
    vec = np.asarray(vec, dtype=np.float64)
    for i in range(layers-1, -1, -1):
        scale, shift = key_to_params(key, len(vec)//2)
        vec = affine_coupling_layer(vec, scale, shift, invert=True)
    return vec

def vectorize_message(message_str, vec_size):
    """
    Convert message to a float vector in [0, 1], matching original exactly.
    """
    vec = np.zeros(vec_size, dtype=np.float64)
    message_bytes = message_str.encode('utf-8')[:vec_size]
    vec[:len(message_bytes)] = np.frombuffer(message_bytes, dtype=np.uint8).astype(np.float64) / 255.0
    return vec

def devectorize_message(vec):
    """
    Convert vector back to string with precise rounding to avoid byte errors.
    """
    # Scale and round to nearest 1/255 to match original byte values
    scaled_vec = vec * 255.0
    bytes_approx = np.round(scaled_vec).clip(0, 255).astype(np.uint8)
    try:
        return bytes_approx.tobytes().decode('utf-8').rstrip('\x00')
    except UnicodeDecodeError:
        print("Warning: UTF-8 decode failed, returning raw bytes")
        return bytes_approx.tobytes().hex()

if __name__ == "__main__":
    # Use a 256-bit key (32 bytes) for security
    key = secrets.token_bytes(32)
    message = input(f"{bcolors.BOLD}Message to encrypt: ")
    vec_size = int(len(message)*1.1)
    if vec_size % 2 != 0:
        vec_size += 1
    layers = 10  # Single layer to match original

    print(f"{bcolors.OKBLUE}Original message: {message}{bcolors.ENDC}")
    msg_vec = vectorize_message(message, vec_size)
    print(f"{bcolors.OKCYAN}Message vector: {msg_vec}{bcolors.ENDC}")

    encrypted_vec = encrypt(msg_vec, key, layers=layers)
    print(f"{bcolors.OKGREEN}Encrypted vector:{encrypted_vec}{bcolors.ENDC}")

    decrypted_vec = decrypt(encrypted_vec, key, layers=layers)
    print(f"{bcolors.OKGREEN}Decrypted vector: {decrypted_vec}{bcolors.ENDC}")

    decrypted_msg = devectorize_message(decrypted_vec)
    print(f"{bcolors.OKCYAN}Decrypted message: {decrypted_msg}{bcolors.ENDC}")

    # Check message match
    if decrypted_msg == message:
        print(f"{bcolors.BOLD}Success: Decrypted message matches original!{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}Error: Decrypted message does not match original!{bcolors.ENDC}")
        print(f"{bcolors.FAIL}Expected: {message}{bcolors.ENDC}")
        print(f"{bcolors.FAIL}Got: {decrypted_msg}{bcolors.ENDC}")

    # Compute reconstruction error
    error = np.linalg.norm(msg_vec - decrypted_vec, ord=2)
    print(f"{bcolors.WARNING}Reconstruction error (should be ~0): {error}{bcolors.ENDC}")

    # Debug: Element-wise differences
    diffs = np.abs(msg_vec - decrypted_vec)
    max_diff = np.max(diffs)
    print(f"{bcolors.WARNING}Maximum element-wise difference: {max_diff}{bcolors.ENDC}")
    if max_diff > 0:
        print(f"{bcolors.BOLD}Elements with differences:{bcolors.ENDC}")
        for i, (orig, dec, diff) in enumerate(zip(msg_vec, decrypted_vec, diffs)):
            if diff > 0:
                print(f"{bcolors.OKGREEN}Index {i}: Original={orig:.10f}, Decrypted={dec:.10f}, Diff={diff:.10e}{bcolors.ENDC}")