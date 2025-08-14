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
    """
    seed = hashlib.sha256(key + layer_idx.to_bytes(4, 'big')).digest()
    rng = np.random.default_rng(np.frombuffer(seed, dtype=np.uint32))
    scale = rng.uniform(0.5, 2.0, size).astype(np.float64)
    shift = rng.uniform(-1.0, 1.0, size).astype(np.float64)
    return scale, shift

def key_to_noise(key, size, noise_level=0.01):
    """
    Generate deterministic pseudo-noise from the key for exact reversibility.
    """
    seed = hashlib.sha256(key + b"noise").digest()
    rng = np.random.default_rng(np.frombuffer(seed, dtype=np.uint32))
    noise = rng.normal(0, noise_level, size=size).astype(np.float64)
    return noise

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

def add_noise(vec, key, noise_level=0.01):
    """
    Add key-derived pseudo-noise to the vector, returning noise for exact denoising.
    """
    vec = np.asarray(vec, dtype=np.float64)
    noise = key_to_noise(key, vec.shape, noise_level)
    return vec + noise, noise

def denoise(vec, noise):
    """
    Remove exact pseudo-noise for perfect invertibility.
    """
    return np.asarray(vec, dtype=np.float64) - noise

def encrypt(vec, key, layers=10):
    """
    Encrypt vector with multiple layers and add key-derived noise at the end.
    Returns encrypted vector and noise for decryption.
    """
    vec = np.asarray(vec, dtype=np.float64)
    for i in range(layers):
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=False)
    vec, noise = add_noise(vec, key, noise_level=0.01)
    return vec, noise

def decrypt(vec, noise, key, layers=10):
    """
    Decrypt vector by removing noise first, then inverting layers in reverse order.
    """
    vec = denoise(vec, noise)
    for i in range(layers-1, -1, -1):
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=True)
    return vec

def vectorize_message(message_str, vec_size):
    """
    Convert message to a float vector in [0, 1].
    """
    vec = np.zeros(vec_size, dtype=np.float64)
    message_bytes = message_str.encode('utf-8')[:vec_size]
    vec[:len(message_bytes)] = np.frombuffer(message_bytes, dtype=np.uint8).astype(np.float64) / 255.0
    return vec

def devectorize_message(vec):
    """
    Convert vector back to string with precise rounding and enhanced error handling.
    """
    vec = np.asarray(vec, dtype=np.float64)
    scaled_vec = vec * 255.0
    bytes_approx = np.round(scaled_vec).clip(0, 255).astype(np.uint8)
    try:
        decoded = bytes_approx.tobytes().decode('utf-8').rstrip('\x00')
        return decoded
    except UnicodeDecodeError as e:
        print(f"{bcolors.FAIL}UTF-8 decode error: {e}{bcolors.ENDC}")
        print(f"{bcolors.WARNING}Raw bytes: {bytes_approx.tobytes().hex()}{bcolors.ENDC}")
        print(f"{bcolors.WARNING}Scaled vector (before rounding): {scaled_vec}{bcolors.ENDC}")
        return None

if __name__ == "__main__":
    # Use a 256-bit key (32 bytes) for security
    key = secrets.token_bytes(32)
    message = input(f"{bcolors.BOLD}Message to encrypt: ")
    vec_size = int(len(message)*1.1)
    if vec_size % 2 != 0:
        vec_size += 1
    layers = 10

    print(f"{bcolors.OKBLUE}Original message: {message}{bcolors.ENDC}")
    msg_vec = vectorize_message(message, vec_size)
    print(f"{bcolors.OKCYAN}Message vector: {msg_vec}{bcolors.ENDC}")

    encrypted_vec, noise = encrypt(msg_vec, key, layers=layers)
    print(f"{bcolors.OKGREEN}Encrypted vector (noisy): {encrypted_vec}{bcolors.ENDC}")

    decrypted_vec = decrypt(encrypted_vec, noise, key, layers=layers)
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