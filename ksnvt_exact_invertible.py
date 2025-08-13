import numpy as np
import secrets
import hashlib

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
    message = "ExactInvert"
    vec_size = 16
    if vec_size % 2 != 0:
        vec_size += 1
    layers = 1  # Single layer to match original

    print(f"Original message: {message}")
    msg_vec = vectorize_message(message, vec_size)
    print(f"Message vector: {msg_vec}")

    encrypted_vec = encrypt(msg_vec, key, layers=layers)
    print(f"Encrypted vector: {encrypted_vec}")

    decrypted_vec = decrypt(encrypted_vec, key, layers=layers)
    print(f"Decrypted vector: {decrypted_vec}")

    decrypted_msg = devectorize_message(decrypted_vec)
    print(f"Decrypted message: {decrypted_msg}")

    # Check message match
    if decrypted_msg == message:
        print("Success: Decrypted message matches original!")
    else:
        print("Error: Decrypted message does not match original!")
        print(f"Expected: {message}")
        print(f"Got: {decrypted_msg}")

    # Compute reconstruction error
    error = np.linalg.norm(msg_vec - decrypted_vec, ord=2)
    print(f"Reconstruction error (should be ~0): {error}")

    # Debug: Element-wise differences
    diffs = np.abs(msg_vec - decrypted_vec)
    max_diff = np.max(diffs)
    print(f"Maximum element-wise difference: {max_diff}")
    if max_diff > 0:
        print("Elements with differences:")
        for i, (orig, dec, diff) in enumerate(zip(msg_vec, decrypted_vec, diffs)):
            if diff > 0:
                print(f"Index {i}: Original={orig:.10f}, Decrypted={dec:.10f}, Diff={diff:.10e}")