import numpy as np

def key_to_params(key, size, layer_idx):
    rng = np.random.default_rng(seed=key + layer_idx)
    scale = rng.uniform(0.5, 2.0, size)
    shift = rng.uniform(-1.0, 1.0, size)
    return scale, shift

def affine_coupling_layer(x, scale, shift, invert=False):
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

def add_noise(vec, noise_level=0.01):
    noise = np.random.normal(0, noise_level, size=vec.shape)
    return vec + noise

def denoise(vec, iterations=10):
    vec_est = np.copy(vec)
    for _ in range(iterations):
        # Simple smoothing denoising step
        vec_est = (np.roll(vec_est, 1) + vec_est + np.roll(vec_est, -1)) / 3
    return vec_est

def encrypt(vec, key, layers=3):
    for i in range(layers):
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=False)
    vec = add_noise(vec, noise_level=0.01)
    return vec

def decrypt(vec, key, layers=3):
    vec = denoise(vec, iterations=10)
    for i in reversed(range(layers)):
        scale, shift = key_to_params(key, len(vec)//2, i)
        vec = affine_coupling_layer(vec, scale, shift, invert=True)
    return vec

def vectorize_message(message_str, vec_size):
    vec = np.zeros(vec_size)
    message_bytes = message_str.encode('utf-8')[:vec_size]
    vec[:len(message_bytes)] = np.array(message_bytes) / 255.0
    return vec

def devectorize_message(vec):
    bytes_approx = (vec * 255).clip(0, 255).astype(np.uint8)
    try:
        return bytes_approx.tobytes().decode('utf-8').rstrip('\x00')
    except UnicodeDecodeError:
        return None

if __name__ == "__main__":
    key = 42
    message = "NoiseTolerance"
    vec_size = 16
    if vec_size % 2 != 0:
        vec_size += 1

    print(f"Original message: {message}")
    msg_vec = vectorize_message(message, vec_size)
    print(f"Message vector: {msg_vec}")

    encrypted_vec = encrypt(msg_vec, key)
    print(f"Encrypted vector (noisy): {encrypted_vec}")

    decrypted_vec = decrypt(encrypted_vec, key)
    print(f"Decrypted vector (denoised): {decrypted_vec}")

    decrypted_msg = devectorize_message(decrypted_vec)
    print(f"Decrypted message approx: {decrypted_msg}")

    error = np.linalg.norm(msg_vec - decrypted_vec)
    print(f"Reconstruction error: {error}")
