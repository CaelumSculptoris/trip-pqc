import time
from ksnvt import encrypt, decrypt, load_encrypted, bcolors
import numpy as np

def benchmark_file(filename, layers=10):
    encrypted_vec, key = load_encrypted(filename)
    dim = len(encrypted_vec)
    print(f"{bcolors.OKCYAN}Benchmarking file: {filename}, vector dim={dim}, layers={layers}{bcolors.ENDC}")

    start = time.time()
    enc_vec = encrypt(encrypted_vec, key, layers=layers)
    enc_time = time.time() - start
    print(f"Encryption time: {enc_time:.6f}s")

    start = time.time()
    dec_vec = decrypt(enc_vec, key, layers=layers)
    dec_time = time.time() - start
    print(f"Decryption time: {dec_time:.6f}s")

    # L2 error
    error = np.linalg.norm(encrypted_vec - dec_vec)
    print(f"Reconstruction error (L2 norm): {error:e}")

if __name__ == "__main__":
    filename = input("Enter encrypted vector file for benchmark: ")
    layers_input = input("Number of INN layers (default 10): ").strip()
    layers = int(layers_input) if layers_input else 10
    benchmark_file(filename, layers=layers)
