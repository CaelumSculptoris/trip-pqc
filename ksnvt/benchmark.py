import secrets
import numpy as np
import time
from improved import (
    vectorize_message,
    devectorize_message,
    encrypt,
    decrypt,
    bcolors,
)

def benchmark_message(message, layers=10, repeat=5):
    print(f"{bcolors.OKBLUE}Benchmarking message: {message}{bcolors.ENDC}")

    key = secrets.token_bytes(32)
    vec = vectorize_message(message)

    # Simulate high-dimensional space by tiling vector
    high_dim_vec = np.tile(vec, 10)  # 10x original length

    total_time_encrypt = 0.0
    total_time_decrypt = 0.0
    success = True

    for _ in range(repeat):
        # Encrypt
        start = time.perf_counter()
        encrypted_vec, noise = encrypt(high_dim_vec, key, layers=layers)
        end = time.perf_counter()
        total_time_encrypt += end - start

        # Decrypt
        start = time.perf_counter()
        decrypted_vec = decrypt(encrypted_vec, noise, key, layers=layers)
        end = time.perf_counter()
        total_time_decrypt += end - start

        # Check exact recovery
        if not np.allclose(high_dim_vec, decrypted_vec, atol=1e-12):
            print(f"{bcolors.FAIL}Vector recovery failed in repeat!{bcolors.ENDC}")
            success = False
        decrypted_msg = devectorize_message(decrypted_vec[:len(vec)])
        if decrypted_msg != message:
            print(f"{bcolors.FAIL}Message recovery failed: {decrypted_msg}{bcolors.ENDC}")
            success = False

    print(f"Average encryption time: {total_time_encrypt / repeat:.6f}s")
    print(f"Average decryption time: {total_time_decrypt / repeat:.6f}s")
    print(f"{bcolors.OKGREEN if success else bcolors.FAIL}Success: {success}{bcolors.ENDC}")
    print("-" * 60)

def run_benchmarks():
    test_messages = [
        "Hello, PQC world!",
        "🚀 Unicode test: 🌟✨🔥",
        "Mixed ASCII & Emoji: A🙂B🚀C",
    ]

    for msg in test_messages:
        benchmark_message(msg, layers=10, repeat=3)

if __name__ == "__main__":
    run_benchmarks()
