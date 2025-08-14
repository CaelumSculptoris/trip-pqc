import secrets
import numpy as np
from ksnvt_improved import (
    vectorize_message,
    devectorize_message,
    encrypt,
    decrypt,
    bcolors,
)

def test_message_recovery(message, layers=10):
    print(f"{bcolors.OKBLUE}Testing message: {message}{bcolors.ENDC}")

    key = secrets.token_bytes(32)
    vec = vectorize_message(message)

    # Encrypt
    encrypted_vec, noise = encrypt(vec, key, layers=layers)

    # Decrypt
    decrypted_vec = decrypt(encrypted_vec, noise, key, layers=layers)

    # Vector-level comparison
    diff_vec = np.abs(vec - decrypted_vec)
    max_diff = np.max(diff_vec)
    vector_ok = np.allclose(vec, decrypted_vec, atol=1e-12)

    # UTF-8 string recovery
    decrypted_msg = devectorize_message(decrypted_vec)
    string_ok = decrypted_msg == message

    # Print results
    if vector_ok and string_ok:
        print(f"{bcolors.OKGREEN}Success: exact vector and string recovery!{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}Failure detected!{bcolors.ENDC}")
        print(f"Max vector difference: {max_diff}")
        print(f"Original message: {message}")
        print(f"Decrypted message: {decrypted_msg}")
        print(f"Vector differences: {diff_vec}")

    return vector_ok and string_ok

def run_tests():
    test_messages = [
        "Hello, PQC world!",
        "🚀 Unicode test: 🌟✨🔥",
        "Short",
        "Edge case with null byte:\x00\x01\x02",
        "Exact length vector test for high-dimensional INN.",
        "Mixed ASCII & Emoji: A🙂B🚀C",
    ]

    all_passed = True
    for msg in test_messages:
        result = test_message_recovery(msg, layers=10)
        all_passed &= result
        print("-" * 60)

    if all_passed:
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}All tests passed!{bcolors.ENDC}")
    else:
        print(f"{bcolors.BOLD}{bcolors.FAIL}Some tests failed.{bcolors.ENDC}")

if __name__ == "__main__":
    run_tests()
