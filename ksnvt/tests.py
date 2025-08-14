import secrets
import numpy as np
from improved import (
    vectorize_message,
    devectorize_message,
    encrypt,
    decrypt,
    bcolors
)

def test_encrypt_decrypt(message, layers=10):
    print(f"{bcolors.OKBLUE}Testing message: {message}{bcolors.ENDC}")

    # Step 1: Encrypt
    vec = vectorize_message(message)
    key = secrets.token_bytes(32)
    encrypted_vec = encrypt(vec, key, layers=layers)

    # Display key (hex) to simulate saving
    key_hex = key.hex()
    print(f"{bcolors.WARNING}Encryption key (hex): {key_hex}{bcolors.ENDC}")

    # Step 2: Decrypt using key only
    key_loaded = bytes.fromhex(key_hex)
    decrypted_vec = decrypt(encrypted_vec, key_loaded, layers=layers)
    decrypted_msg = devectorize_message(decrypted_vec)

    # Step 3: Verify
    if decrypted_msg == message:
        print(f"{bcolors.OKGREEN}Success: message recovered exactly!{bcolors.ENDC}")
        return True
    else:
        print(f"{bcolors.FAIL}Failure: recovered message does not match.{bcolors.ENDC}")
        print(f"Original: {message}")
        print(f"Decrypted: {decrypted_msg}")
        return False

def run_tests():
    test_messages = [
        "Hello, PQC world!",
        "🚀 Unicode test: 🌟✨🔥",
        "Short text",
        "Null byte test: \x00\x01\x02",
        "Mixed ASCII & Emoji: A🙂B🚀C",
    ]

    all_passed = True
    for msg in test_messages:
        result = test_encrypt_decrypt(msg, layers=10)
        all_passed &= result
        print("-" * 60)

    if all_passed:
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}All tests passed!{bcolors.ENDC}")
    else:
        print(f"{bcolors.BOLD}{bcolors.FAIL}Some tests failed.{bcolors.ENDC}")

if __name__ == "__main__":
    run_tests()