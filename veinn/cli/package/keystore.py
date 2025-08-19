# veinn/keystore.py
import os
import pickle
import json
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def create_keystore(passphrase: str, keystore_file: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = b64encode(kdf.derive(passphrase.encode()))
    _ = Fernet(key)  # ensure derive works
    keystore = {"salt": b64encode(salt).decode(), "keys": {}}
    with open(keystore_file, "wb") as kf:
        pickle.dump(keystore, kf)
    print(f"Keystore created at {keystore_file}")

def load_keystore(passphrase: str, keystore_file: str):
    with open(keystore_file, "rb") as kf:
        keystore = pickle.load(kf)
    salt = b64decode(keystore["salt"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = b64encode(kdf.derive(passphrase.encode()))
    return keystore, Fernet(key)

def store_key_in_keystore(passphrase: str, key_name: str, key_data: dict, keystore_file: str):
    keystore, fernet = load_keystore(passphrase, keystore_file)
    encrypted_key = fernet.encrypt(json.dumps(key_data).encode()).decode()
    keystore["keys"][key_name] = encrypted_key
    with open(keystore_file, "wb") as kf:
        pickle.dump(keystore, kf)

def retrieve_key_from_keystore(passphrase: str, key_name: str, keystore_file: str) -> dict:
    keystore, fernet = load_keystore(passphrase, keystore_file)
    if key_name not in keystore["keys"]:
        raise ValueError(f"Key {key_name} not found in keystore")
    encrypted_key = keystore["keys"][key_name]
    try:
        decrypted_key = fernet.decrypt(encrypted_key.encode())
        return json.loads(decrypted_key.decode())
    except Exception:
        raise ValueError("Failed to decrypt key. Wrong passphrase?")
