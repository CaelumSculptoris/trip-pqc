# veinn/serialization.py
import json
import numpy as np
from .params import DTYPE

def bytes_to_block(b: bytes, n: int) -> np.ndarray:
    padded = b + b"\x00" * ((2 * n - len(b)) % (2 * n))
    arr = np.frombuffer(padded, dtype=np.uint16)
    if arr.shape[0] < n:
        arr = np.pad(arr, (0, n - arr.shape[0]), mode="constant", constant_values=0)
    return arr[:n].astype(DTYPE)

def block_to_bytes(x: np.ndarray) -> bytes:
    return x.tobytes()

def write_ciphertext_json(path: str, encrypted_blocks: list, metadata: dict, enc_seed_bytes: bytes, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    payload = {
        "veinn_metadata": metadata,
        "enc_seed": [int(b) for b in enc_seed_bytes],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in encrypted_blocks],
    }
    if hmac_value:
        payload["hmac"] = hmac_value
    if nonce:
        payload["nonce"] = [int(b) for b in nonce]
    if timestamp:
        payload["timestamp"] = timestamp
    with open(path, "w") as f:
        json.dump(payload, f)

def read_ciphertext(path: str):
    with open(path, "r") as f:
        payload = json.load(f)
    enc_seed = bytes([int(b) for b in payload["enc_seed"]])
    metadata = payload["veinn_metadata"]
    enc_blocks = [np.array([int(x) for x in blk], dtype=DTYPE) for blk in payload["encrypted"]]
    hmac_value = payload.get("hmac")
    nonce = bytes([int(b) for b in payload.get("nonce", [])]) if "nonce" in payload else None
    timestamp = payload.get("timestamp")
    return metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp
