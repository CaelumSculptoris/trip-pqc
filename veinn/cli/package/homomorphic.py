# veinn/homomorphic.py
from params import Q
from serialization import read_ciphertext
from ring import negacyclic_convolution
import json

def _load_encrypted_file(enc_file: str):
    metadata, _, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file)
    meta_parsed = {
        "n": int(metadata["n"]),
        "rounds": int(metadata["rounds"]),
        "layers_per_round": int(metadata["layers_per_round"]),
        "shuffle_stride": int(metadata["shuffle_stride"]),
        "use_lwe": metadata["use_lwe"],
        "mode": metadata.get("mode", "numeric"),
        "bytes_per_number": int(metadata.get("bytes_per_number", metadata.get("n", 4) * 2)),
    }
    return enc_blocks, meta_parsed, hmac_value, nonce, timestamp

def _write_encrypted_payload(out_file: str, enc_blocks, meta, hmac_value: str = None, nonce: bytes = None, timestamp: float = None):
    out = {
        "veinn_metadata": {
            "n": int(meta["n"]),
            "rounds": int(meta["rounds"]),
            "layers_per_round": int(meta["layers_per_round"]),
            "shuffle_stride": int(meta["shuffle_stride"]),
            "use_lwe": meta["use_lwe"],
            "mode": meta.get("mode", "numeric"),
            "bytes_per_number": int(meta.get("bytes_per_number", meta["n"] * 2)),
        },
        "enc_seed": [],
        "encrypted": [[int(x) for x in blk.tolist()] for blk in enc_blocks],
    }
    if hmac_value:
        out["hmac"] = hmac_value
    if nonce:
        out["nonce"] = [int(b) for b in nonce]
    if timestamp:
        out["timestamp"] = timestamp
    with open(out_file, "w") as f:
        json.dump(out, f)

def homomorphic_add_files(f1: str, f2: str, out_file: str):
    enc1, meta1, _, _, _ = _load_encrypted_file(f1)
    enc2, meta2, _, _, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    summed = [(a + b) % Q for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, summed, meta1)
    print(f"Lattice-based homomorphic sum saved to {out_file}")

def homomorphic_mul_files(f1: str, f2: str, out_file: str):
    enc1, meta1, _, _, _ = _load_encrypted_file(f1)
    enc2, meta2, _, _, _ = _load_encrypted_file(f2)
    if meta1 != meta2:
        raise ValueError("Encrypted files metadata mismatch")
    if len(enc1) != len(enc2):
        raise ValueError("Encrypted files must have same number of blocks")
    prod = [negacyclic_convolution(a, b, Q) for a, b in zip(enc1, enc2)]
    _write_encrypted_payload(out_file, prod, meta1)
    print(f"Lattice-based homomorphic product saved to {out_file}")
