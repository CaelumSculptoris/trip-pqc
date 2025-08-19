# veinn/public_api.py
import math
import hmac
import time
import secrets
import json
from base64 import b64decode
from params import Q, DTYPE, VeinnParams
from key_schedule import key_from_seed
from permutation import permute_forward, permute_inverse
from serialization import bytes_to_block, block_to_bytes, write_ciphertext_json, read_ciphertext
from utils import pkcs7_pad, pkcs7_unpad, derive_seed_bytes, int_to_bytes_be, bytes_be_to_int
from rsa_oaep import generate_rsa_keypair, oaep_encode, oaep_decode, validate_timestamp

def veinn_from_seed(seed_input: str, vp: VeinnParams):
    seed = seed_input.encode("utf-8")
    _ = key_from_seed(seed, vp)
    print(f"Derived VEINN key with params: n={vp.n}, rounds={vp.rounds}, layers_per_round={vp.layers_per_round}, shuffle_stride={vp.shuffle_stride}, use_lwe={vp.use_lwe}")

def encrypt_with_pub(pubfile: str, message: str | None = None, numbers: list | None = None, in_path: str | None = None, mode: str = "text", vp: VeinnParams = VeinnParams(), seed_len: int = 32, nonce: bytes | None = None, out_file: str = "enc_pub.json") -> str:
    with open(pubfile, "r") as f:
        pub = json.load(f)
    n = pub["n"]; e = pub["e"]
    if in_path:
        with open(in_path, "rb") as f:
            message_bytes = f.read()
    elif mode == "text":
        if not message:
            raise ValueError("Message required for text mode")
        message_bytes = message.encode("utf-8")
    else:
        if not numbers:
            raise ValueError("Numbers required for numeric mode")
        bytes_per_number = vp.n * 2
        message_bytes = b"".join(int(num).to_bytes(bytes_per_number, "big", signed=True) for num in numbers)

    message_bytes = pkcs7_pad(message_bytes, vp.n * 2)
    nonce = nonce or secrets.token_bytes(16)
    ephemeral_seed = derive_seed_bytes(nonce, seed_len)
    k = key_from_seed(ephemeral_seed, vp)

    blocks = [bytes_to_block(message_bytes[i:i + vp.n * 2], vp.n) for i in range(0, len(message_bytes), vp.n * 2)]
    enc_blocks = [permute_forward(b, k) for b in blocks]

    seed_int = oaep_encode(ephemeral_seed, n, nonce)
    enc_seed = pow(seed_int, e, n)
    enc_seed_bytes = int_to_bytes_be(enc_seed)

    metadata = {
        "n": vp.n, "rounds": vp.rounds, "layers_per_round": vp.layers_per_round,
        "shuffle_stride": vp.shuffle_stride, "use_lwe": vp.use_lwe,
        "mode": mode, "bytes_per_number": vp.n * 2
    }
    timestamp = time.time()
    msg_for_hmac = enc_seed_bytes + b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, "big")
    hmac_value = hmac.new(ephemeral_seed, msg_for_hmac, hashlib.sha256).hexdigest()

    write_ciphertext_json(out_file, enc_blocks, metadata, enc_seed_bytes, hmac_value, nonce, timestamp)
    print(f"Encrypted to {out_file}")
    return out_file

def decrypt_with_priv(keystore: str | None, privfile: str | None, encfile: str, passphrase: str | None, key_name: str | None, validity_window: int):
    if keystore and passphrase and key_name:
        from .keystore import retrieve_key_from_keystore
        privkey = retrieve_key_from_keystore(passphrase, key_name, keystore)
    else:
        with open(privfile, "r") as f:
            privkey = json.load(f)
    n = privkey["n"]; d = privkey["d"]
    metadata, enc_seed_bytes, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(encfile)
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError("Timestamp outside validity window")
    enc_seed = bytes_be_to_int(enc_seed_bytes)
    seed_int = pow(enc_seed, d, n)
    ephemeral_seed = oaep_decode(seed_int, n, nonce)
    msg_for_hmac = enc_seed_bytes + b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, "big")
    import hashlib
    if not hmac.compare_digest(hmac.new(ephemeral_seed, msg_for_hmac, hashlib.sha256).hexdigest(), hmac_value):
        raise ValueError("HMAC verification failed")
    vp = VeinnParams(
        n=metadata["n"], rounds=metadata["rounds"],
        layers_per_round=metadata["layers_per_round"],
        shuffle_stride=metadata["shuffle_stride"],
        use_lwe=metadata["use_lwe"]
    )
    k = key_from_seed(ephemeral_seed, vp)
    dec_blocks = [permute_inverse(b, k) for b in enc_blocks]
    dec_bytes = pkcs7_unpad(b"".join(block_to_bytes(b) for b in dec_blocks))
    mode = metadata.get("mode", "numeric")
    if mode == "text":
        print("Decrypted message:", dec_bytes.decode("utf-8"))
    else:
        bytes_per_number = metadata.get("bytes_per_number", vp.n * 2)
        numbers = [int.from_bytes(dec_bytes[i:i + bytes_per_number], "big", signed=True) for i in range(0, len(dec_bytes), bytes_per_number)]
        print("Decrypted numbers:", numbers)

def encrypt_with_public_veinn(seed_input: str, message: str | None = None, numbers: list | None = None, vp: VeinnParams = VeinnParams(), out_file: str = "enc_pub_veinn.json", mode: str = "text", bytes_per_number: int | None = None, nonce: bytes | None = None) -> str:
    seed = seed_input.encode("utf-8")
    k = key_from_seed(seed, vp)
    if message or mode == "text":
        if not message:
            raise ValueError("Message required for text mode")
        message_bytes = message.encode("utf-8")
    else:
        if not numbers:
            raise ValueError("Numbers required for numeric mode")
        if not bytes_per_number:
            bytes_per_number = vp.n * 2
        message_bytes = b"".join(int(num).to_bytes(bytes_per_number, "big", signed=True) for num in numbers)

    message_bytes = pkcs7_pad(message_bytes, vp.n * 2)
    nonce = nonce or secrets.token_bytes(16)
    blocks = [bytes_to_block(message_bytes[i:i + vp.n * 2], vp.n) for i in range(0, len(message_bytes), vp.n * 2)]
    enc_blocks = [permute_forward(b, k) for b in blocks]
    metadata = {
        "n": vp.n, "rounds": vp.rounds, "layers_per_round": vp.layers_per_round,
        "shuffle_stride": vp.shuffle_stride, "use_lwe": vp.use_lwe,
        "mode": mode, "bytes_per_number": bytes_per_number or vp.n * 2
    }
    timestamp = time.time()
    import hashlib
    msg_for_hmac = b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, "big")
    hmac_value = hmac.new(seed, msg_for_hmac, hashlib.sha256).hexdigest()
    write_ciphertext_json(out_file, enc_blocks, metadata, b"", hmac_value, nonce, timestamp)
    print(f"Encrypted to {out_file}")
    return out_file

def decrypt_with_public_veinn(seed_input: str, enc_file: str, validity_window: int):
    seed = seed_input.encode("utf-8")
    metadata, _, enc_blocks, hmac_value, nonce, timestamp = read_ciphertext(enc_file)
    if not validate_timestamp(timestamp, validity_window):
        raise ValueError("Timestamp outside validity window")
    import hashlib
    msg_for_hmac = b"".join(block_to_bytes(b) for b in enc_blocks) + math.floor(timestamp).to_bytes(8, "big")
    if not hmac.compare_digest(hmac.new(seed, msg_for_hmac, hashlib.sha256).hexdigest(), hmac_value):
        raise ValueError("HMAC verification failed")
    vp = VeinnParams(
        n=metadata["n"], rounds=metadata["rounds"],
        layers_per_round=metadata["layers_per_round"],
        shuffle_stride=metadata["shuffle_stride"],
        use_lwe=metadata["use_lwe"]
    )
    k = key_from_seed(seed, vp)
    dec_blocks = [permute_inverse(b, k) for b in enc_blocks]
    dec_bytes = pkcs7_unpad(b"".join(block_to_bytes(b) for b in dec_blocks))
    mode = metadata.get("mode", "numeric")
    if mode == "text":
        print("Decrypted message:", dec_bytes.decode("utf-8"))
    else:
        bytes_per_number = metadata.get("bytes_per_number", vp.n * 2)
        numbers = [int.from_bytes(dec_bytes[i:i + bytes_per_number], "big", signed=True) for i in range(0, len(dec_bytes), bytes_per_number)]
        print("Decrypted numbers:", numbers)
