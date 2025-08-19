# veinn/__init__.py
from .params import Q, DTYPE, VeinnParams
from .utils import (
    shake, derive_u16, odd_constant_from_key,
    pkcs7_pad, pkcs7_unpad, derive_seed_bytes,
    int_to_bytes_be, bytes_be_to_int,
)
from .ring import negacyclic_convolution
from .coupling import CouplingParams, coupling_forward, coupling_inverse
from .shuffle import make_shuffle_indices, shuffle, unshuffle
from .key_schedule import RoundParams, VeinnKey, key_from_seed
from .permutation import permute_forward, permute_inverse
from .serialization import bytes_to_block, block_to_bytes, write_ciphertext_json, read_ciphertext
from .homomorphic import homomorphic_add_files, homomorphic_mul_files
from .keystore import create_keystore, load_keystore, store_key_in_keystore, retrieve_key_from_keystore
from .rsa_oaep import (
    is_probable_prime, gen_prime, egcd, modinv,
    generate_rsa_keypair, oaep_encode, oaep_decode,
    validate_timestamp,
)
from .public_api import (
    veinn_from_seed,
    encrypt_with_pub, decrypt_with_priv,
    encrypt_with_public_veinn, decrypt_with_public_veinn,
)
