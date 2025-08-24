# VEINN Documentation

## Overview

VEINN (Vector Encrypted Invertible Neural Network) is a Python-based cryptographic tool that implements a lattice-based invertible neural network for encryption and decryption. It leverages post-quantum cryptography, including the ML-KEM (Kyber) algorithm for key encapsulation, ring convolutions for homomorphic operations, and invertible permutations for secure data transformation. The system supports both asymmetric encryption (using Kyber public/private keys) and symmetric encryption (using a shared seed). It also provides homomorphic addition and multiplication over encrypted data, making it suitable for privacy-preserving computations.
Absolutely! Let’s break down Invertible Neural Networks (INNs) clearly and compare them to standard neural networks.

VEINN functions as a lattice-based invertible neural network (INN) cryptography primitive.
It leverages concepts from both invertible neural networks and lattice-based cryptography to create a system for encryption and homomorphic operations. The network is built from invertible components (coupling layers, shuffling, and scaling) derived from a shared secret seed. The core operations, such as ring convolution, are performed in a finite ring, which is a fundamental aspect of lattice-based cryptography.

- Lattice-based: The ring_convolution operation, especially the ntt method, is a key component derived from number theory and is central to many lattice-based cryptosystems. The lwe_prf_expand function also explicitly uses a learning with errors (LWE) primitive to derive pseudorandom parameters, which is a common building block in post-quantum cryptography.
- INN: The network is explicitly designed to be invertible, with distinct permute_forward and permute_inverse functions. This allows data to be encrypted and then perfectly recovered without loss, a crucial feature for a cryptographic primitive.
- Cryptography Primitive: The system provides functions for encryption (encrypt_with_pub, encrypt_with_public_veinn) and decryption (decrypt_with_priv, decrypt_with_public_veinn), as well as homomorphic operations (homomorphic_add_files, homomorphic_mul_files), making it a tool for secure data manipulation. The parameters are not learned but are derived from a seed, giving the network a fixed, keyed structure suitable for cryptographic use.

### How does this differ from traditional cryptography?
Unlike a block cipher (like AES) which uses a fixed, complex, and non-linear function, VEINN's transformation is a series of elementary invertible functions. It also differs from public-key systems (like RSA) by relying on the difficulty of solving problems on mathematical lattices (like LWE), which is believed to be secure against attacks from quantum computers. The code includes functions for key management and uses Kyber, a post-quantum key encapsulation mechanism, to securely exchange the ephemeral seed. This hybrid approach combines the structural properties of invertible networks with the security foundations of lattice-based cryptography.

### What is the purpose of the modular inverse and ring convolution?
The ring_convolution acts as the non-linear mixing function within the network. It's a key part of the coupling layers, which are essential for the network's expressive power and security. Without it, the network would be a simple linear system and easily broken. The modinv and inv_vec_mod_q functions compute the modular inverse for each element of the ring_scale vector. This is crucial for the network's invertibility, as it allows the permute_inverse function to perfectly undo the scaling operation applied during the forward pass.
Yes, based on the code, it's a lattice-based invertible neural network (INN) cryptography primitive.

It merges two advanced fields of study:
- Invertible Neural Networks: The network's core structure is explicitly designed to be invertible, meaning it has a one-to-one mapping that allows for a forward (encryption) and a perfectly reversible inverse (decryption) process. This is achieved through layered, invertible components like coupling layers and modular scaling.
- Lattice-based Cryptography: The cryptographic security and efficiency of the network are rooted in the mathematics of lattices. The ring_convolution is a key operation that performs polynomial multiplication in a finite ring, a core component of many post-quantum, lattice-based cryptosystems. The use of a Number Theoretic Transform (NTT) is a highly efficient way to implement this convolution. The code also leverages a post-quantum key encapsulation mechanism, Kyber, to securely share the initial seed, which is then used to derive the network's fixed parameters.

This combination creates a system that can not only encrypt and decrypt data but also perform homomorphic operations (like addition and multiplication), which are operations on encrypted data without needing to decrypt it first.

### What is an Invertible Neural Network?

An Invertible Neural Network (INN) is a type of neural network where every mapping from input to output is bijective, meaning it’s one-to-one and onto, and therefore invertible. This means:
	•	For every input x, there is a unique output y.
	•	For every output y, you can uniquely recover the input x.

Formally, if f is an INN:
y = f(x) \quad \text{and} \quad x = f^{-1}(y)
where f^{-1} is the exact inverse function.

This property is not guaranteed in standard neural networks, which often lose information (e.g., through downsampling or non-invertible activations).

### Similarities with Standard Neural Networks

INNs share many characteristics with traditional neural networks:
1.	Layered Structure:
Like standard networks, INNs are composed of layers, often with linear transformations and nonlinear activations.
2. Trainable Parameters:
INNs have weights and biases that are optimized using gradient-based methods.
3.	Backpropagation:
They use backpropagation for training, although some architectures exploit invertibility to compute gradients more efficiently.
4.	Applications:
INNs can be used for supervised learning (classification/regression) and unsupervised learning (density estimation), just like other neural networks.

### How Invertible Neural Networks Work (Mechanism)

INNs usually rely on special layer types to ensure invertibility:

1. Coupling Layers
    - Split input x into two parts: x_1 and x_2.
    - Transform one part using a function of the other:
        y_1 = x_1, \quad y_2 = x_2 + g(x_1)
    - These are easily invertible:
        x_1 = y_1, \quad x_2 = y_2 - g(y_1)

2. Invertible 1x1 Convolutions
    - Permute channels in a reversible way.
    - Common in image-based normalizing flows.

3. Additive or Affine Transformations
    - Maintain invertibility while allowing complex, nonlinear mappings.

### Advantages of INNs
1.	Exact Reconstruction: Can reconstruct inputs perfectly from outputs.
2.	Efficient Memory Use: Can recompute intermediate states instead of storing them.
3.	Density Estimation: Can model probability densities via change-of-variable formula: p_X(x) = p_Y(f(x)) \left|\det \frac{\partial f(x)}{\partial x}\right|

### Summary
- Similarities: Layered, parameterized, trainable via gradient descent, applicable to many ML tasks.
- Differences: Must be invertible, use specialized layers/activations, enable exact input reconstruction, strong use in probabilistic modeling.

Think of INNs as standard neural networks with a built-in “undo” button — you can always reverse the transformation without losing information.

From the code analysis, the most relevant functions for an invertible neural network are:
- coupling_forward
- coupling_inverse
- permute_forward
- permute_inverse

Here’s why these qualify as components of an Invertible Neural Network (INN):

1. Coupling Layers
	- coupling_forward and coupling_inverse implement a bijective transformation where part of the input is transformed based on another part, similar to affine coupling layers used in INNs.
	- This satisfies the INN property: the transformation is reversible, and no information is lost.

Formally, if the input is split as x = (x_1, x_2):
y_1 = x_1, \quad y_2 = x_2 + g(x_1)
Then coupling_inverse computes:
x_1 = y_1, \quad x_2 = y_2 - g(y_1)
This guarantees exact reconstruction.


2. Permutation Layers
- permute_forward and permute_inverse implement invertible shuffling of components.
- These are analogous to invertible 1x1 convolutions or channel permutations in normalizing flows.
- They preserve information while rearranging it, which is critical for mixing features in an INN.


3. Why this qualifies as an INN
- Every forward transformation has a corresponding inverse: This is the key property of invertibility.
- No information is lost: Coupling + permutation layers ensure bijectivity.
- Structured like a neural network: These functions are used in layers and repeated (via rounds/layers in VeinnParams) to form a deep, trainable mapping.


## Key features:
- **Post-Quantum Security**: Uses ML-KEM_768 for ~128-bit security.
- **Invertible Neural Network**: Employs coupling layers, shuffling, and scaling for reversible transformations.
- **Homomorphic Operations**: Supports addition and multiplication on encrypted blocks using ring convolutions.
- **Key Management**: Includes a keystore for secure storage of private keys and seeds.
- **Modes**: Text mode (`t`) for string messages and numeric mode (`n`) for lists of integers.
- **CLI Interface**: Interactive menu and command-line arguments for operations like key generation, encryption, decryption, and homomorphic computations.

The code is structured into sections: utilities, ring operations, coupling layers, shuffling, key derivation, permutation functions, block handling, homomorphic operations, key management, encryption/decryption, serialization, and CLI handlers.

Global constants:
- `Q`: Large prime modulus (default: 65537).
- `DTYPE`: NumPy data type (np.int64).
- `VeinnParams`: Default parameters (n=256, rounds=10, layers_per_round=10, shuffle_stride=11, use_lwe=True, valid=3600, seed_len=32, q=Q).

Dependencies: os, sys, json, math, hashlib, hmac, secrets, numpy, argparse, pickle, time, typing, cryptography (fernet, pbkdf2, hashes), base64, dataclasses, kyber_py (ML_KEM_768).

**Note**: The code assumes no internet access and uses pre-installed libraries. Some RSA-related functions are commented out and not documented here.

## Data Classes

### VeinnParams
Dataclass for core parameters.

- **Fields**:
  - `n: int = 256`: Number of int64 words per block.
  - `rounds: int = 10`: Number of permutation rounds.
  - `layers_per_round: int = 10`: Coupling layers per round.
  - `shuffle_stride: int = 11`: Stride for shuffling (must be coprime with n).
  - `use_lwe: bool = True`: Use LWE PRF for nonlinearity.
  - `valid: int = 3600`: Timestamp validity window in seconds.
  - `seed_len: int = 32`: Seed length in bytes.
  - `q: int = Q`: Modulus.

### CouplingParams
Dataclass for coupling layer parameters.

- **Fields**:
  - `mask_a: np.ndarray`: Mask for first half.
  - `mask_b: np.ndarray`: Mask for second half.

### RoundParams
Dataclass for round parameters.

- **Fields**:
  - `cpls: list[CouplingParams]`: List of coupling parameters.
  - `ring_scale: np.ndarray`: Elementwise odd scaling factors (invertible mod q).
  - `ring_scale_inv: np.ndarray`: Modular inverses of ring_scale.

### VeinnKey
Dataclass for the derived key.

- **Fields**:
  - `seed: bytes`: Seed bytes.
  - `params: VeinnParams`: Parameters.
  - `shuffle_idx: np.ndarray`: Shuffle indices.
  - `rounds: list[RoundParams]`: Per-round parameters.

## Utilities

### shake(expand_bytes: int, *chunks: bytes) -> bytes
Pseudorandom function using SHAKE-256.

- **Parameters**:
  - `expand_bytes`: Number of bytes to output.
  - `*chunks`: Variable bytes chunks to hash.
- **Returns**: Expanded bytes.
- **Description**: Hashes chunks with lengths prefixed, then digests.

### derive_u16(count: int, vp: VeinnParams, *chunks: bytes) -> np.ndarray
Derives uint16-like values (mod q).

- **Parameters**:
  - `count`: Number of values.
  - `vp`: VeinnParams instance.
  - `*chunks`: Bytes chunks.
- **Returns**: NumPy array of DTYPE values.
- **Description**: Uses LWE if enabled, else direct shake.

### odd_constant_from_key(tag: bytes) -> int
Derives an odd constant mod q.

- **Parameters**:
  - `tag`: Bytes tag.
- **Returns**: Odd integer mod q.

### pkcs7_pad(data: bytes, block_size: int) -> bytes
PKCS7 padding.

- **Parameters**:
  - `data`: Bytes to pad.
  - `block_size`: Block size.
- **Returns**: Padded bytes.
- **Raises**: None (assumes valid input).

### pkcs7_unpad(data: bytes) -> bytes
PKCS7 unpadding.

- **Parameters**:
  - `data`: Padded bytes.
- **Returns**: Unpadded bytes.
- **Raises**: ValueError on invalid padding.

## Ring Convolution Operations

### ring_convolution(a, b, q, method="ntt")
Ring convolution mod q.

- **Parameters**:
  - `a, b`: NumPy arrays.
  - `q`: Modulus.
  - `method`: "naive", "fft", or "ntt" (default).
- **Returns**: Convolved array.
- **Raises**: ValueError on invalid method.

### iterative_ntt(a: np.ndarray, root: int, q: int) -> np.ndarray
Iterative Number Theoretic Transform.

- **Parameters**:
  - `a`: Input array.
  - `root`: Primitive root.
  - `q`: Modulus.
- **Returns**: Transformed array.

### iterative_intt(A: np.ndarray, root: int, q: int) -> np.ndarray
Iterative Inverse NTT.

- **Parameters**:
  - `A`: Transformed array.
  - `root`: Primitive root.
  - `q`: Modulus.
- **Returns**: Inverse transformed array.

### mod_mul(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray
Modular multiplication.

- **Parameters**:
  - `a, b`: Arrays.
  - `q`: Modulus.
- **Returns**: (a * b) % q.

### find_primitive_root(q)
Finds primitive root mod q.

- **Parameters**:
  - `q`: Prime modulus.
- **Returns**: Primitive root or None.

### factorize(n)
Factorizes n.

- **Parameters**:
  - `n`: Integer.
- **Returns**: List of prime factors.

### lwe_prf_expand(seed: bytes, out_n: int, vp: VeinnParams) -> np.ndarray
LWE-based PRF expansion.

- **Parameters**:
  - `seed`: Bytes seed.
  - `out_n`: Output length.
  - `vp`: Parameters.
- **Returns**: Expanded array.
- **Description**: Generates s, A, e, computes b = a*s + e mod q.

## Coupling Layers

### coupling_forward(x: np.ndarray, cp: CouplingParams) -> np.ndarray
Forward coupling transformation.

- **Parameters**:
  - `x`: Input array.
  - `cp`: CouplingParams.
- **Returns**: Transformed array.
- **Raises**: AssertionError on shape mismatch.

### coupling_inverse(x: np.ndarray, cp: CouplingParams) -> np.ndarray
Inverse coupling.

- **Parameters**:
  - `x`: Input array.
  - `cp`: CouplingParams.
- **Returns**: Inverse transformed array.
- **Raises**: AssertionError on shape mismatch.

## Shuffling

### make_shuffle_indices(n: int, stride: int) -> np.ndarray
Generates shuffle indices.

- **Parameters**:
  - `n`: Length.
  - `stride`: Stride (coprime with n).
- **Returns**: Indices array.
- **Raises**: ValueError if not coprime.

### shuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray
Shuffles array.

- **Parameters**:
  - `x`: Input.
  - `idx`: Indices.
- **Returns**: Shuffled array.
- **Raises**: AssertionError on shape mismatch.

### unshuffle(x: np.ndarray, idx: np.ndarray) -> np.ndarray
Unshuffles array.

- **Parameters**:
  - `x`: Input.
  - `idx`: Indices.
- **Returns**: Unshuffled array.
- **Raises**: AssertionError on shape mismatch.

## Modular Inverses

### modinv(a: int, m: int) -> int
Modular inverse using extended Euclid.

- **Parameters**:
  - `a`: Integer.
  - `m`: Modulus.
- **Returns**: Inverse.
- **Raises**: ValueError if no inverse.

### inv_vec_mod_q(arr: np.ndarray) -> np.ndarray
Vector modular inverses.

- **Parameters**:
  - `arr`: Array.
- **Returns**: Inverses array.

### ensure_coprime_to_q_vec(vec, q)
Ensures vector elements coprime to q.

- **Parameters**:
  - `vec`: Array.
  - `q`: Modulus.
- **Returns**: Adjusted array.

## Key Derivation

### key_from_seed(seed: bytes, vp: VeinnParams) -> VeinnKey
Derives VeinnKey from seed.

- **Parameters**:
  - `seed`: Bytes.
  - `vp`: Parameters.
- **Returns**: VeinnKey.
- **Description**: Generates shuffle indices, coupling masks, scales.

## Permutations

### permute_forward(x: np.ndarray, key: VeinnKey) -> np.ndarray
Forward permutation.

- **Parameters**:
  - `x`: Input block.
  - `key`: VeinnKey.
- **Returns**: Permuted array.
- **Raises**: AssertionError on shape mismatch.

### permute_inverse(x: np.ndarray, key: VeinnKey) -> np.ndarray
Inverse permutation.

- **Parameters**:
  - `x`: Encrypted block.
  - `key`: VeinnKey.
- **Returns**: Decrypted array.
- **Raises**: AssertionError on shape mismatch.

## Block Handling

### bytes_to_block(b: bytes, n: int) -> np.ndarray
Converts bytes to block array.

- **Parameters**:
  - `b`: Bytes.
  - `n`: Block size.
- **Returns**: Array of uint16 values.

### block_to_bytes(x: np.ndarray) -> bytes
Converts array to bytes.

- **Parameters**:
  - `x`: Array.
- **Returns**: Bytes.

## Homomorphic Operations

### _load_encrypted_file(enc_file: str)
Loads encrypted file (internal).

- **Parameters**:
  - `enc_file`: Path.
- **Returns**: (enc_blocks, meta, hmac, nonce, timestamp).

### _write_encrypted_payload(out_file: str, enc_blocks, meta, hmac_value: str = None, nonce: bytes = None, timestamp: float = None)
Writes encrypted payload (internal).

- **Parameters**:
  - `out_file`: Path.
  - `enc_blocks`: List of arrays.
  - `meta`: Dict.
  - Optional: hmac_value, nonce, timestamp.
- **Description**: Saves as JSON.

### homomorphic_add_files(f1: str, f2: str, out_file: str)
Homomorphic addition.

- **Parameters**:
  - `f1, f2`: Encrypted files.
  - `out_file`: Output.
- **Raises**: ValueError on mismatch.
- **Description**: Adds blocks mod q.

### homomorphic_mul_files(f1: str, f2: str, out_file: str)
Homomorphic multiplication.

- **Parameters**:
  - `f1, f2`: Encrypted files.
  - `out_file`: Output.
- **Raises**: ValueError on mismatch.
- **Description**: Multiplies via ring convolution.

## Key Management

### create_keystore(passphrase: str, keystore_file: str)
Creates keystore.

- **Parameters**:
  - `passphrase`: String.
  - `keystore_file`: Path.
- **Description**: Uses PBKDF2 for key derivation, saves pickle.

### load_keystore(passphrase: str, keystore_file: str)
Loads keystore.

- **Parameters**:
  - `passphrase`: String.
  - `keystore_file`: Path.
- **Returns**: (keystore dict, Fernet instance).

### store_key_in_keystore(passphrase: str, key_name: str, key_data: dict, keystore_file: str)
Stores key in keystore.

- **Parameters**:
  - `passphrase`: String.
  - `key_name`: Name.
  - `key_data`: Dict to store.
  - `keystore_file`: Path.

### retrieve_key_from_keystore(passphrase: str, key_name: str, keystore_file: str) -> dict
Retrieves key.

- **Parameters**:
  - `passphrase`: String.
  - `key_name`: Name.
  - `keystore_file`: Path.
- **Returns**: Decrypted dict.
- **Raises**: ValueError on failure.

## Kyber Key Generation

### generate_kyber_keypair() -> dict
Generates ML-KEM keypair.

- **Returns**: {"ek": list (encapsulation key), "dk": list (decapsulation key)}.

## Encryption/Decryption

### derive_seed_bytes(nonce: bytes, seed_len: int = 32) -> bytes
Derives seed from nonce.

- **Parameters**:
  - `nonce`: Bytes.
  - `seed_len`: Length.
- **Returns**: Seed bytes.

### oaep_encode(message: bytes, n: int, seed: bytes) -> int
OAEP encoding (using SHAKE).

- **Parameters**:
  - `message`: Bytes.
  - `n`: Modulus (for size).
  - `seed`: Bytes.
- **Returns**: Encoded integer.
- **Raises**: ValueError if message too long.

### oaep_decode(cipher_int: int, n: int) -> bytes
OAEP decoding.

- **Parameters**:
  - `cipher_int`: Integer.
  - `n`: Modulus.
- **Returns**: Decoded bytes.
- **Raises**: ValueError on invalid format.

### validate_timestamp(timestamp: float, validity_window: int) -> bool
Checks timestamp validity.

- **Parameters**:
  - `timestamp`: Unix time.
  - `validity_window`: Seconds.
- **Returns**: True if valid.

### veinn_from_seed(seed_input: str, vp: VeinnParams)
Derives and prints VeinnKey (CLI helper).

- **Parameters**:
  - `seed_input`: String seed.
  - `vp`: Parameters.

### encrypt_with_pub(pubfile: str, message: Optional[str] = None, numbers: Optional[list] = None, in_path: Optional[str] = None, mode: str = "t", vp: VeinnParams = VeinnParams(), seed_len: int = 32, nonce: Optional[bytes] = None, out_file: str = "enc_pub.json") -> str
Asymmetric encryption with Kyber.

- **Parameters**:
  - `pubfile`: Public key path.
  - `message`: Text (for mode "t").
  - `numbers`: List of ints (for mode "n").
  - `in_path`: Input file (alternative to message/numbers).
  - `mode`: "t" or "n".
  - `vp`: Parameters.
  - `seed_len`: Seed length.
  - `nonce`: Optional nonce.
  - `out_file`: Output path.
- **Returns**: Output path.
- **Raises**: ValueError on missing input.
- **Description**: Encapsulates seed with Kyber, derives key, permutes blocks, adds HMAC/timestamp.

### decrypt_with_priv(keystore: Optional[str], privfile: Optional[str], encfile: str, passphrase: Optional[str], key_name: Optional[str], validity_window: int)
Asymmetric decryption.

- **Parameters**:
  - `keystore`: Keystore path (if using).
  - `privfile`: Private key path (if not keystore).
  - `encfile`: Encrypted file.
  - `passphrase`: For keystore.
  - `key_name`: In keystore.
  - `validity_window`: Seconds.
- **Raises**: ValueError on failures (HMAC, timestamp).
- **Description**: Decapsulates seed, verifies HMAC/timestamp, inverse permutes.

### encrypt_with_public_veinn(seed_input: str, message: Optional[str] = None, numbers: Optional[list] = None, vp: VeinnParams = VeinnParams(), out_file: str = "enc_pub_veinn.json", mode: str = "t", bytes_per_number: Optional[int] = None, nonce: Optional[bytes] = None) -> str
Symmetric encryption with shared seed.

- **Parameters**:
  - `seed_input`: String seed.
  - `message`: Text.
  - `numbers`: Ints.
  - `vp`: Parameters.
  - `out_file`: Output.
  - `mode`: "t" or "n".
  - `bytes_per_number`: For numeric mode.
  - `nonce`: Optional.
- **Returns**: Output path.
- **Raises**: ValueError on missing input.

### decrypt_with_public_veinn(seed_input: str, enc_file: str, validity_window: int)
Symmetric decryption.

- **Parameters**:
  - `seed_input`: String seed.
  - `enc_file`: Encrypted file.
  - `validity_window`: Seconds.
- **Raises**: ValueError on failures.

## Serialization

### write_ciphertext_json(path: str, encrypted_blocks: list, metadata: dict, enc_seed_bytes: bytes, hmac_value: str = None, nonce: bytes = None, timestamp: float = None)
Writes ciphertext as JSON.

- **Parameters**:
  - `path`: Payload path (also writes "key_" + path for metadata).
  - `encrypted_blocks`: List of arrays.
  - `metadata`: Dict.
  - `enc_seed_bytes`: Kyber ciphertext.
  - Optional: hmac_value, nonce, timestamp.
- **Description**: Base64 encodes seed/nonce.

### read_ciphertext(path: str)
Reads ciphertext.

- **Parameters**:
  - `path`: Payload path.
- **Returns**: (metadata, enc_seed, enc_blocks, hmac_value, nonce, timestamp).

## CLI Functions

These are interactive menu helpers and not intended for direct calls. The main entry point is `main()`, which parses args or runs an interactive loop.

- `menu_generate_keystore()`, `menu_generate_kyber_keypair()`, etc.: Prompt-based wrappers.
- `main()`: Handles CLI args or menu.