# Vector-Based Invertible Neural Networks for Experimental PQC

## Overview
This repository explores using high-dimensional vector spaces and invertible neural networks (INNs) to experiment with post-quantum resistant encryption. The goal is to step from a linear message space into a continuous, high-dimensional vector space, where key-dependent nonlinear transformations make inversion without the key difficult.

## Key Features
- **Vectorized message encoding:** Messages are converted to float vectors in [-1,1] for INN transformations.
- **Invertible neural network layers:** Affine coupling layers provide nonlinear, reversible transformations.
- **Deterministic key-derived noise:** Ensures exact invertibility for legitimate decryption.
- **File-based key/vector persistence:** Save encrypted vectors and keys for later decryption.
- **Configurable layers:** Number of INN layers can be set at runtime for experimentation.
- **Test and benchmark scripts:** Separate files allow validation and performance evaluation.

## Motivation
Quantum algorithms pose risks to classical encryption. Embedding plaintext into vector spaces with nonlinear transformations explores a novel layer of potential quantum resistance. Minor reconstruction drift is acceptable for security while enabling legitimate decryption.

## Disclaimer
- This is an **experimental research framework**, not a production-ready PQC system.
- Security has **not been formally analyzed**. Use for learning and prototyping only.

## Getting Started

### Requirements
- Python 3.9+
- Numpy

    ```bash
    pip install numpy
    ```

### Files
- `cli/ksnvt.py` – Main CLI for encryption/decryption with file persistence.
- `cli/tests.py` – Test multiple messages using a saved encrypted vector file.
- `cli/benchmark.py` – Benchmark encryption/decryption performance and reconstruction error.

## Usage

### Encrypt & Save
    ```bash
    python3 cli/ksnvt.py
    ```
1. Choose `1) Encrypt & save`.
2. Enter your message.
3. Set the number of INN layers (default 10).
4. Provide a filename to save the encrypted vector.
5. The encryption key (hex) will be displayed; keep it safe.

### Load & Decrypt
    ```bash
    python3 cli/ksnvt.py
    ```
1. Choose `2) Load & decrypt`.
2. Provide the encrypted vector filename.
3. Enter the number of INN layers used during encryption.
4. Decrypted message will be displayed.

## Testing
    ```bash
    python3 cli/tests.py
    ```
- Prompts for the encrypted vector file.
- Tests multiple messages for correct reconstruction using the saved key.

## Benchmarking
    ```bash
    python3 cli/benchmark.py
    ```
- Prompts for the encrypted vector file.
- Optionally set the number of INN layers.
- Reports encryption/decryption times and reconstruction error.

## Example Workflow

### 1. Encrypt a Message
    ```bash
    $ python3 cli/ksnvt.py
    Choose action:
    1) Encrypt & save
    2) Load & decrypt
    1
    Message to encrypt: Hello PQC world!
    Number of INN layers (default 10): 12
    Save encrypted data to filename: encrypted_vector.npz
    Encrypted vector saved to encrypted_vector.npz
    Encryption key (hex): 8f2a1b... (keep this safe)
    Layers used: 12
    ```

### 2. Decrypt a Message
    ```bash
    $ python3 cli/ksnvt.py
    Choose action:
    1) Encrypt & save
    2) Load & decrypt
    2
    Enter encrypted vector file to load: encrypted_vector.npz
    Number of INN layers used during encryption: 12
    Decrypted message: Hello PQC world!
    Layers used: 12
    ```

### 3. Run Tests
    ```bash
    $ python3 cli/tests.py
    Enter encrypted vector file to test: encrypted_vector.npz
    Testing message: Hello PQC world!
    Success!
    Testing message: 🚀 Unicode test 🌟
    Success!
    Testing message: Null byte test:
    Success!
    ```

### 4. Run Benchmark
    ```bash
    $ python3 cli/benchmark.py
    Enter encrypted vector file for benchmark: encrypted_vector.npz
    Number of INN layers (default 10): 12
    Benchmarking file: encrypted_vector.npz, vector dim=32, layers=12
    Encryption time: 0.002134s
    Decryption time: 0.002048s
    Reconstruction error (L2 norm): 0.000000e+00
    ```

## Contributing & Feedback
- This is an experimental PQC research project. Feedback from the cryptography community is welcome.
- Suggestions for improving invertible vector transformations, benchmarking, or formal security analysis are encouraged.

## License
[MIT](https://opensource.org/license/mit)
