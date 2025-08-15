# VEINN: Vector Encrypted Invertible Neural Network
**An Experimental Framework for Vector-Space Symmetric Encryption with Invertible Neural Layers**

---

## Abstract
VEINN (Vector Encrypted Invertible Neural Network) is an experimental symmetric encryption scheme that transforms plaintext into continuous, high-dimensional vector space and applies key-derived nonlinear transformations via invertible neural network (INN) layers. Deterministic, key-based noise is injected at each layer to increase polymorphism and hinder cryptanalysis. Unlike classical symmetric encryption, which operates in discrete integer spaces, VEINN operates in continuous floating-point domains, providing tunable scalability in layers, vector dimensions, and noise levels. While not a production-ready system, VEINN introduces a novel approach to post-quantum cryptography (PQC) by combining neural-network-inspired architectures with traditional symmetric key concepts.

---

## Introduction
Quantum computing poses challenges to public-key cryptography, particularly those relying on factoring or discrete logarithms. Symmetric cryptography is less vulnerable, but advances in algorithmic cryptanalysis still motivate exploration of novel approaches.

VEINN proposes embedding plaintext into continuous vector spaces, then applying multi-layer, key-derived affine coupling transformations with invertibility guarantees. This shifts encryption from a discrete combinatorial problem to one resembling nonlinear dynamical systems, potentially expanding the attack surface's complexity.

---

## Methodology

### 1. Vectorization of Plaintext
1. Plaintext is Base64-encoded.
2. Encoded bytes are normalized to the range `[-1, 1]`.
3. Padding ensures an even-length vector suitable for coupling layers.

### 2. Invertible Neural Network Layers
- Each layer splits the vector into two halves.
- One half is transformed using a **key-derived scale and shift**, generated deterministically from the encryption key.
- Affine coupling layers guarantee reversibility.

### 3. Layer-wise Noise Injection
- Deterministic, key-derived Gaussian noise is added at each layer.
- Noise is small enough to permit exact decryption but diversifies ciphertext even for identical plaintext and keys.

### 4. Decryption
- Noise is subtracted deterministically using the same key.
- Layers are applied in reverse order with inverted transformations.

---

## Novelty and Non-Triviality
- **Continuous Vector Domain** – Encryption operates in floating-point space rather than finite integer fields.
- **Structural Polymorphism** – Variable numbers of layers, noise levels, and vector sizes.
- **Parameter Polymorphism** – Key-derived parameters differ per layer, producing unique transformation graphs for each key.
- **Tunable Scalability** – Security complexity can be increased by adding layers, increasing vector size, or altering noise amplitude.

---

## Comparison with Existing Cryptographic Approaches

| Feature               | VEINN                              | AES / Symmetric Ciphers   | Kyber / Lattice PQC         |
|-----------------------|-------------------------------------|---------------------------|-----------------------------|
| Data Space            | Continuous floating-point           | Discrete finite field     | Discrete finite ring        |
| Transformation Type   | Neural affine coupling              | Substitution–permutation  | Polynomial ring arithmetic  |
| Invertibility         | Guaranteed via INN                  | Guaranteed via SPN        | Guaranteed via lattice trapdoor |
| Noise                 | Key-derived, per-layer Gaussian     | None                      | Error vector (LWE)          |
| PQC Relevance         | Experimental                        | Classical secure          | NIST PQC finalist           |

---

## Polymorphism in VEINN
- **Structural polymorphism**: Layer count, vector size, noise profile can change per encryption session.
- **Parameter polymorphism**: Scale and shift parameters vary deterministically with both the key and the layer index.
- **Extensibility**: Could introduce different coupling types, nonlinearities, or random topology graphs.

---

## PQC Implications and Hybridization
While symmetric schemes are inherently more resilient to quantum attacks, VEINN's unique structure could be wrapped around standard PQC key exchanges (e.g., Kyber) for hybrid encryption. In such a model, VEINN encrypts the payload using a symmetric key delivered via PQC key exchange.

---

## Limitations & Disclaimer
- No formal cryptanalysis performed.
- Floating-point operations may introduce platform-dependent behavior.
- Currently intended for research, testing, and conceptual exploration only.

---

## Future Work
- Formal security proofs.
- Statistical resistance testing against known-plaintext and chosen-ciphertext attacks.
- Hybrid protocols integrating VEINN with lattice-based key exchange.

---

**License:** MIT
