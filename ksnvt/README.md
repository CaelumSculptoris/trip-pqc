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