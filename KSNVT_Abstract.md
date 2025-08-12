# Key-Seeded Invertible Nonlinear Vector Transforms for Post-Quantum Cryptography

## Synopsis:
This work proposes a novel approach to post-quantum cryptography (PQC) leveraging key-seeded nonlinear invertible transforms acting on vectorized messages. By using secret keys as seeds to generate parameters of nonlinear yet exactly invertible mappings—such as affine coupling layers inspired by invertible neural networks—messages are encrypted into high-dimensional vectors. Decryption requires the secret key to exactly invert these transforms, while attackers face the complexity of inverting nonlinear mappings without a trapdoor.

The approach aims to:

* Break the algebraic linearity exploited by quantum algorithms like Shor’s, using nonlinear, high-dimensional mappings.

* Provide exact invertibility, enabling lossless decryption via the trapdoor key.

* Introduce large key spaces and parameterized transforms resistant to classical and quantum cryptanalysis.

* Lay groundwork for embedding noise/error tolerance to increase hardness, akin to lattice-based PQC.

This method combines concepts from neural networks, nonlinear dynamics, and cryptography to offer a promising PQC candidate that moves beyond number-theoretic hardness assumptions.