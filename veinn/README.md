![alt text](veinn.jpg "But you have heard of me.")
# VEINN: Vector Encrypted Invertible Neural Network

VEINN is a **post-quantum cryptographic** primitive that combines:

- **Invertible Neural Networks (INNs)**  
- **Lattice-based cryptography (LWE/RLWE hardness)**  
- **Homomorphic encryption features**  

to form a **vector-space symmetric cipher** with **post-quantum security assumptions**.  

VEINN encrypts data blockwise as vectors in $\mathbb{Z}_{2^{16}}^n$, applying coupling layers, modular scalings, and shuffles derived from a seed. Optionally, **Learning With Errors (LWE)**-based pseudorandom functions (PRFs) are used in the key schedule, embedding lattice hardness. The result is a **fast, invertible, lattice-secure block cipher** that supports **homomorphic addition and multiplication**.

---

## ✨ Features

- 🔑 **Seed-based symmetric cipher** with compact key derivation.  
- 🔄 **Invertible neural network structure** (coupling layers, modular scaling, shuffles).  
- 🧮 **Lattice security** via LWE-based PRF for mask/scale derivation.  
- ➕ **Homomorphic addition** of ciphertexts (plaintext sums preserved).  
- ✖️ **Homomorphic multiplication** via negacyclic convolution (plaintext product in ring).  
- ⚡ **Efficient vectorized arithmetic**: modular 16-bit ops, SIMD/GPU-friendly.  
- 📦 **Metadata + HMAC** included for integrity and replay protection.  
- 🔐 **Post-quantum resistance** against both classical and quantum attacks.  

---

## 📂 Project Structure

```
veinn.py        # Core VEINN implementation (encryption, decryption, key schedule)
README.md       # Project overview (this file)
```

Key components in `veinn.py`:

- **Block conversion**: `bytes_to_block`, `block_to_bytes`
- **Key schedule**: `key_from_seed`, `VeinnParams`, `VeinnKey`
- **Coupling layers**: `coupling_forward`, `coupling_inverse`
- **Round transforms**: `permute_forward`, `permute_inverse`
- **Homomorphic ops**: `homomorphic_add`, `homomorphic_multiply`
- **Integrity**: HMAC binding of ciphertext + metadata

---

## 🚀 Quick Start

### Installation

Clone the repo:
```bash
git clone https://github.com/CaelumSculptoris/veinn.git
cd veinn
```

(Requires Python 3.8+ and `numpy`.)

Install dependencies:
```bash
python3 -m venv veinn
source bin/activate
pip install -r requirements.txt
```

### Usage via CLI

#### Menu access
```bash
python3 cli/veinn.py 
```

#### package access
```bash
python3 -m cli/package.cli
```

#### Encrypt a file
```bash
python veinn.py encrypt --infile plaintext.txt --outfile ciphertext.json --seed mysecretseed
```

#### Decrypt a file
```bash
python veinn.py decrypt --infile ciphertext.json --outfile recovered.txt --seed mysecretseed
```

#### Homomorphic addition
```bash
python veinn.py add --infile1 ciphertext1.json --infile2 ciphertext2.json --outfile sum.json
```

#### Homomorphic multiplication
```bash
python veinn.py mul --infile1 ciphertext1.json --infile2 ciphertext2.json --outfile product.json
```

---

## 🐍 Examples (Python API)

You can also use **VEINN directly from Python**:

```python
from veinn import encrypt, decrypt, homomorphic_add

# Secret seed (used to derive key + parameters)
seed = "mysecretseed"

# Messages
msg1 = b"hello world"
msg2 = b"goodbye world"

# Encrypt both
ct1 = encrypt(msg1, seed)
ct2 = encrypt(msg2, seed)

# Homomorphic addition (ciphertexts add → plaintexts add)
ct_sum = homomorphic_add(ct1, ct2)

# Decrypt results
dec1 = decrypt(ct1, seed)
dec2 = decrypt(ct2, seed)
dec_sum = decrypt(ct_sum, seed)

print("Decrypted msg1:", dec1)
print("Decrypted msg2:", dec2)
print("Decrypted homomorphic sum:", dec_sum)
```

This produces:
```
Decrypted msg1: b'hello world'
Decrypted msg2: b'goodbye world'
Decrypted homomorphic sum: b'...'  # vector sum of plaintexts
```

---

## 🔬 How It Works

### Vector Encryption
- Plaintext is split into blocks, converted into vectors in $\mathbb{Z}_{2^{16}}^n$.  
- Each block passes through multiple **rounds** of:
  1. **Coupling layers** (invertible, RealNVP-style).  
  2. **Elementwise scaling** by odd vectors (invertible mod $2^{16}$).  
  3. **Shuffle permutations** for diffusion.  

### Lattice Security
- Parameters derived from seed using SHAKE or an **LWE-based PRF**.  
- LWE PRF introduces lattice-hardness assumptions (believed post-quantum secure).  

### Homomorphism
- Ciphertexts form a **vector space**:  
  - Addition of ciphertexts → addition of plaintexts.  
  - Negacyclic convolution of ciphertexts → multiplication of plaintexts (in ring).  

---

## 📊 Comparison

| Scheme   | Type        | PQ Secure? | Homomorphic? | Performance |
|----------|------------|------------|--------------|-------------|
| AES-128  | Block cipher | ❌ (Grover) | No           | High |
| RSA/ECC  | Public-key  | ❌ (Shor)   | No           | Medium |
| Kyber    | Lattice KEM | ✅          | Limited      | Medium |
| CKKS     | Lattice FHE | ✅          | Yes (approx) | Low |
| **VEINN** | Symmetric  | ✅ (LWE)    | Yes (add/mul)| High |

---

## 🛡️ Security

- **Classical attacks**: Differential/linear cryptanalysis hindered by nonlinear couplings + random scalings.  
- **Quantum attacks**: Grover limited by seed size (recommend ≥256-bit seed). LWE PRF resists known quantum algorithms.  
- **Integrity**: HMAC ensures ciphertext authenticity.  

---

## 📚 References

- O. Regev, *On Lattices, Learning with Errors, Random Linear Codes, and Cryptography*, STOC 2005.  
- Cheon et al., *CKKS: Homomorphic Encryption for Approximate Arithmetic*, 2017.  
- Dinh et al., *Revisiting the Security of Normalizing Flows*, 2022 (INN concepts).  
- VEINN arXiv draft (2025).  

---

## ⚠️ Disclaimer

This project is **experimental cryptography**.  
It is not yet standardized, audited, or production-ready. Use at your own risk.

---

## 📜 License

MIT License

## Notes   
   - Avalanche test shows good single block obfuscation but poor multiblock obfuscation. Implemented block chaining.

### Updates   
   - Added chaining modes.

### TODO
   - Update package
   - Integrate block chaining avalanche tests
   

### Avalanche Test Results
Using VEINN parameters: n=512, rounds=15, layers=15

Choose test type:
1) Single message test
2) Multiple message sizes
Choice [1]: 1
Enter test message: This is a test
Number of bit flips to test [100]: 
Testing 100 random bit flips in 112-bit message........ done!

Results for 14-byte message:
Message padded to 1024 bytes (1 blocks)
Bit avalanche: 49.99%
Block avalanche: 100.00%
Average bits changed: 4095.3 / 8192
Average blocks affected: 1.0 / 1

Using VEINN parameters: n=512, rounds=15, layers=15

Choose test type:
1) Single message test
2) Multiple message sizes
Choice [1]: 2

Testing message 1/7: 5 bytes
Testing 50 random bit flips in 40-bit message..... done!
  Avalanche: 49.91%, Blocks affected: 100.00%

Testing message 2/7: 37 bytes
Testing 50 random bit flips in 296-bit message...... done!
  Avalanche: 50.01%, Blocks affected: 100.00%

Testing message 3/7: 100 bytes
Testing 50 random bit flips in 800-bit message...... done!
  Avalanche: 49.97%, Blocks affected: 100.00%

Testing message 4/7: 1014 bytes
Testing 50 random bit flips in 8112-bit message...... done!
  Avalanche: 50.09%, Blocks affected: 100.00%

Testing message 5/7: 1024 bytes
Testing 50 random bit flips in 8192-bit message...... done!
  Avalanche: 24.96%, Blocks affected: 50.00%

Testing message 6/7: 1034 bytes
Testing 50 random bit flips in 8272-bit message...... done!
  Avalanche: 24.96%, Blocks affected: 50.00%

Testing message 7/7: 2048 bytes
Testing 50 random bit flips in 16384-bit message...... done!
  Avalanche: 16.67%, Blocks affected: 33.33%

Summary across message sizes:
------------------------------------------------------------
       5 bytes:  49.91% bit, 100.00% block avalanche
      37 bytes:  50.01% bit, 100.00% block avalanche
     100 bytes:  49.97% bit, 100.00% block avalanche
    1014 bytes:  50.09% bit, 100.00% block avalanche
    1024 bytes:  24.96% bit,  50.00% block avalanche
    1034 bytes:  24.96% bit,  50.00% block avalanche
    2048 bytes:  16.67% bit,  33.33% block avalanche