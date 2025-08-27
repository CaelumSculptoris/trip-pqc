# Run under Python 3.10+, uses only Python ints (masked to 32-bit).
from typing import List, Tuple
import struct

def bytes_to_state(data: bytes, n: int) -> list[int]:
    """Convert up to 4*n bytes into a list of n 32-bit words (little endian)."""
    padded = data.ljust(4 * n, b"\x00")
    return list(struct.unpack("<" + "I"*n, padded))

def state_to_bytes(state: list[int]) -> bytes:
    """Convert list of 32-bit words back into 4*len(state) bytes."""
    return struct.pack("<" + "I"*len(state), *state)

def pad_iso7816(data: bytes, blocksize: int) -> bytes:
    padlen = (-len(data)) % blocksize
    if padlen == 0:
        padlen = blocksize
    return data + b"\x80" + b"\x00"*(padlen-1)

def unpad_iso7816(padded: bytes) -> bytes:
    i = padded.rfind(b"\x80")
    if i == -1 or any(b != 0 for b in padded[i+1:]):
        raise ValueError("Invalid padding")
    return padded[:i]

def vein_encrypt(msg: bytes, perm, n: int) -> bytes:
    blocksize = 4 * n
    msg_padded = pad_iso7816(msg, blocksize)
    blocks = [msg_padded[i:i+blocksize] for i in range(0, len(msg_padded), blocksize)]
    out_blocks = []
    for b in blocks:
        state = bytes_to_state(b, n)
        ct_state = perm(state)
        out_blocks.append(state_to_bytes(ct_state))
    return b"".join(out_blocks)

def vein_decrypt(ct: bytes, inv, n: int) -> bytes:
    blocksize = 4 * n
    if len(ct) % blocksize != 0:
        raise ValueError("Ciphertext length not multiple of blocksize")
    blocks = [ct[i:i+blocksize] for i in range(0, len(ct), blocksize)]
    out_blocks = []
    for b in blocks:
        state = bytes_to_state(b, n)
        pt_state = inv(state)
        out_blocks.append(state_to_bytes(pt_state))
    padded = b"".join(out_blocks)
    return unpad_iso7816(padded)

MASK32 = (1 << 32) - 1

def rol32(x: int, r: int) -> int:
    r %= 32
    return ((x << r) | (x >> (32 - r))) & MASK32

def ror32(x: int, r: int) -> int:
    r %= 32
    return ((x >> r) | ((x << (32 - r)) & MASK32)) & MASK32

def gen_invertible_matrix(gen, n):
    # Produce L and U separately
    L = [[0]*n for _ in range(n)]
    U = [[0]*n for _ in range(n)]
    for i in range(n):
        L[i][i] = 1
        U[i][i] = 1
        for j in range(i):
            L[i][j] = ((next(gen) >> 2) % 5) - 2   # small coeff
        for j in range(i+1, n):
            U[i][j] = ((next(gen) >> 2) % 5) - 2
    return L, U

def mat_mul_LU(vec, L, U, n):
    # y = L * vec
    y = [0]*n
    for i in range(n):
        s = 0
        for j in range(i+1):  # j <= i
            s = (s + L[i][j]*vec[j]) & MASK32
        y[i] = s
    # z = U * y
    z = [0]*n
    for i in range(n):
        s = 0
        for j in range(i, n):  # j >= i
            s = (s + U[i][j]*y[j]) & MASK32
        z[i] = s
    return z

def mat_inv_mul_LU(vec, L, U, n):
    # inverse of U
    y = [0]*n
    for i in reversed(range(n)):
        s = vec[i]
        for j in range(i+1, n):
            s = (s - U[i][j]*y[j]) & MASK32
        y[i] = s  # since U[i][i] = 1
    # inverse of L
    x = [0]*n
    for i in range(n):
        s = y[i]
        for j in range(i):
            s = (s - L[i][j]*x[j]) & MASK32
        x[i] = s  # since L[i][i] = 1
    return x

# Small deterministic RNG for key scheduling (xorshift64*)
def xs64(seed: int):
    s = seed & ((1<<64)-1)
    while True:
        s ^= (s << 13) & ((1<<64)-1)
        s ^= s >> 7
        s ^= (s << 17) & ((1<<64)-1)
        yield s & ((1<<64)-1)

def expand_key(master_key_bytes: bytes, rounds: int, n: int):
    seed = int.from_bytes(master_key_bytes[:8].ljust(8, b'\0'), 'little')
    gen = xs64(seed)
    per_round = []
    for r in range(rounds):
        ks = [next(gen) & MASK32 for _ in range(4 * n)]
        L, U = gen_invertible_matrix(gen, n)
        per_round.append((ks, L, U))
    return per_round

# F: ARX mini-primitive (applied wordwise but receives a small slice of ks)
def F_word(w: int, ks: List[int]) -> int:
    # ks: list of 3 32-bit subkeys to use here
    odd_const = 0x9E3779B1  # golden ratio constant, odd
    w = (w + ks[0]) & MASK32
    w = rol32(w, (ks[1] & 31))
    w ^= ks[2]
    w = (w * odd_const) & MASK32
    return w

# coupling (L, R are lists of words)
def coupling_forward(L: List[int], R: List[int], ks: List[int]) -> Tuple[List[int], List[int]]:
    # ks is a long list; split ks into word-level subkeys
    nL = len(L)
    nR = len(R)
    # build F applied per-word: use 3 subkeys per word
    Fks = [ks[i*3:(i+1)*3] for i in range(nL)]
    Gks = [ks[(nL*3)+i*3:(nL*3)+ (i+1)*3] for i in range(nR)]
    # compute R' = R + F(L)
    R2 = []
    for i in range(nR):
        f = F_word(L[i % nL], Fks[i % nL])
        R2.append((R[i] + f) & MASK32)
    # L' = L + G(R')
    L2 = []
    for i in range(nL):
        g = F_word(R2[i % nR], Gks[i % nR])  # reuse F_word for G
        L2.append((L[i] + g) & MASK32)
    return L2, R2

def coupling_inverse(L2: List[int], R2: List[int], ks: List[int]) -> Tuple[List[int], List[int]]:
    nL = len(L2)
    nR = len(R2)
    Fks = [ks[i*3:(i+1)*3] for i in range(nL)]
    Gks = [ks[(nL*3)+i*3:(nL*3) + (i+1)*3] for i in range(nR)]
    # recover L
    L = []
    for i in range(nL):
        g = F_word(R2[i % nR], Gks[i % nR])
        L.append((L2[i] - g) & MASK32)
    # recover R
    R = []
    for i in range(nR):
        f = F_word(L[i % nL], Fks[i % nL])
        R.append((R2[i] - f) & MASK32)
    return L, R

# small matrix multiply mod 2^32 for mixing
def mat_mul(vec: List[int], mat_small: List[int], n: int) -> List[int]:
    # mat_small is row-major n*n small ints (e.g. in -2..2). Multiply then mod 2^32
    out = [0]*n
    for i in range(n):
        s = 0
        base = i*n
        for j in range(n):
            coeff = mat_small[base + j]
            s = (s + (coeff * vec[j])) & MASK32
        out[i] = s
    return out

# full VEINN forward round (one round)
def vein_round(state, round_info, n):
    ks, L, U = round_info
    fgks = ks[:3*n]
    injks = ks[3*n:4*n]
    # coupling
    nL, nR = n//2, n - n//2
    Ls, Rs = state[:nL], state[nL:]
    L2, R2 = coupling_forward(Ls, Rs, fgks)
    mid = L2 + R2
    mixed = mat_mul_LU(mid, L, U, n)
    out = [(mixed[i] + injks[i]) & MASK32 for i in range(n)]
    return out

def vein_round_inv(state, round_info, n):
    ks, L, U = round_info
    fgks = ks[:3*n]
    injks = ks[3*n:4*n]
    # subtract injection
    mixed = [(state[i] - injks[i]) & MASK32 for i in range(n)]
    # apply inverse matrix
    mid = mat_inv_mul_LU(mixed, L, U, n)
    # split
    nL, nR = n//2, n - n//2
    L2, R2 = mid[:nL], mid[nL:]
    Ls, Rs = coupling_inverse(L2, R2, fgks)
    return Ls + Rs

def build_permutation(master_key: bytes, rounds: int, n: int):
    round_keys = expand_key(master_key, rounds, n)
    def permute(state):
        s = state[:]
        for r in range(rounds):
            s = vein_round(s, round_keys[r], n)
        return s
    def inverse(state):
        s = state[:]
        for r in reversed(range(rounds)):
            s = vein_round_inv(s, round_keys[r], n)
        return s
    return permute, inverse

# inverse of the round requires inverse of mat (used arbitrary mat_small; for invertibility ensure det=1)
# For a production test, choose mat_small to be L*U and invert via back-substitution.

# Quick bijectivity test for very small n (use invertible mat_small in practice)
if __name__ == "__main__":
    # small smoke: this only checks function runs; full bijectivity requires invertible mat_small
    master = b"VEINNPRIMITIVE"
    rounds = 4
    n = 6
    perm, inv = build_permutation(master, rounds, n)

    msg = b"Hey, how's it goin? This is a rough demo of the conceptual VEINN primitive."
    ct = vein_encrypt(msg, perm, n)
    pt = vein_decrypt(ct, inv, n)

    print("msg:", msg)
    print("ct :", ct.hex())
    print("pt :", pt)
    assert pt == msg