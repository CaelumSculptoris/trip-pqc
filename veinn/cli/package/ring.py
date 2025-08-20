# veinn/ring.py
import numpy as np
from .params import DTYPE

# -----------------------------
# LWE-Based PRF
# -----------------------------
def int_ring_convolve(a, b, q, root):
    """Convolution over Z_q[x]/(x^n+1) using NTT"""
    n = len(a)
    A = ntt(a, q, root)
    B = ntt(b, q, root)
    C = (A * B) % q
    # Inverse NTT: use modular inverse of n and root
    inv_n = pow(n, -1, q)
    inv_root = pow(root, -1, q)
    c = ntt(C, q, inv_root)
    return (c * inv_n) % q

def ring_convolution(a, b, q, method="naive"):
    """
    Ring convolution modulo q, drop-in replacement for your current method.

    Args:
        a, b : list[int] or np.ndarray
            Polynomials represented as coefficient lists of length n
        q : int
            Modulus
        method : str
            "naive" → O(n^2), slow but exact
            "fft"   → O(n log n), floating point FFT (fast, but rounding)
            "ntt"   → O(n log n), modular NTT (exact if q supports)

    Returns:
        np.ndarray : coefficients of (a * b) mod (x^n+1, q)
    """
    n = len(a)
    a = np.array(a, dtype=int) % q
    b = np.array(b, dtype=int) % q

    if method == "naive":
        # direct polynomial multiplication
        res = np.zeros(2*n, dtype=int)
        for i in range(n):
            for j in range(n):
                res[i+j] += a[i] * b[j]
        # wrap back into ring (mod x^n + 1)
        res = (res[:n] - res[n:]) % q
        return res

    elif method == "fft":
        # floating point FFT
        A = np.fft.fft(a, 2*n)
        B = np.fft.fft(b, 2*n)
        C = A * B
        res = np.fft.ifft(C).real.round().astype(int)
        res = (res[:n] - res[n:]) % q
        return res

    elif method == "ntt":
        # NTT requires q ≡ 1 mod 2n (so a primitive root exists)
        # toy implementation: only works if q is carefully chosen
        # Here we fallback to naive if q is unsuitable
        if (q - 1) % (2*n) != 0:
            return ring_convolution(a, b, q, method="naive")

        # find primitive 2n-th root of unity modulo q
        g = find_primitive_root(q)
        root = pow(g, (q - 1) // (2*n), q)

        A = ntt(a, root, q)
        B = ntt(b, root, q)
        C = [(x*y) % q for x, y in zip(A, B)]
        res = intt(C, root, q)
        res = (np.array(res[:n]) - np.array(res[n:])) % q
        return res

    else:
        raise ValueError("method must be one of: naive, fft, ntt")

# -----------------------------
# Helper functions for NTT 
# -----------------------------
def ntt(a, root, q):
    n = len(a)
    A = [0]*n
    for k in range(n):
        s = 0
        for j in range(n):
            s = (s + a[j] * pow(root, (j*k) % (2*n), q)) % q
        A[k] = s
    return A

def intt(A, root, q):
    n = len(A)
    inv_n = pow(n, -1, q)
    root_inv = pow(root, -1, q)
    a = [0]*n
    for j in range(n):
        s = 0
        for k in range(n):
            s = (s + A[k] * pow(root_inv, (j*k) % (2*n), q)) % q
        a[j] = (s * inv_n) % q
    return a

def find_primitive_root(q):
    """Finds a primitive root modulo q (very naive)."""
    factors = factorize(q-1)
    for g in range(2, q):
        ok = True
        for f in factors:
            if pow(g, (q-1)//f, q) == 1:
                ok = False
                break
        if ok:
            return g
    return None

def factorize(n):
    factors = set()
    d = 2
    while d*d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return list(factors)

def negacyclic_convolution(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    """O(n^2) negacyclic convolution in Z_q[x]/(x^n+1)."""
    assert a.shape == b.shape, f"Convolution shape mismatch: a {a.shape}, b {b.shape}"
    n = a.shape[0]
    res = np.zeros(n, dtype=np.int64)
    a_int = a.astype(np.int64)
    b_int = b.astype(np.int64)
    for i in range(n):
        ai = a_int[i]
        for j in range(n):
            k = (i + j) % n
            sign = -1 if (i + j) >= n else 1
            res[k] = (res[k] + ai * b_int[j] * sign)
    return (res % q).astype(DTYPE)