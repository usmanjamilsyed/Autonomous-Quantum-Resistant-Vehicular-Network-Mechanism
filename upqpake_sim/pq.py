"""
Post-quantum cryptographic primitives for the UPQ-PAKE simulation.

Real NIST-standardized implementations (FIPS 203 / FIPS 204):
    ML-KEM-768  - key encapsulation  (NIST security level 3)
    ML-DSA-65   - digital signatures (NIST security level 3)
    SHA3-256    - hash function H(.)
    HKDF-SHA3   - session-key derivation

Parameter sizes match Table 7 of the paper exactly:
    epk = 1184 B, ct = 1088 B, pk = 1952 B, sig = 3309 B, ss = 32 B
"""

import hashlib
import hmac as _hmac
import secrets
import time

from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65

KEM = ML_KEM_768
DSA = ML_DSA_65

# ------------------------------------------------------------- sizes (B)
EPK_SIZE = 1184
CT_SIZE = 1088
SS_SIZE = 32
PK_SIZE = 1952
SIG_SIZE = 3309
NONCE_SIZE = 32
TS_SIZE = 8


def rand_bytes(n=32):
    return secrets.token_bytes(n)


def H(*parts):
    """SHA3-256 hash of the concatenated inputs (paper's H(.))."""
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p if isinstance(p, bytes) else str(p).encode())
    return h.digest()


def hkdf(*parts, out_len=32):
    """HKDF-SHA3-256 key derivation (paper's HKDF)."""
    ikm = b"".join(p if isinstance(p, bytes) else str(p).encode()
                   for p in parts)
    prk = _hmac.new(b"\x00" * 32, ikm, hashlib.sha3_256).digest()
    return _hmac.new(prk, b"\x01" + b"UPQ-PAKE", hashlib.sha3_256).digest()[:out_len]


def timestamp():
    return int(time.time()).to_bytes(TS_SIZE, "big")


def bench(fn, n=20):
    """Median-ish op timing: min over batches is robust to CPU jitter."""
    fn()
    best = float("inf")
    for _ in range(7):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        best = min(best, (time.perf_counter() - t0) / n)
    return best


def measure_primitives():
    """Measure per-operation cost (seconds) on this machine."""
    ek, dk = KEM.keygen()
    ss, ct = KEM.encaps(ek)
    pk, sk = DSA.keygen()
    sig = DSA.sign(sk, b"bench")
    return {
        "TSign":   bench(lambda: DSA.sign(sk, b"x"), 8),
        "TVerify": bench(lambda: DSA.verify(pk, b"x", sig), 8),
        "TEncap":  bench(lambda: KEM.encaps(ek), 8),
        "TDecap":  bench(lambda: KEM.decaps(dk, ct), 8),
        "TKGen":   bench(KEM.keygen, 8),
        "TH":      bench(lambda: H(b"x" * 64), 200),
        "THKDF":   bench(lambda: hkdf(b"a" * 32, b"b" * 32), 100),
    }
