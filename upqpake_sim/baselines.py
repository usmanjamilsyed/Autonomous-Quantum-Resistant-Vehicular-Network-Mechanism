"""
Baseline-scheme emulations for the comparative evaluation
(paper Sections 6.2-6.4, Figures 3-5, Table 5).

Schemes compared (as named in the paper figures):
    ECC-Based  - conventional ECC authentication (Liu et al. [2])
    PQAKA      - post-quantum AKA scheme [12]
    UPQ-PAKE   - proposed (fully implemented in protocol.py)

The proposed scheme's cost is MEASURED by executing the real protocol.
Baselines are emulated via operation profiles expressed in the measured
primitives (ML-DSA/ML-KEM ops for the PQ scheme, ECDSA/ECDH-class ops
for ECC), with counts reproducing each scheme's reported operation
profile (Table 5). A platform normalisation factor maps the pure-Python
timings to the paper's liboqs/i7-12700 reference platform, anchored on
the proposed scheme.
"""

from .pq import measure_primitives
from . import protocol


# ---------------------------------------------------------- packet sizes
def message_packet(scheme):
    """Serialised authentication exchange; returns (bytes, breakdown)."""
    def pkt(**f):
        body = b"".join(bytes(v) for v in f.values())
        return body, {k: len(v) for k, v in f.items()}

    if scheme == "ecc":                       # cert + ECC sigs + ECDH keys
        return pkt(certificate=bytes(2048), auth_msg=bytes(256),
                   sig_1=bytes(72), sig_2=bytes(71),
                   ecdh_key_1=bytes(64), ecdh_key_2=bytes(64),
                   nonce_1=bytes(32), nonce_2=bytes(32),
                   timestamp=bytes(16), mac=bytes(32),
                   misc_fields=bytes(520))                      # ~3.2 kB
    if scheme == "pqaka":                     # PQ creds + sigs + KEM ct
        return pkt(credential=bytes(2048), auth_msg=bytes(512),
                   pq_sig=bytes(3309 // 2), kem_ct=bytes(1088),
                   kem_ek=bytes(1184), nonces=bytes(64),
                   timestamps=bytes(16), mac=bytes(32),
                   misc_fields=bytes(600))                     # ~7.2 kB
    if scheme == "upqpake":                   # Table 7, exact
        return pkt(PCert_V=bytes(5301), AuthV=bytes(1256),
                   sig_authV=bytes(3309), epkR=bytes(1184),
                   ct_RV=bytes(1088), nR=bytes(32), tR=bytes(8),
                   sigR=bytes(3309), ct_VR=bytes(1088),
                   sig_finV=bytes(3309))                        # 19 884 B
    raise ValueError(scheme)


# --------------------------------------------------- op profiles
# Equivalent crypto operations per session side, reproducing each
# scheme's reported computational profile under the adopted benchmark.
# Measured primitive times are multiplied by these counts.
OP_PROFILES = {
    # vehicle side / RSU side
    "ecc":     {"veh": {"verify_ec": 20, "sign_ec": 8, "ecmul": 30, "TH": 8},
                "rsu": {"verify_ec": 15, "sign_ec": 6, "ecmul": 15, "TH": 10}},
    "pqaka":   {"veh": {"TSign": 2, "TVerify": 1, "TEncap": 1, "TH": 4},
                "rsu": {"TSign": 1, "TVerify": 2, "TDecap": 1, "TH": 6}},
    "upqpake": {"veh": {"TSign": 2, "TVerify": 1, "TEncap": 1, "TDecap": 1,
                        "TH": 5, "THKDF": 1},
                "rsu": {"TSign": 1, "TVerify": 2, "TEncap": 1, "TDecap": 1,
                        "TH": 6, "THKDF": 1}},
}

# delay-critical op count for Fig. 5 (Eq. 94 style) per scheme
DELAY_PROFILES = {
    "ecc":     {"verify_ec": 30, "sign_ec": 12, "ecmul": 60, "TH": 10},
    "pqaka":   {"TSign": 3, "TEncap": 2, "TDecap": 1, "TH": 8},
    "upqpake": {"TSign": 3, "TVerify": 2, "TEncap": 1, "TDecap": 1, "TH": 11},
}

SCHEME_LABELS = {"ecc": "ECC-Based", "pqaka": "PQAKA",
                 "upqpake": "UPQ-PAKE"}
SCHEME_ORDER = ["ecc", "pqaka", "upqpake"]
# figure-6 legend order/name
FIG6_LABELS = {"ecc": "Liu et al.", "pqaka": "PQAKA",
               "upqpake": "UPQ-PAKE"}


def ecc_primitives():
    """Measured ECC-class primitive costs (seconds) via ECDSA lib."""
    from ecdsa import SigningKey, SECP256k1
    from .pq import bench
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    sig = sk.sign(b"x")
    return {
        "sign_ec":   bench(lambda: sk.sign(b"x"), 30),
        "verify_ec": bench(lambda: vk.verify(sig, b"x"), 30),
        "ecmul":     bench(lambda: vk.pubkey.point * 0x12345, 50),
    }


def session_cost(scheme, side, prim):
    """Modelled per-side session cost (seconds, this machine)."""
    return sum(prim.get(op, 0.0) * c
               for op, c in OP_PROFILES[scheme][side].items())


def delay_cost(scheme, prim):
    """Modelled computational delay D_Comp (seconds, this machine)."""
    return sum(prim.get(op, 0.0) * c
               for op, c in DELAY_PROFILES[scheme].items())
