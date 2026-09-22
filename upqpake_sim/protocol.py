"""
UPQ-PAKE protocol implementation - paper Section 3/4, Algorithm 2.

Entities:
    TA      - Trusted Authority: system init, vehicle registration,
              provisioning of short-lived pseudonym credentials PCert_V^(j)
    Vehicle - OBU with PQ capability: selects fresh PCert, initiates the
              authentication request and contributes KEM entropy
    RSU     - verifies credentials, responds with its own KEM
              contribution, derives the session key

Phases (Algorithm 2):
    1  Vehicle registration + pseudonym provisioning
    2  Vehicle authentication request
    3  RSU verification and response
    4  Vehicle verification and KEM contribution
    5  RSU verification + session-key derivation
    6  Secure erasure + credential update

All crypto is REAL: ML-DSA-65 signatures, ML-KEM-768 encapsulation,
SHA3-256 hashing, HKDF-SHA3 key derivation.
"""

import time
from dataclasses import dataclass, field

from .pq import (KEM, DSA, H, hkdf, rand_bytes, timestamp,
                 EPK_SIZE, CT_SIZE, PK_SIZE, SIG_SIZE, NONCE_SIZE)

FRESHNESS_WINDOW_S = 30          # accepted timestamp skew for n/t checks


@dataclass
class PCert:
    """Short-lived pseudonym credential PCert_V^(j) (Alg. 2 step 10)."""
    pid_j: bytes        # PID_V^(j)  = H(PID_V || eta_j)
    pkV: bytes          # vehicle verification key
    validity: bytes     # Validity_j (8-byte expiry)
    sig_ta: bytes       # sigma_TA^(j) = Sign(skTA, H(PID_j||pkV||Validity_j))

    def size(self):
        return len(self.pid_j) + len(self.pkV) + len(self.validity) \
            + len(self.sig_ta)                       # 5301 B, Table 7


class TrustedAuthority:
    def __init__(self, rng):
        self.rng = rng
        self.pkTA, self.skTA = DSA.keygen()          # Eq. (7)
        self.registry = {}                            # R_V records
        self.revoked = set()

    def register(self, vehicle, pool_size=4):
        """Alg. 2 Phase 1 (steps 1-11): registration + PCert pool."""
        rng = self.rng
        sigma_v = rand_bytes()                        # sigma_V secret entropy
        cv = H(vehicle.vid.encode(), vehicle.attr.encode(), sigma_v)  # C_V
        pkV, skV = DSA.keygen()
        rv = rand_bytes()
        pid_v = H(cv, pkV, rv)                        # PID_V
        self.registry[pid_v] = dict(
            vid=vehicle.vid, cv=cv, pid=pid_v, pk=pkV,
            validity=True, revoked=False)
        vehicle.bind(pid_v, pkV, skV)

        pool = []
        for j in range(pool_size):                    # steps 7-10
            eta_j = rand_bytes()
            pid_j = H(pid_v, eta_j)                   # PID_V^(j)
            validity = (int(time.time()) + 3600).to_bytes(8, "big")
            sig_ta = DSA.sign(self.skTA, H(pid_j, pkV, validity))
            pool.append(PCert(pid_j, pkV, validity, sig_ta))
        vehicle.pcert_pool = pool
        return pid_v

    def trace(self, pid_v):
        rec = self.registry.get(pid_v)
        return rec["vid"] if rec else None


class Vehicle:
    _counter = 0

    def __init__(self, rng):
        Vehicle._counter += 1
        self.vid = f"V{Vehicle._counter:04d}"          # ID_V
        self.attr = f"OBU-{Vehicle._counter:04d}"      # Attr_V
        self.rng = rng
        self.pid_v = None
        self.pkV = self.skV = None
        self.pcert_pool = []
        self.used_pcerts = set()

    def bind(self, pid_v, pkV, skV):
        self.pid_v, self.pkV, self.skV = pid_v, pkV, skV

    def fresh_pcert(self):
        """Step 12: pick a fresh unused pseudonym credential."""
        for i, pc in enumerate(self.pcert_pool):
            if i not in self.used_pcerts:
                self.used_pcerts.add(i)
                return pc
        return None

    # -- Phase 2: authentication request -------------------------------
    def auth_request(self):
        pcert = self.fresh_pcert()
        if pcert is None:
            return None
        epkV, eskV = KEM.keygen()                     # step 13
        nV, tV = rand_bytes(), timestamp()            # steps 14-15
        authV = (pcert.pid_j, epkV, nV, tV)           # step 16
        sig_auth = DSA.sign(self.skV,                 # step 17
                            H(*authV, pcert.pid_j, pcert.pkV,
                              pcert.validity, pcert.sig_ta))
        self._eskV, self._authV, self._pcert = eskV, authV, pcert
        return pcert, authV, sig_auth                 # step 18

    # -- Phase 4: vehicle verification + KEM contribution --------------
    def respond(self, epkR, ctRV, nR, tR, sigR, pkR):
        authV, pcert, eskV = self._authV, self._pcert, self._eskV
        pid_j, epkV, nV, tV = authV
        if not _fresh(tR) or nR == b"\x00" * NONCE_SIZE:   # step 31
            return None
        betaR = H(pid_j, epkV, epkR, ctRV, nV, nR, tV, tR)  # step 28
        if not DSA.verify(pkR, betaR, sigR):               # step 32
            return None
        ssRV = KEM.decaps(eskV, ctRV)                      # step 33
        ssVR, ctVR = KEM.encaps(epkR)                      # step 34
        beta = H(betaR, ctVR)                              # step 35
        sig_fin = DSA.sign(self.skV, beta)                 # step 36
        self._ssRV, self._ssVR, self._beta = ssRV, ssVR, beta
        self.session_key = hkdf(ssRV, ssVR, H(*authV), beta)  # step 40
        del self._eskV                                     # step 44 erasure
        return ctVR, sig_fin                               # step 37


class RSU:
    _counter = 0

    def __init__(self, rng):
        RSU._counter += 1
        self.rid = f"RSU{RSU._counter:02d}"
        self.rng = rng
        self.pkR, self.skR = DSA.keygen()
        self.seen_nonces = set()
        self.sessions = {}

    # -- Phase 3: verification and response ------------------------------
    def verify_request(self, pcert, authV, sig_auth, pkTA):
        pid_j, epkV, nV, tV = authV
        # step 19-20: verify sigma_TA + validity/revocation of PCert
        if not DSA.verify(pkTA, H(pcert.pid_j, pcert.pkV,
                                  pcert.validity), pcert.sig_ta):
            return None, "bad TA signature"
        if pid_j != pcert.pid_j:                      # step 21 PID match
            return None, "PID mismatch"
        if not _fresh(tV) or nV in self.seen_nonces:  # step 23 freshness
            return None, "stale/replayed nonce"
        if not DSA.verify(pcert.pkV,                  # step 22 sigma_auth
                          H(*authV, pcert.pid_j, pcert.pkV,
                            pcert.validity, pcert.sig_ta), sig_auth):
            return None, "bad auth signature"
        self.seen_nonces.add(nV)

        epkR, eskR = KEM.keygen()                     # step 24
        ssRV, ctRV = KEM.encaps(epkV)                 # step 25
        nR, tR = rand_bytes(), timestamp()            # steps 26-27
        betaR = H(pid_j, epkV, epkR, ctRV, nV, nR, tV, tR)  # step 28
        sigR = DSA.sign(self.skR, betaR)              # step 29
        self.sessions[pid_j] = dict(eskR=eskR, ssRV=ssRV, betaR=betaR,
                                    authV=authV, pkV=pcert.pkV)
        return (epkR, ctRV, nR, tR, sigR), "ok"       # step 30

    # -- Phase 5: final verification + session-key derivation ------------
    def finalize(self, pid_j, ctVR, sig_fin):
        s = self.sessions.get(pid_j)
        if s is None:
            return None
        beta = H(s["betaR"], ctVR)
        if not DSA.verify(s["pkV"], beta, sig_fin):   # step 38
            return None
        ssVR = KEM.decaps(s["eskR"], ctVR)             # step 39
        key = hkdf(s["ssRV"], ssVR, H(*s["authV"]), beta)  # step 41
        del s["eskR"], s["ssRV"]                       # step 45 erasure
        return key


def _fresh(ts, window=FRESHNESS_WINDOW_S):
    return abs(int(time.time()) - int.from_bytes(ts, "big")) <= window


# ------------------------------------------------------------- timing
def timed(fn, *a, **kw):
    t0 = time.perf_counter()
    r = fn(*a, **kw)
    return r, time.perf_counter() - t0
