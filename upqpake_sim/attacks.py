"""
Replay and MITM attack simulation - paper Sections 5/6.5.

Adversary model: quantum polynomial-time (QPT) adversary controlling the
open channel - eavesdrop, replay, tamper, MITM.  Both attacks are run
against the REAL protocol verifier:

    * Replay: an intercepted authentication tuple (PCert, AuthV, sigma)
      is retransmitted.  It is rejected by nonce-freshness checks
      (seen_nonces), PCert single-use marking and timestamp window.

    * MITM: the adversary modifies transcript components (epkR, ctVR,
      nR) in transit.  Detection via transcript binder beta_R / beta and
      ML-DSA signature verification -> modification always fails.

The paper states: success requires bypassing freshness mechanisms
(bounded by nonce-collision probability ~2^-256) or producing a hash
collision / ML-DSA forgery (EUF-CMA) - i.e. negligible.  The measured
success rate is 0 % for both attacks.
"""

import random

from . import protocol
from .pq import H, rand_bytes, EPK_SIZE, CT_SIZE


def _setup(rng, pool_size=64):
    ta = protocol.TrustedAuthority(rng)
    rsu = protocol.RSU(rng)
    v = protocol.Vehicle(rng)
    ta.register(v, pool_size=pool_size)
    return ta, rsu, v


def _do_session(ta, rsu, v):
    """Run one full honest session; returns the captured transcript."""
    pcert, authV, sig_auth = v.auth_request()
    resp, status = rsu.verify_request(pcert, authV, sig_auth, ta.pkTA)
    assert status == "ok", status
    epkR, ctRV, nR, tR, sigR = resp
    ctVR, sig_fin = v.respond(epkR, ctRV, nR, tR, sigR, rsu.pkR)
    key_r = rsu.finalize(pcert.pid_j, ctVR, sig_fin)
    assert key_r == v.session_key
    return pcert, authV, sig_auth


def simulate_replay(n_attempts, rng, trials=20):
    """Fraction of replayed tuples accepted (percent)."""
    hits = 0
    for _ in range(trials):
        ta, rsu, v = _setup(random.Random(rng.randrange(1 << 30)))
        pcert, authV, sig_auth = _do_session(ta, rsu, v)
        for _ in range(n_attempts):
            resp, _status = rsu.verify_request(pcert, authV, sig_auth,
                                               ta.pkTA)
            if resp is not None:
                hits += 1
    return 100.0 * hits / (trials * n_attempts)


def simulate_mitm(n_attempts, rng, trials=20):
    """Fraction of MITM-modified transcripts accepted (percent)."""
    hits = 0
    for _ in range(trials):
        ta, rsu, v = _setup(random.Random(rng.randrange(1 << 30)))
        for _ in range(n_attempts):
            req = v.auth_request()
            if req is None:
                ta.register(v, pool_size=64)
                continue
            pcert, authV, sig_auth = req
            resp, status = rsu.verify_request(pcert, authV, sig_auth,
                                              ta.pkTA)
            if resp is None:
                continue
            epkR, ctRV, nR, tR, sigR = resp
            # adversary substitutes its own ephemeral KEM key
            epkR_bad = rand_bytes(EPK_SIZE)
            fin = v.respond(epkR_bad, ctRV, nR, tR, sigR, rsu.pkR)
            if fin is None:
                continue                      # tampering detected (sig covers betaR)
            ctVR, sig_fin = fin
            # adversary also tampers the returned ciphertext
            ctVR_bad = rand_bytes(CT_SIZE)
            key_r = rsu.finalize(pcert.pid_j, ctVR_bad, sig_fin)
            if key_r is not None and key_r == v.session_key:
                hits += 1
    return 100.0 * hits / (trials * n_attempts)


def simulate_unlinkability(n_sessions, rng):
    """Correlation check: fraction of session pseudonyms PID_V^(j) that
    an observer can link back to the base PID_V by hashing candidate
    etas (should be ~0 - PID_j = H(PID_V || eta_j) is unlinkable)."""
    ta, rsu, v = _setup(rng)
    base = v.pid_v
    linked = 0
    observed = 0
    for _ in range(n_sessions):
        req = v.auth_request()
        if req is None:
            ta.register(v, pool_size=64)
            continue
        pcert, _, _ = req
        pid_j = pcert.pid_j
        observed += 1
        for _try in range(1000):              # adversary guesses eta_j
            if H(base, rand_bytes()) == pid_j:
                linked += 1
                break
    return 100.0 * linked / max(observed, 1)
