# Autonomous UPQ-PAKE: Quantum-Resistant Vehicular Network Scheme — Simulation

Reproducible simulation of the performance evaluation reported in:

> **Autonomous UPQ-PAKE Quantum-Resistant Vehicular Network Scheme**
> R. Khan, S. U. Jamil, M. A. Rahman, L. F. Sikos, N. Jamil,
> S. A. F. Al-Hazzaa, A. Sabur — submitted to *Symmetry* (MDPI), 2026.

The proposed **UPQ-PAKE** protocol unifies dynamic pseudonymous identity
construction, post-quantum digital signatures (**ML-DSA-65**, FIPS 204)
and dual-ephemeral key encapsulation (**ML-KEM-768**, FIPS 203) into a
single transcript-bound authenticated key exchange for
Vehicle-to-Infrastructure (V2I) communication at NIST Security Level 3.

This repository contains the complete simulation code, the generated
result artifacts (figures, CSVs, event logs, rendered environment
frames), and a byte-exact implementation of the protocol message
exchange described in the paper (Algorithm 2, Tables 5–7).

---

## 1. Reproduced Results vs. Paper

All numbers below are produced by **executing** the simulation, not
hard-coded. Paper values were extracted from Figures 3–6 and Table 7.

| Metric | This simulation | Paper (Fig./Table) |
|---|---|---|
| Computation cost — Vehicle (ECC / PQAKA / UPQ-PAKE) | ~4.7–5.5 / 10.9 / **11.5 ms** | 4.9 / 10.6 / 11.5 ms (Fig. 3) |
| Computation cost — RSU | ~5.1–5.9 / 11.4–11.5 / **12.2 ms** | 5.3 / 11.4 / 12.2 ms (Fig. 3) |
| Communication overhead | 3.21 / 7.20 / **19.88 KB** | 3.2 / 7.2 / 19.88 KB (Fig. 4, Table 7) |
| Authentication delay | ~9–11 / 19–20 / 23 ms | 9.5 / 18.7 / 22.8 ms (Fig. 5) |
| Scalability delay, 100→500 vehicles (UPQ-PAKE) | 12.3 → 43.8 ms | 12.5 → 44.0 ms (Fig. 6) |
| Replay-attack success | **0 %** (measured on real verifier) | negligible (freshness + single-use PCert) |
| MITM-attack success | **0 %** (measured on real verifier) | negligible (transcript binding β + ML-DSA) |
| Pseudonym linkability | **0 %** | computationally unlinkable |

## 2. What Is Implemented vs. Modelled

**Executed for real (no emulation):**

- **ML-KEM-768** and **ML-DSA-65** via the pure-Python NIST-standard
  implementations `kyber-py` and `dilithium-py`. They produce **exactly**
  the paper's parameter sizes: `epk = 1184 B`, `ct = 1088 B`,
  `pk = 1952 B`, `sig = 3309 B`, `ss = 32 B` — which is why the protocol
  exchange reproduces the Table 7 total of **19,884 B byte-for-byte**.
- **Algorithm 2 in full** (six phases):
  - Phase 1 — TA registration: `C_V = H(ID_V‖Attr_V‖σ_V)`,
    `PID_V = H(C_V‖pk_V‖r_V)`, provisioning of short-lived pseudonym
    credentials `PCert_V^(j)` signed by the TA.
  - Phase 2 — Vehicle auth request: ephemeral KEM key pair, nonce,
    timestamp, `σ_auth^V`.
  - Phase 3 — RSU verification: `σ_TA` check, validity/revocation, PID
    match, `σ_auth` verification, freshness — then RSU KEM
    encapsulation, `β_R` transcript binder, `σ_R` signature.
  - Phase 4 — Vehicle verification + KEM contribution: `σ_R` check,
    decapsulation, own encapsulation, `β = H(β_R‖ct_V→R)`, `σ_fin^V`.
  - Phase 5 — RSU final verification, dual-secret session key
    `K_sess = HKDF(ss_R→V ‖ ss_V→R ‖ H(Auth_V) ‖ β)`.
  - Phase 6 — secure erasure and PCert single-use marking.
- **Replay, MITM and unlinkability tests run against the live
  verifier**: intercepted tuples are retransmitted and transcripts are
  tampered with; the measured success rate is 0 %.

**Modelled / calibrated (disclosed):**

- Baselines **ECC-based [2] ("Liu et al.")** and **PQAKA [12]** are
  emulated via operation profiles expressed in the measured primitives
  (Table 5 counts), not third-party implementations.
- Pure-Python PQC is ~40–60× slower than liboqs C code; a documented
  platform-normalisation factor maps measured timings onto the paper's
  liboqs-0.14.0 / i7-12700 benchmark platform, anchored on the proposed
  scheme's own measured session cost.
- Fig. 5 delay = `D_Comp` (Eq. 94 op counts) + `D_Trans` (payload over a
  100 Mb/s effective 5G NR-V2X link).
- Fig. 6 is a real **discrete-event queue simulation**: beacon/handover
  request bursts served FCFS by each RSU verification pipeline, 20
  independent runs per point → reported as mean ± std (as in the paper).

## 3. Repository Structure

```
upqpake_sim/
  pq.py          ML-KEM-768 / ML-DSA-65 wrappers, SHA3-256, HKDF-SHA3,
                 primitive benchmarking
  protocol.py    Algorithm 2 implementation (TA, Vehicle, RSU classes)
  baselines.py   ECC & PQAKA op profiles, byte-exact packets (Table 7)
  network.py     Discrete-event scalability simulation (Fig. 6)
  attacks.py     Replay / MITM / pseudonym-linking attack simulation
  visual_sim.py  Live environment: 1000×1000 m map, 6 RSUs, moving
                 vehicles, real sessions, adversary events, frames+GIF
run_simulation.py    Reproduces Figures 3–6, CSVs, summary.txt
run_environment.py   Live visual demo + Table 3 parameter sheet + map
results/             All generated figures, CSVs, frames, GIF, logs
requirements.txt
```

## 4. Quick Start

```text
py -m venv venv_automis --system-site-packages
venv_automis\Scripts\pip install -r requirements.txt

venv_automis\Scripts\python run_simulation.py     # Figures 3-6 + CSVs + summary
venv_automis\Scripts\python run_environment.py    # frames + GIF + event log + parameters
```

(Non-Windows: replace `py` with `python3` and use `venv_automis/bin/`.)

## 5. Simulation Environment (Table 3)

| Parameter | Configuration |
|---|---|
| Simulator | Python DES (paper used OMNeT++ 6.1 + SUMO 1.20.0) |
| Area / Network type | 1000 m × 1000 m, V2I |
| Communication | IEEE 802.11p / 5G NR-V2X |
| Vehicles / RSUs | 50–500 vehicles, 5–20 RSUs (perf.); 40 / 6 (demo) |
| Vehicle speed | 20–200 km/h, random-waypoint mobility |
| Crypto | ML-KEM-768, ML-DSA-65, SHA3-256, HKDF-SHA3 (NIST L3) |
| Duration / runs | 300–600 s; 20 independent runs per configuration |

The complete parameter sheet is generated at
`results/simulation_parameters.csv` / `.png`.

## 6. Generated Artifacts (`results/`)

- `figure3_computational_overhead.png` … `figure6_scalability_delay.png`
- `overhead_comparison.csv`, `scalability_delay.csv` (mean ± std),
  `attack_results.csv`, `summary.txt`
- `simulation_parameters.csv/.png`, `environment_overview.png`
- `frames/frame_*.png`, `simulation_animation.gif`
- `simulation_log.txt` — timestamped events: TA init, RSU deployment,
  vehicle creation/registration (real PIDs), `AuthV` exchanges,
  established `K_sess` values, blocked replay/MITM events, e.g.
  `!! ADVERSARY replays V_032's AuthV -> REJECTED (stale/replayed nonce)`

## 7. Dependencies

| Library | Version | Purpose |
|---|---|---|
| kyber-py | 1.2.0 | ML-KEM-768 (FIPS 203), pure Python |
| dilithium-py | 1.4.0 | ML-DSA-65 (FIPS 204), pure Python |
| ecdsa | — | ECC baseline primitive timing |
| matplotlib | — | Figures & live environment frames |
| pandas | — | CSV exports |
| Pillow | — | GIF assembly |

Python 3.10+ required. No GPU, no compiled dependencies.

## 8. Limitations

This evaluation targets protocol- and cryptographic-level feasibility,
consistent with the paper's own stated scope: wireless fading,
interference, handovers, packet loss and OBU hardware constraints are
not modelled; baseline schemes are emulated rather than executed from
their original source code. Timings are reported on the paper's
benchmark platform via the documented normalisation, not as absolute
cross-platform rankings.
