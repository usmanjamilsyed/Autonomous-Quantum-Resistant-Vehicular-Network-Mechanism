"""
UPQ-PAKE visual environment demo - reproduces the paper's Table 3
simulation environment with the real protocol stack running on every
authentication event.

Run:  venv_automis\\Scripts\\python.exe run_environment.py
Outputs: results/frames/*.png, simulation_animation.gif,
         simulation_log.txt, environment_overview.png,
         simulation_parameters.csv/.png
"""

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import Circle

from upqpake_sim.visual_sim import run_visual, AREA, RSU_RANGE

RESULTS = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS, exist_ok=True)

# ------------------------------------------------- parameter table
PARAMS = [
    ("Processor",              "Intel Core i7-12700 (12th Gen, 2.10-4.90 GHz)"),
    ("RAM",                    "16 GB DDR4"),
    ("Operating System",       "Ubuntu 22.04 LTS (paper) / Windows sim host"),
    ("Python Version",         "Python 3.x (pure-Python PQ backend)"),
    ("Cryptographic Library",  "kyber-py 1.2.0 / dilithium-py 1.4.0 (paper: liboqs 0.14.0)"),
    ("ML-KEM Parameter Set",   "ML-KEM-768 (FIPS 203)"),
    ("ML-DSA Parameter Set",   "ML-DSA-65 (FIPS 204)"),
    ("Hash Function",          "SHA3-256"),
    ("Key Derivation Function", "HKDF-SHA3"),
    ("Security Level",         "NIST Security Level 3"),
    ("Simulator",              "Python DES (paper: OMNeT++ 6.1 + SUMO 1.20.0)"),
    ("Network Type",           "Vehicle-to-Infrastructure (V2I)"),
    ("Communication Standard", "IEEE 802.11p / 5G NR-V2X"),
    ("Simulation Area",        "1000 m x 1000 m"),
    ("Number of Vehicles",     "50-500 (performance); 40 (visual demo)"),
    ("Number of RSUs",         "5-20 (performance); 6 (visual demo)"),
    ("Vehicle Speed",          "20-200 km/h"),
    ("RSU Coverage",           "300 m (V2I range)"),
    ("PCert Pool per Vehicle", "8 short-lived pseudonym credentials"),
    ("Auth Tuple Size",        "19,884 B (Table 7 byte-exact)"),
    ("Freshness Window",       "30 s timestamp validity"),
    ("Simulation Duration",    "300-600 s (perf); 30 s (visual demo)"),
    ("Independent Runs",       "20 per configuration"),
    ("epk / ct / ss (ML-KEM)", "1184 B / 1088 B / 32 B"),
    ("pk / sig (ML-DSA)",      "1952 B / 3309 B"),
    ("Random Seed",            "11 (visual), 2026 (performance)"),
]

df = pd.DataFrame(PARAMS, columns=["Parameter", "Configuration"])
df.to_csv(os.path.join(RESULTS, "simulation_parameters.csv"), index=False)

fig, ax = plt.subplots(figsize=(10, 8))
ax.axis("off")
tbl = ax.table(cellText=df.values, colLabels=df.columns,
               cellLoc="left", loc="center")
tbl.auto_set_font_size(False)
tbl.set_fontsize(8)
tbl.scale(1, 1.35)
for (r, c), cell in tbl.get_celld().items():
    if r == 0:
        cell.set_facecolor("#2c3e50")
        cell.set_text_props(color="white", weight="bold")
    cell.set_edgecolor("#bdc3c7")
ax.set_title("Experimental Setup and Simulation Parameters (Table 3)",
             fontsize=12, pad=14)
fig.tight_layout()
fig.savefig(os.path.join(RESULTS, "simulation_parameters.png"), dpi=200)
plt.close(fig)
print("parameter table written")

# ------------------------------------------------- overview map
fig, ax = plt.subplots(figsize=(7, 7))
ax.set_xlim(0, AREA)
ax.set_ylim(0, AREA)
ax.set_aspect("equal")
ax.set_facecolor("#f5f6fa")
ax.grid(ls=":", alpha=0.4)
import math, random
rng = random.Random(11)
n_rsu = 6
cols = math.ceil(math.sqrt(n_rsu * 2))
rows = math.ceil(n_rsu / cols)
rsus = [(AREA * (c + 0.5) / cols, AREA * (r + 0.5) / rows)
        for i in range(n_rsu) for c, r in [(i % cols, i // cols)]]
for i, (x, y) in enumerate(rsus):
    ax.add_patch(Circle((x, y), RSU_RANGE, color="#8e44ad", alpha=0.08))
    ax.plot(x, y, "s", color="#8e44ad", ms=11)
    ax.annotate(f"RSU_{i}", (x, y + 35), ha="center", fontsize=9,
                color="#5e2d78")
for i in range(40):
    ax.plot(rng.uniform(0, AREA), rng.uniform(0, AREA), "o",
            color="#2980b9", ms=4)
ax.set_title("UPQ-PAKE deployment map - 1000 x 1000 m, 6 RSUs (300 m), "
             "40 vehicles")
ax.set_xlabel("x (m)")
ax.set_ylabel("y (m)")
fig.tight_layout()
fig.savefig(os.path.join(RESULTS, "environment_overview.png"), dpi=200)
plt.close(fig)
print("overview map written")

# ------------------------------------------------- run visual sim
sim, frames, gif_path, log_path = run_visual(
    n_vehicles=40, n_rsu=6, sim_time=30.0, dt=0.1, outdir=RESULTS)
print(f"\nframes: {len(frames)}")
print(f"gif: {gif_path}")
print(f"log: {log_path}")
print(f"stats: {sim.stats}")
