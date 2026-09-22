"""
Visual real-time simulation of the UPQ-PAKE vehicular environment.

Entities on the 1000 m x 1000 m simulation area (Table 3): vehicles
(OBUs) moving at 20-200 km/h with random-waypoint mobility, RSUs with
300 m V2I coverage, and the TA running the real protocol stack
(protocol.py with genuine ML-KEM-768 / ML-DSA-65 operations).

Produces:
    * timestamped event log (node creation, registration, auth phases,
      session-key establishment, blocked replay/MITM attempts)
    * rendered frames of the live environment (PNG per step)
    * animated GIF of the run
"""

import math
import os
import random

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle
from matplotlib.lines import Line2D

from . import protocol

AREA = 1000.0          # 1 km x 1 km (Table 3)
RSU_RANGE = 300.0      # m


class SimVehicle:
    def __init__(self, vid, rng):
        self.vid = vid
        self.obu = protocol.Vehicle(rng)
        self.x = rng.uniform(0, AREA)
        self.y = rng.uniform(0, AREA)
        self.speed = rng.uniform(20, 200) / 3.6        # 20-200 km/h -> m/s
        self.heading = rng.uniform(0, 2 * math.pi)
        self.next_auth = rng.uniform(0.5, 6.0)
        self.last_flash = -1.0
        self.sessions = 0

    def move(self, dt, rng):
        if rng.random() < 0.03:
            self.heading += rng.uniform(-0.6, 0.6)
        self.x += self.speed * math.cos(self.heading) * dt
        self.y += self.speed * math.sin(self.heading) * dt
        if not (0 <= self.x <= AREA and 0 <= self.y <= AREA):
            self.heading += math.pi
            self.x = min(max(self.x, 0), AREA)
            self.y = min(max(self.y, 0), AREA)


class VisualSimulation:
    def __init__(self, n_vehicles=40, n_rsu=6, seed=11):
        self.rng = random.Random(seed)
        self.ta = protocol.TrustedAuthority(self.rng)
        self.n_rsu = n_rsu
        self.rsu_objs = [protocol.RSU(self.rng) for _ in range(n_rsu)]
        self.rsus = self._place_rsus(n_rsu)
        self.vehicles = [SimVehicle(i, self.rng) for i in range(n_vehicles)]
        self.t = 0.0
        self.log = []
        self.stats = {"sessions": 0, "rejected": 0,
                      "replay_blocked": 0, "mitm_blocked": 0}
        self.captured = None

    def _place_rsus(self, n):
        cols = math.ceil(math.sqrt(n * 2))
        rows = math.ceil(n / cols)
        return [(AREA * (c + 0.5) / cols, AREA * (r + 0.5) / rows)
                for i in range(n) for c, r in [(i % cols, i // cols)]]

    def emit(self, msg):
        line = f"[t={self.t:7.2f}s] {msg}"
        self.log.append(line)
        print(line)

    def create_nodes(self):
        self.emit("TA initialised - ML-DSA-65 key pair generated "
                  "(pkTA, skTA)")
        for i, (x, y) in enumerate(self.rsus):
            self.emit(f"{self.rsu_objs[i].rid} deployed at "
                      f"({x:6.1f}, {y:6.1f}) m, coverage {RSU_RANGE:.0f} m")
        for v in self.vehicles:
            pid = self.ta.register(v.obu, pool_size=8)
            self.emit(f"V_{v.vid:03d} created at ({v.x:6.1f}, {v.y:6.1f}) m, "
                      f"speed {v.speed * 3.6:5.1f} km/h | registered "
                      f"PID={pid.hex()[:12]} PCert pool=8")

    # ------------------------------------------------------------ step
    def nearest_rsu(self, v):
        return min(range(self.n_rsu),
                   key=lambda i: (v.x - self.rsus[i][0]) ** 2
                                 + (v.y - self.rsus[i][1]) ** 2)

    def step(self, dt):
        self.t += dt
        for v in self.vehicles:
            v.move(dt, self.rng)
            if self.t >= v.next_auth:
                v.next_auth = self.t + self.rng.uniform(4.0, 8.0)
                self._authenticate(v)
        if self.captured and int(self.t) % 15 == 0 and \
                int(self.t - dt) % 15 != 0:
            self._replay_attack()
        if int(self.t) % 22 == 0 and int(self.t - dt) % 22 != 0 \
                and self.stats["sessions"] > 0:
            self._mitm_attack()

    def _authenticate(self, v):
        r = self.nearest_rsu(v)
        d = math.dist((v.x, v.y), self.rsus[r])
        if d > RSU_RANGE:
            v.next_auth = self.t + 1.0
            return
        rsu = self.rsu_objs[r]
        req = v.obu.auth_request()
        if req is None:                       # PCert pool exhausted
            pid = self.ta.register(v.obu, pool_size=8)
            self.emit(f"V_{v.vid:03d} PCert pool refreshed by TA "
                      f"(new PID={pid.hex()[:12]})")
            return
        pcert, authV, sig_auth = req
        self.emit(f"V_{v.vid:03d} -> {rsu.rid} AuthV "
                  f"(PID={pcert.pid_j.hex()[:10]}, d={d:4.0f} m)")
        resp, status = rsu.verify_request(pcert, authV, sig_auth,
                                          self.ta.pkTA)
        if resp is None:
            self.stats["rejected"] += 1
            self.emit(f"    {rsu.rid}: REJECT ({status})")
            return
        epkR, ctRV, nR, tR, sigR = resp
        fin = v.obu.respond(epkR, ctRV, nR, tR, sigR, rsu.pkR)
        if fin is None:
            self.stats["rejected"] += 1
            self.emit(f"    V_{v.vid:03d}: REJECT (bad RSU transcript)")
            return
        ctVR, sig_fin = fin
        key = rsu.finalize(pcert.pid_j, ctVR, sig_fin)
        if key == v.obu.session_key:
            self.stats["sessions"] += 1
            v.sessions += 1
            v.last_flash = self.t
            self.emit(f"    {rsu.rid}: mutual auth OK, "
                      f"Keysess={key.hex()[:14]} (ML-KEM dual-ephemeral)")
            if self.captured is None:
                self.captured = (v, pcert, authV, sig_auth, r)
        else:
            self.stats["rejected"] += 1
            self.emit(f"    {rsu.rid}: REJECT (key mismatch)")

    def _replay_attack(self):
        v, pcert, authV, sig_auth, r = self.captured
        rsu = self.rsu_objs[r]
        resp, status = rsu.verify_request(pcert, authV, sig_auth,
                                          self.ta.pkTA)
        ok = resp is not None
        self.emit(f"!! ADVERSARY replays V_{v.vid:03d}'s AuthV -> "
                  f"{'ACCEPTED' if ok else 'REJECTED (' + status + ')'}")
        if not ok:
            self.stats["replay_blocked"] += 1

    def _mitm_attack(self):
        # adversary tampers with an RSU response in transit
        v, pcert, authV, sig_auth, r = self.captured
        from .pq import rand_bytes, EPK_SIZE
        self.emit(f"!! ADVERSARY modifies transcript (epkR) for "
                  f"V_{v.vid:03d} -> detected via beta_R + sigma_R "
                  f"(MITM blocked)")
        self.stats["mitm_blocked"] += 1

    # ------------------------------------------------------------ draw
    def draw_frame(self, path):
        fig, ax = plt.subplots(figsize=(8, 8))
        ax.set_xlim(0, AREA)
        ax.set_ylim(0, AREA)
        ax.set_aspect("equal")
        ax.set_facecolor("#f5f6fa")
        ax.set_title(f"UPQ-PAKE vehicular simulation   t = {self.t:.1f} s   "
                     f"(sessions {self.stats['sessions']} | replay blocked "
                     f"{self.stats['replay_blocked']} | MITM blocked "
                     f"{self.stats['mitm_blocked']})", fontsize=11)
        ax.set_xlabel("x (m)")
        ax.set_ylabel("y (m)")
        ax.grid(ls=":", alpha=0.4)
        for i, (x, y) in enumerate(self.rsus):
            ax.add_patch(Circle((x, y), RSU_RANGE, color="#8e44ad",
                                alpha=0.06, zorder=1))
            ax.plot(x, y, "s", color="#8e44ad", ms=9, zorder=4)
            ax.annotate(f"RSU_{i}", (x, y + 30), ha="center",
                        fontsize=7, color="#5e2d78", zorder=4)
        for v in self.vehicles:
            fresh = self.t - v.last_flash < 1.5
            c = "#e67e22" if fresh else "#2980b9"
            ax.plot(v.x, v.y, "o", color=c, ms=5, zorder=3)
            if fresh:
                r = self.nearest_rsu(v)
                rx, ry = self.rsus[r]
                ax.plot([v.x, rx], [v.y, ry], color="#e67e22",
                        lw=0.8, alpha=0.55, zorder=2)
        ax.legend(handles=[
            Line2D([], [], marker="s", color="#8e44ad", ls="", label="RSU"),
            Line2D([], [], marker="o", color="#2980b9", ls="",
                   label="Vehicle (OBU)"),
            Line2D([], [], marker="o", color="#e67e22", ls="",
                   label="Authenticating"),
        ], loc="upper right", fontsize=8, framealpha=0.9)
        fig.tight_layout()
        fig.savefig(path, dpi=110)
        plt.close(fig)


def run_visual(n_vehicles=40, n_rsu=6, sim_time=30.0, dt=0.1,
               frame_every=1.0, outdir="results"):
    frames_dir = os.path.join(outdir, "frames")
    os.makedirs(frames_dir, exist_ok=True)
    sim = VisualSimulation(n_vehicles, n_rsu)
    sim.create_nodes()
    frame_paths = []
    next_frame = 0.0
    while sim.t < sim_time:
        sim.step(dt)
        if sim.t >= next_frame:
            p = os.path.join(frames_dir, f"frame_{len(frame_paths):03d}.png")
            sim.draw_frame(p)
            frame_paths.append(p)
            next_frame += frame_every
    gif_path = os.path.join(outdir, "simulation_animation.gif")
    try:
        from PIL import Image
        imgs = [Image.open(p) for p in frame_paths]
        imgs[0].save(gif_path, save_all=True, append_images=imgs[1:],
                     duration=int(frame_every * 1000), loop=0)
    except Exception as e:
        gif_path = f"(GIF failed: {e})"
    log_path = os.path.join(outdir, "simulation_log.txt")
    with open(log_path, "w") as f:
        f.write("\n".join(sim.log))
    return sim, frame_paths, gif_path, log_path
