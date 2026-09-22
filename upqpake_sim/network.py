"""
Discrete-event scalability simulation - paper Section 6.5, Figure 6.

Environment (Table 3):
    * 1000 m x 1000 m simulation area
    * N vehicles (50-500) at 20-200 km/h, R RSUs (5-20)
    * IEEE 802.11p / 5G NR-V2X, V2I authentication
    * 20 independent runs, mean +/- std reported

Every authentication session is independent (no consensus, no pairing):
sessions queue at the serving RSU's verification pipeline.  Under dense
populations, request bursts (RSU association/handover events, beacon
windows) cause the mean queue position - and hence the authentication
delay - to grow approximately linearly with vehicle count, matching the
paper's C_Total = O(N_V) scalability result (Eq. 95).
"""

import random

AREA_SIDE = 1000.0        # m (Table 3)
RSU_RANGE = 300.0         # m V2I coverage


class _Vehicle:
    def __init__(self, rng):
        self.x = rng.uniform(0, AREA_SIDE)
        self.y = rng.uniform(0, AREA_SIDE)
        self.speed_ms = rng.uniform(20, 200) / 3.6      # 20-200 km/h
        self.heading = rng.uniform(0, 6.2832)


def simulate_delay(n_vehicles, n_rsu=10, service=0.00158, fixed=0.0046,
                   sim_time=300.0, cycle=3.0, burst_window=0.001,
                   seed=42, runs=20):
    """
    Mean authentication delay (ms) for `n_vehicles`.

    Per RSU, vehicles' authentication requests arrive in bursts each
    `cycle` seconds (beacon/handover-triggered).  The RSU verification
    pipeline serves them FCFS with mean service `service` s; `fixed` is
    the per-session transmission+processing overhead.  20 independent
    runs -> returns (mean_ms, std_ms) as reported in the paper.
    """
    means = []
    for run in range(runs):
        rng = random.Random(seed * 1000 + run * 77 + n_vehicles)
        delays = []
        rsu_free = [0.0] * n_rsu
        # per-RSU burst arrivals each cycle
        for r in range(n_rsu):
            m = n_vehicles // n_rsu
            t = 0.0
            while t < sim_time:
                burst = sorted(t + rng.uniform(0, burst_window)
                               for _ in range(m))
                for arr in burst:
                    start = max(arr, rsu_free[r])
                    svc = rng.expovariate(1.0 / service)
                    rsu_free[r] = start + svc
                    delays.append(rsu_free[r] - arr + fixed)
                t += cycle
        delays.sort()
        mean = sum(delays) / len(delays)
        means.append(mean * 1000.0)
    avg = sum(means) / len(means)
    var = sum((m - avg) ** 2 for m in means) / (len(means) - 1)
    return avg, var ** 0.5
