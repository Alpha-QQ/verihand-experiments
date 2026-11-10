"""Corruption-pattern experiment (Fig. 3): secret-recovery rate for every pair (a, b).

a members are corrupted in epoch e-1 only, b members in epoch e (handoff state
included), on disjoint indices, both within the per-epoch bound t-1. The adversary
tries every interpolation available to it.
"""
from .field import R, evaluate, interpolate_at0, lagrange_coeffs, rand, random_poly


def corruption_grid(n, t, gamma):
    xs = list(range(1, n + 1))
    s = [rand() for _ in range(gamma)]
    polys = [random_poly(v, t - 1) for v in s]
    old = [[evaluate(p, x) for x in xs] for p in polys]
    # DP-DID handoff (Eq. 4)
    z = [[[evaluate([0] + [rand() for _ in range(t - 1)], x) for x in xs]
          for _ in range(gamma)] for _ in range(n)]
    new_dp = [[(old[i][k] + sum(z[j][i][k] for j in range(n))) % R for k in range(n)]
              for i in range(gamma)]
    # VeriHand handoff (resharing by the first t dealers)
    q = [[random_poly(old[i][j], t - 1) for i in range(gamma)] for j in range(t)]
    lam = lagrange_coeffs(xs[:t])
    new_vh = [[sum(lam[j] * evaluate(q[j][i], xs[k]) for j in range(t)) % R for k in range(n)]
              for i in range(gamma)]

    def pct(point_sets):
        hit = 0
        for i in range(gamma):
            if any(len(ps(i)) >= t and interpolate_at0(ps(i)[:t]) == s[i] for ps in point_sets):
                hit += 1
        return 100.0 * hit / gamma

    cells = []
    for a in range(t):
        for b in range(t):
            olds, news = list(range(a)), list(range(a, a + b))
            dp_old = lambda i: [(xs[k], old[i][k]) for k in olds] + \
                [(xs[k], (new_dp[i][k] - sum(z[j][i][k] for j in range(n))) % R) for k in news]
            dp_new = lambda i: [(xs[k], new_dp[i][k]) for k in news]
            vh_old = lambda i: [(xs[k], old[i][k]) for k in olds]
            vh_new = lambda i: [(xs[k], new_vh[i][k]) for k in news]
            vh_mix = lambda i: vh_old(i) + vh_new(i)
            cells.append({"a": a, "b": b, "dpdid_pct": pct([dp_old, dp_new]),
                          "verihand_pct": pct([vh_old, vh_new, vh_mix])})
    lost = [c for c in cells if c["dpdid_pct"] == 100.0]
    return {"n": n, "t": t, "gamma": gamma, "admissible_pairs": len(cells),
            "dpdid_pairs_all_lost": len(lost),
            "dpdid_lost_iff_a_plus_b_ge_t": all((c["a"] + c["b"] >= t) == (c["dpdid_pct"] == 100.0)
                                                for c in cells),
            "verihand_pairs_any_lost": sum(c["verihand_pct"] > 0 for c in cells),
            "cells": cells}
