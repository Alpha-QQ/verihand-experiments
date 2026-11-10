"""VeriHand / DP-DID experiments: one entry point for every result in the paper.

Edit only the CONFIG block below (or pass --profile quick|paper), then run
    python3 main.py
All parameters and results (means, standard deviations, pass/fail flags, and the
derived numbers quoted in the paper) are written to one JSON file, results.json.
Timings depend on the machine; they are stored with the machine description.
"""
import argparse
import datetime
import json
import os
import platform
import sys
import time

from verihand import attacks, fault_handling, grid, rust_bench, stats, weights

# ----------------------------------------------------------------------------------
# CONFIG: the only part you need to change.
# ----------------------------------------------------------------------------------
PROFILE = "paper"          # "paper": parameters of the paper; "quick": smoke test

PROFILES = {
    "paper": {
        "output": "results.json",
        "run": {                            # switch individual experiments on or off
            "attacks": True, "corruption_grid": True, "weight_timing": True,
            "fault_handling": True, "rust_handoff": True, "rust_sweep": True,
            "rust_baseline": True, "rust_issuance": True, "rust_revocation": True,
        },
        "attacks": {"a1_num_revoked": 3, "n": 20, "t": 7, "gamma": 1000},
        "corruption_grid": {"n": 20, "t": 7, "gamma": 200},
        "weight_timing": {"configs": [[5, 3], [20, 7]], "gamma": 30},
        "fault_handling": {"configs": [[5, 3], [20, 7]], "gamma": 8},
        "rust_handoff": {"n": 20, "t": 7, "gammas": [1000, 10000, 100000],
                         "reps_multithreaded": 10, "reps_single_threaded": 10,
                         "threads": None},        # None = all cores
        "rust_sweep": {"gamma": 20000, "reps": 10,
                       "configs": [[10, 7], [20, 7], [30, 7], [40, 7], [50, 7],
                                   [30, 3], [30, 9], [30, 15]]},
        "rust_baseline": {"n": 20, "t": 7, "gammas": [1000, 10000, 100000], "reps": 10},
        "rust_issuance": {"n": 20, "t": 7, "credentials": 100},
        "rust_revocation": {"revoked": [1000, 10000, 100000, 1000000]},
        "cargo_target_dir": None,              # None = rust/target
    },
    "quick": {
        "output": "results-quick.json",
        "run": {
            "attacks": True, "corruption_grid": True, "weight_timing": True,
            "fault_handling": True, "rust_handoff": True, "rust_sweep": True,
            "rust_baseline": True, "rust_issuance": True, "rust_revocation": True,
        },
        "attacks": {"a1_num_revoked": 3, "n": 20, "t": 7, "gamma": 20},
        "corruption_grid": {"n": 20, "t": 7, "gamma": 5},
        "weight_timing": {"configs": [[5, 3]], "gamma": 4},
        "fault_handling": {"configs": [[5, 3]], "gamma": 4},
        "rust_handoff": {"n": 20, "t": 7, "gammas": [100], "reps_multithreaded": 2,
                         "reps_single_threaded": 2, "threads": None},
        "rust_sweep": {"gamma": 100, "reps": 1, "configs": [[10, 3]]},
        "rust_baseline": {"n": 20, "t": 7, "gammas": [100], "reps": 2},
        "rust_issuance": {"n": 5, "t": 3, "credentials": 5},
        "rust_revocation": {"revoked": [1000]},
        "cargo_target_dir": None,
    },
}
# ----------------------------------------------------------------------------------

HANDOFF_KEYS = ["orig_offline_member_ms", "orig_handoff_recv_ms", "plus_deal_member_ms",
                "plus_recv_member_ms", "plus_public_ms", "per_dealer_fallback_ms",
                "retry_commit_ms", "retry_recv_ms", "retry_public_ms", "a2_success_of_50",
                "const_ok", "recv_ok", "newv_ok", "correct", "tamper_caught",
                "cancel_attack_caught", "retry_ok", "audit_ok", "audit_all_ms",
                "worst_ok", "worst_attempts", "worst_commit_ms_total", "worst_recv_ms_total",
                "worst_public_ms_total"]
BASELINE_KEYS = ["deal_member_ms", "recv_member_ms", "derive_member_ms",
                 "derive_agg_setup_ms", "derive_agg_member_ms", "derive_agg_matches",
                 "bcast_bytes_total", "bcast_bytes_derived", "p2p_bytes_per_receiver", "ok"]
ISSUANCE_KEYS = ["dkg_ms_total_sim", "partial_sign_ms_per_cred_all_t",
                 "partial_verify_ms_per_cred", "verify_cred_ms"]
REVOCATION_KEYS = ["build_ms", "prove_us", "verify_us", "avg_siblings", "avg_proof_bytes"]


def log(msg):
    print(f"[{datetime.datetime.now():%H:%M:%S}] {msg}", flush=True)


def repeated(bin_dir, name, args, reps, keys):
    runs = [rust_bench.run(bin_dir, name, *args) for _ in range(reps)]
    return {"args": list(args), "reps": reps, "summary": stats.summarize(runs, keys),
            "all_checks_pass": stats.all_flags(runs), "runs": runs}


def verihand_public_bytes(n, t, gamma):
    """Public data of a VeriHand handoff: share keys, digests and commitments (Sec. VIII)."""
    return 48 * n * gamma + 32 * n * n + 48 * t * t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=sorted(PROFILES), default=PROFILE)
    cfg = PROFILES[ap.parse_args().profile]
    started = time.time()
    res = {"meta": {"profile": ap.parse_args().profile,
                    "started": datetime.datetime.now().isoformat(timespec="seconds"),
                    "note": "Timings are machine-dependent; all other values are not."},
           "machine": {"platform": platform.platform(), "processor": platform.processor(),
                       "cpu_count": os.cpu_count(), "python": sys.version.split()[0]},
           "config": cfg}
    run = cfg["run"]

    # ---- algebraic attacks on DP-DID (Section IV, Table VII) ----
    if run["attacks"]:
        c = cfg["attacks"]
        log("attacks A1, A2, Q3, A3")
        res["attacks"] = {"A1": attacks.attack_a1(c["a1_num_revoked"]),
                          "A2": attacks.attack_a2(c["n"], c["t"], c["gamma"]),
                          "Q3": attacks.attack_q3(c["n"], c["t"], c["gamma"]),
                          "A3": attacks.attack_a3(c["n"], c["t"])}

    # ---- corruption grid (Fig. 3) ----
    if run["corruption_grid"]:
        c = cfg["corruption_grid"]
        log("corruption grid")
        res["corruption_grid"] = grid.corruption_grid(c["n"], c["t"], c["gamma"])

    # ---- weight timing (Remark 1) and Theorem 1 check ----
    if run["weight_timing"]:
        c = cfg["weight_timing"]
        log("weight timing (Remark 1)")
        res["weight_timing"] = {
            "shift_fixed_weights": [weights.shift_attack(n, t, c["gamma"], "fixed") for n, t in c["configs"]],
            "shift_weights_after_F": [weights.shift_attack(n, t, c["gamma"], "after_F") for n, t in c["configs"]],
            "cancel_weights_rho_only": [weights.cancellation_attack(n, t, c["gamma"], "rho_only") for n, t in c["configs"]],
            "cancel_weights_after_F": [weights.cancellation_attack(n, t, c["gamma"], "after_F") for n, t in c["configs"]],
            "theorem1_rejected_dealing": [weights.rejected_dealing_share_keys(n, t) for n, t in c["configs"]],
        }

    # ---- fault handling of Algorithm 1 (Section VIII-D) ----
    if run["fault_handling"]:
        c = cfg["fault_handling"]
        log("fault handling")
        runs = fault_handling.run_scenarios([tuple(x) for x in c["configs"]], c["gamma"])
        res["fault_handling"] = {"scenarios": len(runs), "all_ok": all(r["ok"] for r in runs),
                                 "max_attempts": max(r["attempts"] for r in runs), "runs": runs}

    # ---- Rust measurements ----
    if any(run[k] for k in run if k.startswith("rust_")):
        log("building Rust prototype (cargo build --release)")
        bin_dir = rust_bench.build(cfg["cargo_target_dir"])
        if run["rust_handoff"]:
            c = cfg["rust_handoff"]
            mt, st1 = [], []
            for g in c["gammas"]:
                log(f"handoff Gamma={g} (multi-threaded)")
                args = [c["n"], c["t"], g] + ([c["threads"]] if c["threads"] else [])
                mt.append(repeated(bin_dir, "dpdid_plus", args, c["reps_multithreaded"], HANDOFF_KEYS))
                log(f"handoff Gamma={g} (single-threaded)")
                st1.append(repeated(bin_dir, "dpdid_plus", [c["n"], c["t"], g, 1],
                                    c["reps_single_threaded"], HANDOFF_KEYS))
            res["handoff_multithreaded"], res["handoff_single_threaded"] = mt, st1
        if run["rust_sweep"]:
            c = cfg["rust_sweep"]
            res["sweep"] = []
            for n, t in c["configs"]:
                log(f"sweep n={n} t={t}")
                res["sweep"].append(repeated(bin_dir, "dpdid_plus", [n, t, c["gamma"]], c["reps"], HANDOFF_KEYS))
        if run["rust_baseline"]:
            c = cfg["rust_baseline"]
            res["per_secret_baseline"] = []
            for g in c["gammas"]:
                log(f"per-secret baseline Gamma={g}")
                res["per_secret_baseline"].append(
                    repeated(bin_dir, "baseline", [c["n"], c["t"], g], c["reps"], BASELINE_KEYS))
        if run["rust_issuance"]:
            c = cfg["rust_issuance"]
            log("issuance, LA-FS")
            r = rust_bench.run(bin_dir, "issuance", c["n"], c["t"], c["credentials"])
            res["issuance"] = {"args": [c["n"], c["t"], c["credentials"]], "result": r,
                               "all_checks_pass": stats.all_flags([r])}
        if run["rust_revocation"]:
            c = cfg["rust_revocation"]
            res["revocation"] = []
            for s in c["revoked"]:
                log(f"revocation |S_D|={s}")
                r = rust_bench.run(bin_dir, "revocation", s)
                res["revocation"].append({"revoked": s, "result": r, "all_checks_pass": stats.all_flags([r])})

    res["paper_numbers"] = derived_numbers(res)
    res["meta"]["runtime_s"] = round(time.time() - started, 1)
    with open(cfg["output"], "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    log(f"wrote {cfg['output']}")
    print(json.dumps(res["paper_numbers"], indent=2))


def derived_numbers(res):
    """Numbers quoted in the paper's text, computed from the results above."""
    out = {}
    if "corruption_grid" in res:
        g = res["corruption_grid"]
        out["grid_dpdid_pairs_all_lost"] = f"{g['dpdid_pairs_all_lost']} of {g['admissible_pairs']}"
        out["grid_verihand_pairs_any_lost"] = g["verihand_pairs_any_lost"]
    if "fault_handling" in res:
        f = res["fault_handling"]
        out["fault_handling"] = f"{f['scenarios']} runs, all ok: {f['all_ok']}, max attempts {f['max_attempts']}"
    mt = {e["args"][2]: e["summary"] for e in res.get("handoff_multithreaded", [])}
    for g, m in sorted(mt.items()):
        if "audit_all_ms" in m:
            out[f"gamma_{g}_roles_multithreaded"] = {
                "dealer_s": m["plus_deal_member_ms"]["mean"] / 1e3,
                "receiver_s": m["plus_recv_member_ms"]["mean"] / 1e3,
                "auditor_all_members_s": m["audit_all_ms"]["mean"] / 1e3,
                "worst_case_attempts": m["worst_attempts"]["mean"],
                "worst_case_receiver_total_s": m["worst_recv_ms_total"]["mean"] / 1e3,
                "worst_case_public_total_s": m["worst_public_ms_total"]["mean"] / 1e3,
            }
    st1 = {e["args"][2]: e["summary"] for e in res.get("handoff_single_threaded", [])}
    base = {e["args"][2]: e for e in res.get("per_secret_baseline", [])}
    for g in sorted(set(st1) & set(base)):
        b, v = base[g]["summary"], st1[g]
        n, t = base[g]["args"][0], base[g]["args"][1]
        vb = verihand_public_bytes(n, t, g)
        out[f"gamma_{g}"] = {
            "verihand_deal_ms_single_threaded": v["plus_deal_member_ms"]["mean"],
            "deal_speedup_vs_per_secret": b["deal_member_ms"]["mean"] / v["plus_deal_member_ms"]["mean"],
            "receive_speedup_vs_per_secret": b["recv_member_ms"]["mean"] / v["plus_recv_member_ms"]["mean"],
            "verihand_public_MB": vb / 1e6,
            "per_secret_public_MB_published_keys": b["bcast_bytes_total"]["mean"] / 1e6,
            "per_secret_public_MB_derived_keys": b["bcast_bytes_derived"]["mean"] / 1e6,
            "public_data_ratio_published_keys": b["bcast_bytes_total"]["mean"] / vb,
            "public_data_ratio_derived_keys": b["bcast_bytes_derived"]["mean"] / vb,
            "per_secret_key_derivation_s_per_member": b["derive_member_ms"]["mean"] / 1e3,
            # coefficient aggregation C_il = prod_j A_ijl^{lambda_j}, computed once and reused
            "per_secret_key_aggregation_setup_s": b["derive_agg_setup_ms"]["mean"] / 1e3,
            "per_secret_key_derivation_s_per_member_reused": b["derive_agg_member_ms"]["mean"] / 1e3,
        }
    return out


if __name__ == "__main__":
    main()
