"""Summary statistics for repeated runs: mean, sample standard deviation, relative std."""
import statistics


def summarize(runs, keys):
    """For each numeric key, return {mean, std, rsd_pct, n}; boolean keys must all hold."""
    out = {}
    for key in keys:
        xs = [r[key] for r in runs if key in r]
        if not xs:
            continue
        if all(isinstance(x, bool) for x in xs):
            out[key] = all(xs)
            continue
        mean = statistics.mean(xs)
        std = statistics.stdev(xs) if len(xs) > 1 else 0.0
        out[key] = {"mean": mean, "std": std,
                    "rsd_pct": (100.0 * std / mean) if mean else 0.0, "n": len(xs)}
    return out


def all_flags(runs):
    """True iff every boolean field of every run is True (the checks of the prototype),
    ignoring fields that report attack outcomes on the original scheme."""
    expected_false = {"paper_pkC_verifies", "lafs_backdated_anchored", "lafs_fake_path_anchored"}
    for r in runs:
        for k, v in r.items():
            if k == "worst_ok" and r.get("worst_attempts") == 0:
                continue                      # worst case not run: needs n >= 2t-1
            if isinstance(v, bool) and k not in expected_false and k != "lafs_backdated_sig_valid" and not v:
                return False
            if k in expected_false and v:
                return False
    return True
