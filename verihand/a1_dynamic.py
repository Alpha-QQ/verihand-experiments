"""Cross-epoch share combination (A1) with an explicit membership change.

Two committees share the index set 1..n: members at the first n - m indices stay,
the m members at the last indices leave and m new members join at those indices
(DP-DID identifies a node by its index k and its point x_k). The handoff runs in
one of three ways:

  incoming    DP-DID Eq. (4), computed by the node at k in the new committee: a
              joining member receives the old share p_k and the update columns.
  forwarding  DP-DID Eq. (4), computed by the node at k in the old committee; a
              departing member forwards p'_k to the joining member.
  verihand    resharing from shares: each of t dealers deals a fresh sharing of its
              share; a joining member receives only sub-shares. VeriHand always erases,
              so it is evaluated under rules II and III only. Its rows count the shares
              of each epoch that the adversary holds (sub-shares from honest dealers at
              other points are not available to it); secrecy itself is Theorem 1.

The adversary follows a schedule of corruptions, each at one time: epoch e-1
proper ('old'), the handoff window W_e ('window') or epoch e proper ('new').
Corrupting a party reveals the state it holds at that time (worst case within the
window: after its computation). Each schedule is charged under three accounting
rules (Section IV-B of the paper):

  I    as specified: no erasure; a corruption counts in the epoch of its time
       slot, also for a node that has left the committee; the specification assigns
       no epoch to the window, so a schedule with a window corruption is not
       evaluable under I.
  II   erasure at the end of W_e; a corruption counts against every committee the
       party belongs to at that time (window: old and/or new committee); a departed
       node holds nothing after W_e.
  III  erasure at the end of W_e; a corruption counts against epoch e-1 if the
       party then holds epoch-(e-1) share material (an old share or values that
       determine it) and against epoch e if it holds an epoch-e share.

A schedule is admissible under a rule if each budget is at most t - 1. The
adversary then interpolates every user secret from the old shares and, separately,
from the new shares it holds. A1 applies to a handoff variant under a rule iff some
admissible schedule recovers every secret.
"""
from .field import R, evaluate, interpolate_at0, lagrange_coeffs, rand, random_poly


def _setup(n, t, gamma):
    xs = list(range(1, n + 1))
    s = [rand() for _ in range(gamma)]
    polys = [random_poly(v, t - 1) for v in s]
    old = [[evaluate(p, x) for x in xs] for p in polys]           # old[i][k]
    return xs, s, old


def _dpdid_new(old, n, t, gamma, xs):
    """DP-DID Offline + Eq. (4). Returns new shares and update-column sums."""
    zsum = [[0] * n for _ in range(gamma)]
    for _ in range(n):                                            # every member j
        for i in range(gamma):
            row = [0] + [rand() for _ in range(t - 1)]              # first column zero
            for k in range(n):
                zsum[i][k] = (zsum[i][k] + evaluate(row, xs[k])) % R
    new = [[(old[i][k] + zsum[i][k]) % R for k in range(n)] for i in range(gamma)]
    return new, zsum


def _verihand_new(old, n, t, gamma, xs, dealers):
    q = {j: [random_poly(old[i][j], t - 1) for i in range(gamma)] for j in dealers}
    lam = lagrange_coeffs([xs[j] for j in dealers])
    new = [[sum(lam[a] * evaluate(q[j][i], xs[k]) for a, j in enumerate(dealers)) % R
            for k in range(n)] for i in range(gamma)]
    return new, q


def _state(role, k, time, variant, erasure):
    """Share material held by the party at index k: set of ('old'|'new', k)."""
    st = set()
    if role == "staying":
        if time == "old":
            st.add(("old", k))
        elif time == "window":
            st |= {("old", k), ("new", k)}
        else:
            st.add(("new", k))
            if not erasure:
                st.add(("old", k))
    elif role == "departing":
        if time == "old":
            st.add(("old", k))
        elif time == "window":
            st.add(("old", k))
            if variant == "forwarding":
                st.add(("new", k))
        elif not erasure:                                         # departed, epoch e proper:
            st.add(("old", k))                                    # keeps what it held
            if variant == "forwarding":
                st.add(("new", k))
    else:                                                         # joining
        if time == "window":
            st.add(("new", k))
            if variant == "incoming":
                st.add(("old", k))                              # p_k, or p'_k minus updates
        elif time == "new":
            st.add(("new", k))
            if variant == "incoming" and not erasure:
                st.add(("old", k))
    return st


def _charge(rule, role, time, state):
    """Budgets (epochs e-1 and e) that one corruption counts against."""
    if rule == "I":
        if time == "window":
            return None
        return {"e-1"} if time == "old" else {"e"}
    if rule == "II":
        if time == "old":
            return {"e-1"}
        if time == "new":
            return set() if role == "departing" else {"e"}       # a departed node is in no committee
        return {"staying": {"e-1", "e"}, "departing": {"e-1"}, "joining": {"e"}}[role]
    # rule III: by the share material held
    if time == "old":
        return {"e-1"}
    if time == "new":
        return {("e-1" if kind == "old" else "e") for kind, _ in state} if role == "departing" else {"e"}
    return {("e-1" if kind == "old" else "e") for kind, _ in state}


def _schedules(n, t, m):
    stay = list(range(n - m))
    leave = list(range(n - m, n))
    assert m >= t, "need at least t departing indices for schedule C"
    j_k = leave[-1]                                               # joining member's index
    return {
        "A: t-1 old members in epoch e-1, joining member in epoch e":
            [("staying", k, "old") for k in stay[:t - 1]] + [("joining", j_k, "new")],
        "B: t-1 old members in epoch e-1, joining member during W_e":
            [("staying", k, "old") for k in stay[:t - 1]] + [("joining", j_k, "window")],
        "C: t-1 departing members during W_e, joining member during W_e":
            [("departing", k, "window") for k in leave[:t - 1]] + [("joining", j_k, "window")],
        "D: t-1 departing members during W_e, joining member in epoch e":
            [("departing", k, "window") for k in leave[:t - 1]] + [("joining", j_k, "new")],
        "E: t-1 old members in epoch e-1, one departed member in epoch e":
            [("staying", k, "old") for k in stay[:t - 1]] + [("departing", leave[0], "new")],
    }


def a1_dynamic(n=20, t=7, gamma=1000, m=8):
    """Run every (variant, rule, schedule) combination; return records for results.json."""
    xs, s, old = _setup(n, t, gamma)
    new_dp, _ = _dpdid_new(old, n, t, gamma, xs)
    new_vh, _ = _verihand_new(old, n, t, gamma, xs, list(range(t)))
    new_of = {"incoming": new_dp, "forwarding": new_dp, "verihand": new_vh}
    records = []
    for variant in ("incoming", "forwarding", "verihand"):
        for rule in ("I", "II", "III"):
            erasure = rule != "I"
            if variant == "verihand" and not erasure:
                continue                                          # VeriHand always erases
            for name, sched in _schedules(n, t, m).items():
                held, budget, evaluable, events = set(), {"e-1": 0, "e": 0}, True, []
                for role, k, time in sched:
                    st = _state(role, k, time, variant, erasure)
                    if variant == "verihand" and role == "joining":
                        st = {("new", k)}                         # joining members never hold old shares
                    ch = _charge(rule, role, time, st)
                    if ch is None:
                        evaluable = False
                    else:
                        for c in ch:
                            budget[c] += 1
                    held |= st
                    events.append({"role": role, "index": k + 1, "time": time,
                                   "state": sorted(f"{a}_{b + 1}" for a, b in st),
                                   "charged_to": sorted(ch) if ch else None})
                olds = sorted(k for kind, k in held if kind == "old")
                news = sorted(k for kind, k in held if kind == "new")
                recovered = 0
                for i in range(gamma):
                    hit = False
                    if len(olds) >= t:
                        hit |= interpolate_at0([(xs[k], old[i][k]) for k in olds[:t]]) == s[i]
                    if len(news) >= t:
                        hit |= interpolate_at0([(xs[k], new_of[variant][i][k]) for k in news[:t]]) == s[i]
                    if not hit and olds and news:                 # mixed attempt
                        pts = [(xs[k], old[i][k]) for k in olds] + \
                              [(xs[k], new_of[variant][i][k]) for k in news if k not in olds]
                        hit = len(pts) >= t and interpolate_at0(pts[:t]) == s[i]
                    recovered += hit
                admissible = evaluable and budget["e-1"] <= t - 1 and budget["e"] <= t - 1
                if not evaluable:
                    budget = None                                 # the window has no epoch under rule I
                records.append({"variant": variant, "rule": rule, "schedule": name,
                                "evaluable": evaluable, "budget": budget,
                                "admissible": admissible,
                                "old_shares_held": len(olds), "new_shares_held": len(news),
                                "secrets_recovered": recovered, "gamma": gamma,
                                "events": events})
    summary = {}
    for variant in ("incoming", "forwarding", "verihand"):
        for rule in ("I", "II", "III"):
            rs = [r for r in records if r["variant"] == variant and r["rule"] == rule]
            if not rs:
                continue
            wins = [r["schedule"].split(":")[0] for r in rs
                    if r["admissible"] and r["secrets_recovered"] == gamma]
            summary[f"{variant}/{rule}"] = {"a1_applies": bool(wins), "via_schedules": wins}
    return {"n": n, "t": t, "gamma": gamma, "joining_members": m,
            "summary": summary, "records": records}
