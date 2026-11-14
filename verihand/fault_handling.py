"""Fault handling of Algorithm 1: deadlines, complaints, disqualification, restarts.

Group elements are represented by their discrete logs, so every check is a linear
equation over Z_r; the control flow (which messages exist by each deadline, who is
blamed, when rounds 2-7 restart) follows Algorithm 1 exactly. A party that misses a
deadline has no message on the ledger; absence is public.
"""
import secrets

from .field import R as r, evaluate as ev, hash_to_field as H, lagrange_coeffs as lagr

def handoff(n, t, G, bad_dealers, bad_receivers):
    """bad_dealers: {j: behaviour}, bad_receivers: {k: behaviour}. Returns a report."""
    X = list(range(1, n + 1))
    P = [[secrets.randbelow(r) for _ in range(t)] for _ in range(G)]
    S = [P[i][0] for i in range(G)]
    p = [[ev(P[i], X[j]) for j in range(n)] for i in range(G)]
    V = [[p[i][j] for j in range(n)] for i in range(G)]            # dlog of V_ij
    honest_recv = [k for k in range(n) if k not in bad_receivers]
    # ---- Round 1: deal and post digests (deadline D1) ----
    Qp = {}       # dealer j -> its sub-polynomials
    sent = {}     # (j, k) -> vector delivered privately
    digest = {}   # (j, k) -> salted digest h_jk = H(r_jk || s_jk) on the ledger
    salt = {}     # (j, k) -> 256-bit salt r_jk, sent privately with s_jk
    D = lambda j, k, v: H(salt[(j, k)], tuple(v))
    for j in range(n):
        b = bad_dealers.get(j)
        if b == 'no_digest':
            continue                                              # misses D1
        Qp[j] = [[p[i][j]] + [secrets.randbelow(r) for _ in range(t - 1)] for i in range(G)]
        for k in range(n):
            salt[(j, k)] = secrets.token_bytes(32)
            vec = [ev(Qp[j][i], X[k]) for i in range(G)]
            if b == 'bad_sub' and k == honest_recv[0]:
                vec[0] = (vec[0] + 1) % r                         # inconsistent, digest matches
                digest[(j, k)] = D(j, k, vec)
            elif b in ('digest_mismatch', 'refuse_open') and k == honest_recv[0]:
                digest[(j, k)] = D(j, k, vec)
                vec = vec[:]
                vec[0] = (vec[0] + 1) % r                         # delivered vector != digest
            else:
                digest[(j, k)] = D(j, k, vec)
            sent[(j, k)] = vec
    disq_d, disq_r, log = set(), set(), []
    # ---- Round 2 complaints on digest mismatch (answer deadline D2) ----
    for (j, k), vec in list(sent.items()):
        if k in bad_receivers or D(j, k, vec) == digest[(j, k)]:
            continue
        if bad_dealers.get(j) == 'refuse_open':
            disq_d.add(j)
            log.append(f'dealer {j} did not answer digest complaint of {k}: disqualified')
        else:                                                     # publishes the true vector
            true = [ev(Qp[j][i], X[k]) for i in range(G)]
            if D(j, k, true) == digest[(j, k)]:
                sent[(j, k)] = true
            else:
                disq_d.add(j)
    # corrupted receiver that complains falsely about a matching vector. Only public
    # evidence decides: the honest dealer publishes a vector that matches its digest, so
    # the dealer stays qualified and the receiver uses the published vector (Algorithm 1,
    # round 2). Nobody can tell whether the private delivery failed, so the receiver is
    # not disqualified either.
    for k, b in bad_receivers.items():
        if b == 'false_digest_complaint':
            j = 0
            opened = [ev(Qp[j][i], X[k]) for i in range(G)]   # published answer
            if D(j, k, opened) == digest[(j, k)]:
                sent[(j, k)] = opened
                log.append(f'receiver {k} complained against dealer {j}; the published vector matches its digest: dealer kept, receiver uses it')
            else:
                disq_d.add(j)
    attempts = 0
    while True:
        attempts += 1
        assert attempts <= t, 'more than t attempts'
        eligible = [j for j in range(n) if j in Qp and j not in disq_d]
        assert len(eligible) >= t, 'fewer than t qualified dealers'
        Q = eligible[:t]
        lam = lagr([X[j] for j in Q])
        newp, Vn = {}, {}
        for k in range(n):
            if k in disq_r:
                continue
            newp[k] = [sum(lam[a] * sent[(j, k)][i] for a, j in enumerate(Q)) % r for i in range(G)]
            b = bad_receivers.get(k)
            if b == 'withhold_V':
                continue                                          # misses D2: no V' on ledger
            Vn[k] = newp[k][:]
            if b == 'wrong_V':
                Vn[k][0] = (Vn[k][0] + 5) % r
        for k in range(n):
            if k not in disq_r and k not in Vn:
                disq_r.add(k)
                log.append(f'receiver {k} posted no share keys by the deadline: disqualified')
        # ---- Availability: hash h'_k is on the ledger, vector is gossiped ----
        complained = {k for k in Vn if bad_receivers.get(k) in ('withhold_vec_refuse', 'withhold_vec_publish')}
        if any(b == 'false_avail_complaint' for b in bad_receivers.values()):
            complained |= {k for k in Vn if k not in bad_receivers}  # honest receivers must publish
        for k in sorted(complained):
            if bad_receivers.get(k) == 'withhold_vec_refuse':
                del Vn[k]
                disq_r.add(k)
                log.append(f'receiver {k} withheld its share-key vector after an availability complaint: disqualified')
            else:
                log.append(f'receiver {k} published its share-key vector on the ledger after an availability complaint')
        # ---- Round 3: beacon ----
        rho = secrets.randbelow(r)
        rp = [pow(rho, i + 1, r) for i in range(G)]
        # ---- Round 4: commitments of Q (deadline D4) ----
        F = {}
        for j in Q:
            b = bad_dealers.get(j)
            if b == 'withhold_F':
                continue
            F[j] = [sum(rp[i] * Qp[j][i][l] for i in range(G)) % r for l in range(t)]
            if b == 'bad_F':
                F[j][0] = (F[j][0] + 7) % r
        missing = [j for j in Q if j not in F]
        if missing:
            for j in missing:
                disq_d.add(j)
                log.append(f'attempt {attempts}: dealer {j} posted no commitment by the deadline: disqualified, restart')
            continue
        # ---- Round 5: tau from all commitments ----
        tau = {j: H(rho, tuple(tuple(F[x]) for x in Q), j) for j in Q}
        # ---- Round 6: aggregate checks ----
        Fx = lambda j, x: ev(F[j], x)
        ca = sum(tau[j] * (sum(rp[i] * V[i][j] for i in range(G)) - F[j][0]) for j in Q) % r == 0
        cb = {k: sum(tau[j] * (sum(rp[i] * sent[(j, k)][i] for i in range(G)) - Fx(j, X[k])) for j in Q) % r == 0
              for k in Vn}
        cc = {k: (sum(rp[i] * Vn[k][i] for i in range(G)) - sum(lam[a] * Fx(j, X[k]) for a, j in enumerate(Q))) % r == 0
              for k in Vn}
        for k, b in bad_receivers.items():
            if b == 'false_b_complaint' and k in cb:
                cb[k] = False                                     # claims (b) failed
        if ca and all(cb.values()) and all(cc.values()):
            break
        # ---- Round 7: attribution ----
        new_dq = set()
        for j in Q:
            if (sum(rp[i] * V[i][j] for i in range(G)) - F[j][0]) % r:
                new_dq.add(j)
                log.append(f'attempt {attempts}: dealer {j} fails (a_j): disqualified')
        for k in Vn:
            for j in Q:
                ok = (sum(rp[i] * sent[(j, k)][i] for i in range(G)) - Fx(j, X[k])) % r == 0
                claims = (not ok) or (bad_receivers.get(k) == 'false_b_complaint' and j == Q[0])
                if not claims:
                    continue
                opened = sent[(j, k)]                             # opening of s_jk
                if D(j, k, opened) != digest[(j, k)] or ok:
                    disq_r.add(k)
                    log.append(f'attempt {attempts}: receiver {k} complained against {j} but the opening passes (b_jk): receiver disqualified')
                else:
                    new_dq.add(j)
                    log.append(f'attempt {attempts}: dealer {j} fails (b_jk) on an opening that matches its digest: disqualified')
        if new_dq:
            disq_d |= new_dq
            continue
        for k, ok in cc.items():
            if not ok:
                disq_r.add(k)
                log.append(f'attempt {attempts}: all dealers pass, receiver {k} fails (c): disqualified')
        break
    good = [k for k in range(n) if k not in disq_r]
    rec = good[:t]
    lr = lagr([X[k] for k in rec])
    correct = all(sum(lr[a] * newp[k][i] for a, k in enumerate(rec)) % r == S[i] for i in range(G))
    honest_dq = (disq_d - set(bad_dealers)) | (disq_r - set(bad_receivers))
    return dict(attempts=attempts, disq_dealers=sorted(disq_d), disq_receivers=sorted(disq_r),
                honest_disqualified=sorted(honest_dq), correct=correct, log=log)


SCEN = [
    ('dealer in Q withholds F', {2: 'withhold_F'}, {}),
    ('dealer in Q posts a wrong constant term', {1: 'bad_F'}, {}),
    ('dealer sends an inconsistent sub-share (digest matches)', {0: 'bad_sub'}, {}),
    ('dealer refuses to answer a digest complaint', {3: 'refuse_open'}, {}),
    ('dealer posts no digest', {0: 'no_digest'}, {}),
    ('receiver withholds its new share keys', {}, {-1: 'withhold_V'}),
    ('receiver posts wrong share keys', {}, {-2: 'wrong_V'}),
    ('receiver posts the hash but withholds its share-key vector', {}, {-1: 'withhold_vec_refuse'}),
    ('receiver withholds its vector until an availability complaint', {}, {-1: 'withhold_vec_publish'}),
    ('false availability complaints against honest receivers', {}, {-1: 'false_avail_complaint'}),
    ('false digest complaint against an honest dealer', {}, {-1: 'false_digest_complaint'}),
    ('false (b) complaint against an honest dealer', {}, {-1: 'false_b_complaint'}),
]


def chain(t):
    kinds = ['withhold_F', 'bad_F', 'bad_sub', 'refuse_open', 'withhold_F', 'bad_F', 'bad_sub']
    return {j: kinds[j % len(kinds)] for j in range(t - 1)}


def run_scenarios(configs, gamma):
    """Run every scenario for each (n, t) in configs; return one record per run."""
    out = []
    for (n, t) in configs:
        for name, bd, br in SCEN + [(f"{t-1} faulty dealers in Q, mixed faults", chain(t), {})]:
            bd = {j: b for j, b in bd.items() if j < n}
            br = {k % n: b for k, b in br.items()}
            res = handoff(n, t, gamma, bd, br)
            out.append({"n": n, "t": t, "gamma": gamma, "scenario": name,
                        "attempts": res["attempts"], "disqualified_dealers": res["disq_dealers"],
                        "disqualified_receivers": res["disq_receivers"],
                        "honest_disqualified": res["honest_disqualified"],
                        "secrets_correct": res["correct"],
                        "ok": res["correct"] and not res["honest_disqualified"]})
    return out
