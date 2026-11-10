"""Timing of the aggregation weights tau (Remark 1) and the share keys of a rejected
dealing used in the proof of Theorem 1. Discrete-log representation of group elements.
"""
from .field import R, evaluate, hash_to_field, interpolate_at0, lagrange_coeffs, rand, random_poly


def _setup(n, t, gamma):
    xs = list(range(1, n + 1))
    xs_new = list(range(101, 101 + n))
    polys = [random_poly(rand(), t - 1) for _ in range(gamma)]
    s = [p[0] for p in polys]
    p = [[evaluate(polys[i], xs[j]) for j in range(n)] for i in range(gamma)]
    return xs, xs_new, s, p


def _checks(n, t, gamma, xs, xs_new, s, p, sub, f, tau, rho_pows, q_set, lam):
    """Aggregate checks (a), (b) at every receiver, (c) at every receiver; correctness."""
    new_p = {k: [sum(lam[a] * evaluate(sub[j][i], xs_new[k]) for a, j in enumerate(q_set)) % R
                 for i in range(gamma)] for k in range(n)}
    ca = sum(tau[j] * (f[j][0] - sum(rho_pows[i] * p[i][j] for i in range(gamma)))
             for j in q_set) % R == 0
    cb = all(sum(tau[j] * (sum(rho_pows[i] * evaluate(sub[j][i], xs_new[k]) for i in range(gamma))
                           - evaluate(f[j], xs_new[k])) for j in q_set) % R == 0 for k in range(n))
    cc = all((sum(rho_pows[i] * new_p[k][i] for i in range(gamma))
              - sum(lam[a] * evaluate(f[j], xs_new[k]) for a, j in enumerate(q_set))) % R == 0
             for k in range(n))
    lag = lagrange_coeffs(xs_new[:t])
    rec = [sum(lag[a] * new_p[k][i] for a, k in enumerate(range(t))) % R for i in range(gamma)]
    per_dealer_a_fail = [j for j in q_set
                         if (f[j][0] - sum(rho_pows[i] * p[i][j] for i in range(gamma))) % R]
    return {"check_a_pass": ca, "check_b_pass_all": cb, "check_c_pass_all": cc,
            "secrets_correct": rec == s, "dealers_failing_a_j": per_dealer_a_fail}


def shift_attack(n, t, gamma, weights):
    """Two dealers a, b of Q shift their constant terms by delta and -(tau_a/tau_b) delta.

    weights = 'fixed'    : tau_j = H(j), known before dealing (attack succeeds).
    weights = 'after_F'  : tau_j = H(rho, all F, j), as in Algorithm 1 (attack caught).
    """
    xs, xs_new, s, p = _setup(n, t, gamma)
    q_set = list(range(t))
    lam = lagrange_coeffs([xs[j] for j in q_set])
    fixed_tau = {j: hash_to_field("fixed", j) for j in q_set}
    delta = [rand() for _ in range(gamma)]
    a, b = 0, 1
    ratio = fixed_tau[a] * pow(fixed_tau[b], -1, R) % R
    sub = {}
    for j in q_set:
        const = [p[i][j] for i in range(gamma)]
        if j == a:
            const = [(const[i] + delta[i]) % R for i in range(gamma)]
        if j == b:
            const = [(const[i] - ratio * delta[i]) % R for i in range(gamma)]
        sub[j] = [random_poly(const[i], t - 1) for i in range(gamma)]
    rho = rand()
    rho_pows = [pow(rho, i + 1, R) for i in range(gamma)]
    f = {j: [sum(rho_pows[i] * sub[j][i][l] for i in range(gamma)) % R for l in range(t)]
         for j in q_set}                                  # honest commitments to the dealt polys
    if weights == "fixed":
        tau = fixed_tau
    else:
        tau = {j: hash_to_field(rho, tuple(tuple(f[x]) for x in q_set), j) for j in q_set}
    out = _checks(n, t, gamma, xs, xs_new, s, p, sub, f, tau, rho_pows, q_set, lam)
    out.update({"n": n, "t": t, "gamma": gamma, "weights": weights,
                "undetected_shift": out["check_a_pass"] and out["check_b_pass_all"]
                and out["check_c_pass_all"] and not out["secrets_correct"]})
    return out


def cancellation_attack(n, t, gamma, weights):
    """Two dealers shift committed constant terms so that the errors cancel in (a), (b).

    weights = 'rho_only' : tau_j = H(rho, j), known before the commitments.
    weights = 'after_F'  : tau_j = H(rho, all F, j), as in Algorithm 1.
    """
    xs, xs_new, s, p = _setup(n, t, gamma)
    q_set = list(range(t))
    lam = lagrange_coeffs([xs[j] for j in q_set])
    sub = {j: [random_poly(p[i][j], t - 1) for i in range(gamma)] for j in q_set}
    rho = rand()
    rho_pows = [pow(rho, i + 1, R) for i in range(gamma)]
    f = {j: [sum(rho_pows[i] * sub[j][i][l] for i in range(gamma)) % R for l in range(t)]
         for j in q_set}
    a, b = 0, 1
    early = {j: hash_to_field(rho, j) for j in q_set}
    d_a = rand()
    d_b = (-early[a] * d_a * pow(early[b], -1, R)) % R
    f[a][0] = (f[a][0] + d_a) % R
    f[b][0] = (f[b][0] + d_b) % R
    tau = early if weights == "rho_only" else \
        {j: hash_to_field(rho, tuple(tuple(f[x]) for x in q_set), j) for j in q_set}
    out = _checks(n, t, gamma, xs, xs_new, s, p, sub, f, tau, rho_pows, q_set, lam)
    out.update({"n": n, "t": t, "gamma": gamma, "weights": weights})
    return out


def rejected_dealing_share_keys(n, t, delta=5):
    """A dealer of Q dealing p_ia + delta makes honest new share keys interpolate to
    pk_i g^{lambda_a delta}; the simulator of Theorem 1 must reproduce this."""
    xs, xs_new, s, p = _setup(n, t, 1)
    q_set = list(range(t))
    lam = lagrange_coeffs([xs[j] for j in q_set])
    sub = {j: random_poly(p[0][j] + (delta if j == 0 else 0), t - 1) for j in q_set}
    new_p = {k: sum(lam[a] * evaluate(sub[j], xs_new[k]) for a, j in enumerate(q_set)) % R
             for k in range(n)}
    value = interpolate_at0([(xs_new[k], new_p[k]) for k in range(n - t, n)])
    return {"n": n, "t": t, "delta": delta,
            "keys_interpolate_to_shifted_secret": value == (s[0] + lam[0] * delta) % R,
            "keys_differ_from_pk": value != s[0]}
