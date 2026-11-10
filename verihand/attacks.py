"""Attacks on DP-DID (Yin et al., IEEE TIFS 2025), simulated as specified.

A1  Revocation witness forgery in a known-order group (Proposition 1).
A2  Cross-epoch share combination (Proposition 2).
Q3  Unverified refresh polynomial (Proposition 3).
A3  Wrong DKG public key (Algorithm 1, line 19).
Each function returns a dict of parameters and outcomes for results.json.
"""
import secrets

from .field import R, evaluate, interpolate_at0, rand, random_poly

# 1024-bit safe prime q = 2p + 1 (RFC 2409 Oakley group 2); the order-p subgroup
# stands in for DP-DID's group G, since attack A1 only uses the public order p.
SCHNORR_Q = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16)
SCHNORR_P = (SCHNORR_Q - 1) // 2
SCHNORR_G = 4


def attack_a1(num_revoked):
    """Forge a DP-DID non-membership witness (a, B) for a revoked element."""
    q, p, g = SCHNORR_Q, SCHNORR_P, SCHNORR_G
    revoked = [secrets.randbelow(p - 2) + 2 for _ in range(num_revoked)]
    y = 1
    for x in revoked:
        y = y * x % p
    delta = pow(g, y, q)
    x_star = revoked[0]
    a = secrets.randbelow(p)
    target = g * pow(delta, -a % p, q) % q              # need B^{x*} = g * Delta^{-a}
    b_val = pow(target, pow(x_star, -1, p), q)
    accepted = pow(delta, a, q) * pow(b_val, x_star, q) % q == g   # Algorithm 3 check
    return {"group_bits": q.bit_length(), "num_revoked": num_revoked,
            "forged_witness_accepted": accepted}


def _share_all(secrets_, n, t):
    xs = list(range(1, n + 1))
    polys = [random_poly(s, t - 1) for s in secrets_]
    return [[evaluate(poly, x) for x in xs] for poly in polys]


def _offline(n, t, gamma, tamper=None):
    """DBPSS Offline: member j samples B^(j) (first column zero), z^(j) = B^(j) X^T."""
    xs = list(range(1, n + 1))
    zs = []
    for j in range(n):
        b_mat = [[0] + [rand() for _ in range(t - 1)] for _ in range(gamma)]
        if tamper is not None and tamper[0] == j:
            tamper[1](b_mat)
        zs.append([[evaluate(row, x) for x in xs] for row in b_mat])
    return zs


def _handoff(p, zs, n, gamma):
    """DP-DID Eq. (4): p'_k = p_k + sum_j z^(j)_k (nothing is erased)."""
    return [[(p[i][k] + sum(zs[j][i][k] for j in range(n))) % R for k in range(n)]
            for i in range(gamma)]


def attack_a2(n, t, gamma):
    """t-1 corruptions in epoch e-1 plus one joining member in epoch e."""
    xs = list(range(1, n + 1))
    s = [rand() for _ in range(gamma)]
    p = _share_all(s, n, t)
    stolen = {k: [p[i][k] for i in range(gamma)] for k in range(t - 1)}
    zs = _offline(n, t, gamma)
    p_new = _handoff(p, zs, n, gamma)
    k = t - 1                                           # corrupted joining member
    # Its state holds p_old, or p_new and the update columns, which determine p_old.
    stolen[k] = [(p_new[i][k] - sum(zs[j][i][k] for j in range(n))) % R for i in range(gamma)]
    recovered = sum(
        interpolate_at0([(xs[kk], stolen[kk][i]) for kk in sorted(stolen)]) == s[i]
        for i in range(gamma))
    return {"n": n, "t": t, "gamma": gamma, "corrupted_epoch_e_minus_1": t - 1,
            "corrupted_epoch_e": 1, "secrets_recovered": recovered,
            "all_recovered": recovered == gamma}


def attack_q3(n, t, gamma):
    """(i) nonzero refresh constant shifts every secret; (ii) inconsistent column."""
    xs = list(range(1, n + 1))
    s = [rand() for _ in range(gamma)]
    p = _share_all(s, n, t)
    delta = [rand() for _ in range(gamma)]

    def nonzero_const(b_mat):
        for i in range(gamma):
            b_mat[i][0] = delta[i]

    p1 = _handoff(p, _offline(n, t, gamma, (0, nonzero_const)), n, gamma)
    shifted = all(interpolate_at0([(xs[k], p1[i][k]) for k in range(t)]) == (s[i] + delta[i]) % R
                  for i in range(gamma))
    zs = _offline(n, t, gamma)
    zs[0][0][0] = (zs[0][0][0] + 1) % R
    p2 = _handoff(p, zs, n, gamma)
    with_k = interpolate_at0([(xs[k], p2[0][k]) for k in range(0, t)])
    without_k = interpolate_at0([(xs[k], p2[0][k]) for k in range(1, t + 1)])
    return {"n": n, "t": t, "gamma": gamma, "q3i_all_secrets_shifted": shifted,
            "q3ii_subsets_disagree": with_k != without_k}


def attack_a3(n, t):
    """Combined BLS signature vs. DP-DID's pk_C = prod g^{sk_j} (in the exponent)."""
    xs = list(range(1, n + 1))
    s1 = list(range(t))
    deals = {i: random_poly(rand(), t - 1) for i in s1}
    s = sum(deals[i][0] for i in s1) % R
    sk = {j: sum(evaluate(deals[i], xs[j]) for i in s1) % R for j in range(n)}
    log_pk_paper = sum(sk[j] for j in s1) % R
    log_sig = interpolate_at0([(xs[j], sk[j]) for j in range(t)])
    return {"n": n, "t": t, "verifies_under_paper_pkC": log_sig == log_pk_paper,
            "verifies_under_correct_pkC": log_sig == s}
