"""Arithmetic over the BLS12-381 scalar field shared by all simulations.

Group elements are represented by their discrete logarithms wherever a check is
linear in the exponent, which is the case for every algebraic check simulated here.
"""
import hashlib
import secrets

# Order of the BLS12-381 groups (scalar field modulus).
R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


def rand():
    """Uniform field element."""
    return secrets.randbelow(R)


def evaluate(coeffs, x):
    """Horner evaluation of sum_l coeffs[l] x^l mod R."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % R
    return acc


def lagrange_coeffs(xs, z=0):
    """Lagrange coefficients lambda_u(z) for the points xs."""
    out = []
    for i, xi in enumerate(xs):
        num = den = 1
        for j, xj in enumerate(xs):
            if i != j:
                num = num * (z - xj) % R
                den = den * (xi - xj) % R
        out.append(num * pow(den, -1, R) % R)
    return out


def interpolate_at0(points):
    """Value at 0 of the polynomial through [(x, y), ...]."""
    lam = lagrange_coeffs([x for x, _ in points])
    return sum(l * y for l, (_, y) in zip(lam, points)) % R


def random_poly(constant, degree):
    """Polynomial with the given constant term and uniform higher coefficients."""
    return [constant] + [rand() for _ in range(degree)]


def hash_to_field(*items):
    """Random-oracle stand-in: SHA-256 of the repr, reduced mod R."""
    return int.from_bytes(hashlib.sha256(repr(items).encode()).digest(), "big") % R
