//! Baseline: per-secret verifiable resharing (Feldman commitments for every Q_ij,
//! as in HJKY95/CHURP-style resharing without batching). Same dealer policy and the
//! same timing boundaries as Algorithm 1 in src/main.rs:
//!   dealer   = sub-shares for all n receivers + n salted digests + Gamma(t-1) commitments
//!   receiver = check of the n received vectors against their digests
//!            + one random-weight (small-exponent) multi-exponentiation of size t^2*Gamma
//!              over all t dealings of Q
//!            + the new shares p'_k = sum_j lambda_j Q_ij(x'_k), their share keys V'_k
//!              and the hash of the compressed V'_k.
//! Only the t dealers of Q are simulated; the n-t other dealers' vectors (which the
//! receiver also checks against digests) are generated outside the timing.
//! Variant (review r6): new share keys need not be published, since anyone can derive
//! V'_ik = prod_{j in Q} (V_ij prod_l A_ijl^{x'^l})^{lambda_j}; derive_member_ms is the
//! time for one incoming member to derive its Gamma keys (Gamma multi-exps of size t^2),
//! bcast_bytes_derived the public data without V'. derive_agg_*: the same keys with the
//! coefficient aggregation C_il = prod_j A_ijl^{lambda_j} computed once (reusable for all
//! members) and then one multi-exp of size t per member.
//! Prints per-member time and serialized byte counts.
//! Usage: baseline <N> <t> <Gamma>

use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

fn eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

fn salted_digest(salt: &[u8; 32], v: &[Scalar]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(salt);
    for s in v {
        h.update(s.to_bytes_le());
    }
    h.finalize().to_vec()
}

fn lagrange_at0(xs: &[Scalar]) -> Vec<Scalar> {
    xs.iter()
        .enumerate()
        .map(|(i, xi)| {
            let (mut num, mut den) = (Scalar::ONE, Scalar::ONE);
            for (j, xj) in xs.iter().enumerate() {
                if i != j {
                    num *= -*xj;
                    den *= *xi - xj;
                }
            }
            num * den.invert().unwrap()
        })
        .collect()
}

struct FixedBase {
    table: Vec<Vec<G1Projective>>,
}
impl FixedBase {
    fn new(g: G1Projective) -> Self {
        let mut table = Vec::with_capacity(32);
        let mut base = g;
        for _ in 0..32 {
            let mut row = Vec::with_capacity(256);
            let mut acc = G1Projective::identity();
            for _ in 0..256 {
                row.push(acc);
                acc += base;
            }
            table.push(row);
            base = acc;
        }
        FixedBase { table }
    }
    fn mul(&self, s: &Scalar) -> G1Projective {
        let b = s.to_bytes_le();
        let mut acc = G1Projective::identity();
        for (w, byte) in b.iter().enumerate() {
            if *byte != 0 {
                acc += self.table[w][*byte as usize];
            }
        }
        acc
    }
}

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().unwrap()).collect();
    let (n, t, gamma) = (args[0], args[1], args[2]);
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let g = G1Projective::generator();
    let fb = FixedBase::new(g);
    let k_idx = 0usize; // receiver k = 1 (receivers are symmetric)
    let xk = Scalar::from(1u64);
    let xs: Vec<Scalar> = (1..=t as u64).map(Scalar::from).collect(); // dealers of Q
    let lam = lagrange_at0(&xs);

    let mut deal_max = Duration::ZERO;
    let mut bcast_bytes = 0usize;
    let mut all_vk: Vec<Vec<G1Projective>> = Vec::with_capacity(t);
    let mut all_com: Vec<Vec<G1Projective>> = Vec::with_capacity(t);
    // what receiver k holds from each dealer: (salt, vector, digest)
    let mut inbox: Vec<([u8; 32], Vec<Scalar>, Vec<u8>)> = Vec::with_capacity(n);
    for _j in 0..t {
        // old share p_ij and its share key V_ij (public from the previous epoch)
        let shares: Vec<Scalar> = (0..gamma).map(|_| Scalar::random(&mut rng)).collect();
        let vk: Vec<G1Projective> = shares.iter().map(|s| fb.mul(s)).collect();
        // ---- dealer ----
        let st = Instant::now();
        let mut com: Vec<G1Projective> = Vec::with_capacity(gamma * (t - 1));
        let mut sub = vec![vec![Scalar::ZERO; gamma]; n];
        for i in 0..gamma {
            let mut q = vec![shares[i]];
            q.extend((1..t).map(|_| Scalar::random(&mut rng)));
            for k in 0..n {
                sub[k][i] = eval(&q, Scalar::from(k as u64 + 1));
            }
            for l in 1..t {
                com.push(fb.mul(&q[l]));
            }
        }
        let salts: Vec<[u8; 32]> = (0..n).map(|_| { let mut b = [0u8; 32]; rng.fill_bytes(&mut b); b }).collect();
        let dg: Vec<Vec<u8>> = (0..n).map(|k| salted_digest(&salts[k], &sub[k])).collect();
        deal_max = deal_max.max(st.elapsed());
        bcast_bytes += com.iter().map(|c| c.to_compressed().len()).sum::<usize>();
        inbox.push((salts[k_idx], sub.swap_remove(k_idx), dg[k_idx].clone()));
        all_vk.push(vk);
        all_com.push(com);
    }
    // vectors of the n-t dealers outside Q (generated outside the timing)
    for _ in t..n {
        let v: Vec<Scalar> = (0..gamma).map(|_| Scalar::random(&mut rng)).collect();
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let d = salted_digest(&salt, &v);
        inbox.push((salt, v, d));
    }
    // weights of the small-exponent test (derived from a hash in practice)
    let w: Vec<Vec<Scalar>> = (0..t).map(|_| (0..gamma).map(|_| Scalar::random(&mut rng)).collect()).collect();

    // ---- receiver k ----
    let st = Instant::now();
    let digests_ok = inbox.iter().all(|(s, v, d)| salted_digest(s, v) == *d);
    let mut lhs = Scalar::ZERO;
    let mut pts = Vec::with_capacity(t * t * gamma);
    let mut scs = Vec::with_capacity(t * t * gamma);
    for j in 0..t {
        let sub_k = &inbox[j].1;
        for i in 0..gamma {
            lhs += w[j][i] * sub_k[i];
            pts.push(all_vk[j][i]);
            scs.push(w[j][i]);
            let mut xp = xk;
            for l in 1..t {
                pts.push(all_com[j][i * (t - 1) + l - 1]);
                scs.push(w[j][i] * xp);
                xp *= xk;
            }
        }
    }
    let ok = fb.mul(&lhs) == G1Projective::multi_exp(&pts, &scs);
    drop(pts);
    drop(scs);
    let mut newp = vec![Scalar::ZERO; gamma];
    for j in 0..t {
        for i in 0..gamma {
            newp[i] += lam[j] * inbox[j].1[i];
        }
    }
    let newv: Vec<G1Projective> = newp.iter().map(|s| fb.mul(s)).collect();
    let mut h = Sha256::new();
    for p in &newv {
        h.update(p.to_compressed());
    }
    std::hint::black_box(h.finalize());
    let recv = st.elapsed();

    // ---- derived-key variant: one incoming member derives its Gamma share keys ----
    let st = Instant::now();
    let mut xpow = vec![Scalar::ONE; t];
    for l in 1..t {
        xpow[l] = xpow[l - 1] * xk;
    }
    let mut derived = Vec::with_capacity(gamma);
    for i in 0..gamma {
        let mut pts = Vec::with_capacity(t * t);
        let mut scs = Vec::with_capacity(t * t);
        for j in 0..t {
            pts.push(all_vk[j][i]);
            scs.push(lam[j]);
            for l in 1..t {
                pts.push(all_com[j][i * (t - 1) + l - 1]);
                scs.push(lam[j] * xpow[l]);
            }
        }
        derived.push(G1Projective::multi_exp(&pts, &scs));
    }
    let derive = st.elapsed();
    let derive_matches_newv = derived == newv;
    // ---- reused coefficient aggregation: C_il = prod_j A_ijl^{lambda_j} once per i,
    //      then each member's key V'_ik = prod_l C_il^{x'^l} (multi-exp of size t) ----
    let st = Instant::now();
    let mut agg: Vec<Vec<G1Projective>> = Vec::with_capacity(gamma);
    for i in 0..gamma {
        let mut c = Vec::with_capacity(t);
        for l in 0..t {
            let pts: Vec<G1Projective> = (0..t)
                .map(|j| if l == 0 { all_vk[j][i] } else { all_com[j][i * (t - 1) + l - 1] })
                .collect();
            c.push(G1Projective::multi_exp(&pts, &lam));
        }
        agg.push(c);
    }
    let agg_setup = st.elapsed();
    let st = Instant::now();
    let derived_agg: Vec<G1Projective> = agg.iter().map(|c| G1Projective::multi_exp(c, &xpow)).collect();
    let agg_member = st.elapsed();
    let agg_ok = derived_agg == derived;
    let bcast_derived = bcast_bytes + n * n * 32; // commitments + digests
    let p2p_bytes = n * (gamma * 32 + 32); // every old member sends Gamma sub-shares and a salt
    bcast_bytes = bcast_derived + n * gamma * 48 + n * 32; // + new share keys V' and their hashes
    println!(
        "{{\"scheme\":\"per-secret\",\"N\":{n},\"t\":{t},\"Gamma\":{gamma},\"deal_member_ms\":{:.1},\"recv_member_ms\":{:.1},\"p2p_bytes_per_receiver\":{},\"bcast_bytes_total\":{},\"bcast_bytes_derived\":{},\"derive_member_ms\":{:.1},\"derive_agg_setup_ms\":{:.1},\"derive_agg_member_ms\":{:.1},\"derive_agg_matches\":{agg_ok},\"derive_matches_newv\":{derive_matches_newv},\"digests_ok\":{digests_ok},\"ok\":{ok}}}",
        deal_max.as_secs_f64() * 1e3,
        recv.as_secs_f64() * 1e3,
        p2p_bytes,
        bcast_bytes,
        bcast_derived,
        derive.as_secs_f64() * 1e3,
        agg_setup.as_secs_f64() * 1e3,
        agg_member.as_secs_f64() * 1e3
    );
}
