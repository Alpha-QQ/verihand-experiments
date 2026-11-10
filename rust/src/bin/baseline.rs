//! Baseline: per-secret verifiable resharing (Feldman commitments for every Q_ij,
//! as in HJKY95/CHURP-style resharing without batching). Same dealer policy as
//! Algorithm 1: all n dealers send sub-shares, the t dealers in Q commit and are
//! checked. Receivers batch-verify the t*Gamma dealings with random weights (BGR98
//! small-exponent test), so this is the strongest unbatched-commitment baseline.
//! Run single-threaded, dealer by dealer. Broadcast = commitments + new share keys.
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
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

fn eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
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
    let xk = Scalar::from(1u64); // receiver k = 1 (receivers are symmetric)

    let mut deal_max = Duration::ZERO;
    let mut recv = Duration::ZERO;
    let mut lhs = Scalar::ZERO;
    let mut rhs = G1Projective::identity();
    let mut p2p_bytes = 0usize;
    let mut bcast_bytes = 0usize;
    let mut all_vk: Vec<Vec<G1Projective>> = Vec::with_capacity(t);
    let mut all_com: Vec<Vec<G1Projective>> = Vec::with_capacity(t);
    for _j in 0..t {
        // old share p_ij and its share key V_ij (public from the previous epoch)
        let shares: Vec<Scalar> = (0..gamma).map(|_| Scalar::random(&mut rng)).collect();
        let vk: Vec<G1Projective> = shares.iter().map(|s| fb.mul(s)).collect();
        // ---- dealer ----
        let st = Instant::now();
        let mut com: Vec<G1Projective> = Vec::with_capacity(gamma * (t - 1));
        let mut sub_k = Vec::with_capacity(gamma);
        let mut sub_all = vec![Scalar::ZERO; gamma];
        for i in 0..gamma {
            let mut q = vec![shares[i]];
            q.extend((1..t).map(|_| Scalar::random(&mut rng)));
            for k in 1..=n as u64 {
                let v = eval(&q, Scalar::from(k));
                if k == 1 {
                    sub_k.push(v);
                }
                sub_all[i] = v;
            }
            for l in 1..t {
                com.push(fb.mul(&q[l]));
            }
        }
        std::hint::black_box(&sub_all);
        deal_max = deal_max.max(st.elapsed());
        bcast_bytes += com.iter().map(|c| c.to_compressed().len()).sum::<usize>();
        // ---- receiver k: random-weight batch check of this dealer's Gamma sub-shares ----
        let st = Instant::now();
        let w: Vec<Scalar> = (0..gamma).map(|_| Scalar::random(&mut rng)).collect();
        let mut pts = Vec::with_capacity(gamma * t);
        let mut scs = Vec::with_capacity(gamma * t);
        for i in 0..gamma {
            lhs += w[i] * sub_k[i];
            pts.push(vk[i]);
            scs.push(w[i]);
            let mut xp = xk;
            for l in 1..t {
                pts.push(com[i * (t - 1) + l - 1]);
                scs.push(w[i] * xp);
                xp *= xk;
            }
        }
        rhs += G1Projective::multi_exp(&pts, &scs);
        recv += st.elapsed();
        all_vk.push(vk);
        all_com.push(com);
    }
    // ---- derived-key variant: one incoming member derives its Gamma share keys ----
    let lam: Vec<Scalar> = (0..t).map(|_| Scalar::random(&mut rng)).collect();
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
    std::hint::black_box(&derived);
    let derive = st.elapsed();
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
    let bcast_derived = bcast_bytes;
    p2p_bytes += n * gamma * 32; // every old member sends Gamma sub-shares
    bcast_bytes += n * gamma * 48; // new share keys V' (as in VeriHand)
    // final comparison + new share keys (Gamma fixed-base exps, same as DP-DID+)
    let st = Instant::now();
    let ok = fb.mul(&lhs) == rhs;
    let newp: Vec<Scalar> = (0..gamma).map(|_| Scalar::random(&mut rng)).collect();
    let newv: Vec<G1Projective> = newp.iter().map(|s| fb.mul(s)).collect();
    std::hint::black_box(&newv);
    recv += st.elapsed();
    println!(
        "{{\"scheme\":\"per-secret\",\"N\":{n},\"t\":{t},\"Gamma\":{gamma},\"deal_member_ms\":{:.1},\"recv_member_ms\":{:.1},\"p2p_bytes_per_receiver\":{},\"bcast_bytes_total\":{},\"bcast_bytes_derived\":{},\"derive_member_ms\":{:.1},\"derive_agg_setup_ms\":{:.1},\"derive_agg_member_ms\":{:.1},\"derive_agg_matches\":{agg_ok},\"ok\":{ok}}}",
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
