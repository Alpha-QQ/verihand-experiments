//! VeriHand prototype: verifiable batched resharing (Algorithm 1) vs. the original DP-DID DBPSS.
//!
//! DBPSS+ state per epoch: member k holds shares p_ik (i in [Gamma]); public share
//! verification keys V_ik = g^{p_ik} and user keys pk_i = g^{S_i}.
//! Handoff (resharing): old member j deals Q_ij with Q_ij(0) = p_ij to every new
//! member; one global challenge rho (beacon after dealings are committed) lets each
//! dealer publish a Feldman commitment to F_j = sum_i rho^i Q_ij only (t points).
//!   public check   g^{F_j(0)} == prod_i V_ij^{rho^i}            (constant terms)
//!   receiver k     g^{sum_i rho^i Q_ij(x'_k)} == F_j(x'_k)       (degree / consistency)
//!   new key check  prod_i V'_ik^{rho^i} == prod_j F_j(x'_k)^{lambda_j}
//! Usage: dpdid_plus <N> <t> <Gamma> [threads]

use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

// ---------- field helpers ----------
fn sc(x: u64) -> Scalar {
    Scalar::from(x)
}

fn eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
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

fn hash_to_scalar(chunks: &[&[u8]]) -> Scalar {
    let mut h = Sha256::new();
    for c in chunks {
        h.update(c);
    }
    let d = h.finalize();
    let mut l = [0u64; 4];
    for i in 0..4 {
        l[i] = u64::from_le_bytes(d[8 * i..8 * i + 8].try_into().unwrap());
    }
    l[3] &= 0x0fff_ffff_ffff_ffff; // < r
    Scalar::from_u64s_le(&l).unwrap()
}

/// Salted digest h_jk = H(r_jk || s_jk) of one sub-share vector (Algorithm 1, step 1).
fn salted_digest(salt: &[u8; 32], v: &[Scalar]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(salt);
    for s in v {
        h.update(s.to_bytes_le());
    }
    h.finalize().to_vec()
}

fn powers(rho: Scalar, n: usize) -> Vec<Scalar> {
    let mut v = Vec::with_capacity(n);
    let mut p = rho;
    for _ in 0..n {
        v.push(p);
        p *= rho;
    }
    v
}

// ---------- fixed-base exponentiation for g (8-bit windows) ----------
struct FixedBase {
    table: Vec<Vec<G1Projective>>, // table[w][d] = d * 256^w * g
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
            base = acc; // 256 * base
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

fn msm(points: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    G1Projective::multi_exp(points, scalars)
}

fn feldman(fb: &FixedBase, coeffs: &[Scalar]) -> Vec<G1Projective> {
    coeffs.iter().map(|c| fb.mul(c)).collect()
}

fn feldman_eval(com: &[G1Projective], x: Scalar) -> G1Projective {
    let mut xp = Vec::with_capacity(com.len());
    let mut p = Scalar::ONE;
    for _ in 0..com.len() {
        xp.push(p);
        p *= x;
    }
    msm(com, &xp)
}

#[derive(Default, Clone, Copy)]
struct Timing {
    deal: Duration,     // per old member: sub-sharings + commitment to F_j
    receive: Duration,  // per new member: verify N dealings + combine + V'_k
    public: Duration,   // anyone: constant-term check for all dealers + V' check of one member
}

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().unwrap()).collect();
    let (n, t, gamma) = (args[0], args[1], args[2]);
    if let Some(th) = args.get(3) {
        rayon::ThreadPoolBuilder::new().num_threads(*th).build_global().unwrap();
    }
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let g = G1Projective::generator();
    let t0 = Instant::now();
    let fb = FixedBase::new(g);
    eprintln!("fixed-base table: {:?}", t0.elapsed());

    let xs: Vec<Scalar> = (1..=n as u64).map(sc).collect(); // old indices
    let xs_new: Vec<Scalar> = (1..=n as u64).map(sc).collect(); // new indices (fixed points, Sec. 3.1)

    // ---------- Share (users) ----------
    let secrets: Vec<Scalar> = (0..gamma).map(|_| Scalar::random(&mut rng)).collect();
    let polys: Vec<Vec<Scalar>> = secrets
        .iter()
        .map(|s| {
            let mut c = vec![*s];
            c.extend((1..t).map(|_| Scalar::random(&mut rng)));
            c
        })
        .collect();
    // shares[k][i]
    let shares: Vec<Vec<Scalar>> = (0..n)
        .into_par_iter()
        .map(|k| polys.iter().map(|p| eval(p, xs[k])).collect())
        .collect();
    let t_share = Instant::now();
    let pk: Vec<G1Projective> = secrets.par_iter().map(|s| fb.mul(s)).collect();
    let vk: Vec<Vec<G1Projective>> = shares
        .par_iter()
        .map(|row| row.iter().map(|s| fb.mul(s)).collect())
        .collect();
    eprintln!("Share: public keys + share keys for all users: {:?}", t_share.elapsed());

    // ========== Original DP-DID DBPSS (Offline + Handoff, Eq. 4) ==========
    // Each C_j: [[B]]^(j) in F^{Gamma x t} with zero first column, z^(j) = B X^T.
    let t_orig = Instant::now();
    let orig_member: Vec<Duration> = (0..n)
        .into_par_iter()
        .map(|j| {
            let mut r = ChaCha20Rng::seed_from_u64(1000 + j as u64);
            let st = Instant::now();
            let mut z = vec![vec![Scalar::ZERO; gamma]; n];
            for i in 0..gamma {
                let mut b = vec![Scalar::ZERO];
                b.extend((1..t).map(|_| Scalar::random(&mut r)));
                for k in 0..n {
                    z[k][i] = eval(&b, xs[k]);
                }
            }
            std::hint::black_box(&z);
            st.elapsed()
        })
        .collect();
    let orig_offline = orig_member.iter().max().unwrap();
    // receiver side of Eq. 4 is N*Gamma additions
    let st = Instant::now();
    let mut acc = shares[0].clone();
    for j in 0..n {
        for i in 0..gamma {
            acc[i] += shares[j][i]; // stands in for the N received z-columns
        }
    }
    std::hint::black_box(&acc);
    let orig_recv = st.elapsed();
    eprintln!("original DBPSS simulated in {:?}", t_orig.elapsed());

    // ========== DBPSS+ Handoff by resharing ==========
    // 1. Dealing: sub[j][k][i] = Q_ij(x'_k), digests H(sub[j][k]) committed.
    // The dealer's time covers the sub-sharings and the n salted digests h_jk = H(r_jk || s_jk).
    let dealt: Vec<(Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Duration, Vec<[u8; 32]>, Vec<Vec<u8>>)> = (0..n)
        .into_par_iter()
        .map(|j| {
            let mut r = ChaCha20Rng::seed_from_u64(2000 + j as u64);
            let st = Instant::now();
            let mut qs = Vec::with_capacity(gamma); // coefficients Q_ij
            let mut sub = vec![vec![Scalar::ZERO; gamma]; n];
            for i in 0..gamma {
                let mut q = vec![shares[j][i]];
                q.extend((1..t).map(|_| Scalar::random(&mut r)));
                for k in 0..n {
                    sub[k][i] = eval(&q, xs_new[k]);
                }
                qs.push(q);
            }
            let salts: Vec<[u8; 32]> = (0..n).map(|_| { let mut b = [0u8; 32]; r.fill_bytes(&mut b); b }).collect();
            let dg: Vec<Vec<u8>> = (0..n).map(|k| salted_digest(&salts[k], &sub[k])).collect();
            (qs, sub, st.elapsed(), salts, dg)
        })
        .collect();
    let deal_out: Vec<(Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Duration)> =
        dealt.iter().map(|d| (d.0.clone(), d.1.clone(), d.2)).collect();
    let digests: Vec<Vec<u8>> = dealt.iter().flat_map(|d| d.4.clone()).collect();
    // Round 2, once per handoff: each receiver checks the n vectors it received against
    // the posted digests. Added to the receiver's time of the first attempt.
    let digest_check: Vec<(bool, Duration)> = (0..n)
        .into_par_iter()
        .map(|k| {
            let st = Instant::now();
            let ok = (0..n).all(|j| salted_digest(&dealt[j].3[k], &dealt[j].1[k]) == dealt[j].4[k]);
            (ok, st.elapsed())
        })
        .collect();
    let digests_ok = digest_check.iter().all(|d| d.0);
    // 2.-7. One attempt of rounds 2-7 of Algorithm 1 for a qualified set Q of t dealers.
    // Only dealers in Q commit and are checked (|Q| = t), as in the paper.
    let qset: Vec<usize> = (0..t).collect(); // Q (first t qualified dealers)
    let r1 = attempt(&qset, b"attempt-1", &fb, &deal_out, &digests, &vk, &xs, &xs_new, n, t, gamma);

    // Correctness: reconstruct a few secrets from new shares, verify against pk.
    let lam_new = lagrange_at0(&xs_new[..t]);
    let correct = (0..gamma.min(50)).all(|i| {
        let s: Scalar = (0..t).map(|k| lam_new[k] * r1.newp[k][i]).sum();
        s == secrets[i] && fb.mul(&s) == pk[i]
    });

    // A2 against VeriHand: t-1 old shares (epoch e-1) + full state of ONE new member.
    let a2 = (0..gamma.min(50)).filter(|&i| {
        let mut pts: Vec<Scalar> = (0..t - 1).map(|j| xs[j]).collect();
        pts.push(xs[t - 1]);
        let l = lagrange_at0(&pts);
        let mut s = Scalar::ZERO;
        for j in 0..t - 1 {
            s += l[j] * shares[j][i];
        }
        s += l[t - 1] * r1.newp[t - 1][i];
        s == secrets[i]
    }).count();

    // Cancellation attack (Remark 1): the first two dealers of Q shift their constant terms
    // so that errors cancel under weights they could predict before committing. With tau
    // bound to all commitments, check (a) fails and the individual checks flag both.
    let tau_pred: Vec<Scalar> = (0..t).map(|j| hash_to_scalar(&[b"tau", &r1.rho.to_bytes_le(), &[j as u8]])).collect();
    let d_a = Scalar::from(12345u64);
    let d_b = -(tau_pred[0] * d_a) * tau_pred[1].invert().unwrap();
    let mut fbad = r1.f.clone();
    fbad[0][0] += fb.mul(&d_a);
    fbad[1][0] += fb.mul(&d_b);
    let tau_b = taus(&r1.rho, &fbad);
    let cancel_caught = !check_a(&qset, &vk, &r1.rp, &tau_b, &fbad);
    let st = Instant::now();
    let flagged: Vec<usize> = (0..t).filter(|&q| msm(&vk[qset[q]], &r1.rp) != fbad[q][0]).map(|q| qset[q]).collect();
    let fallback_ms = st.elapsed().as_secs_f64() * 1e3;
    let cancel_ok = cancel_caught && flagged == vec![qset[0], qset[1]];

    // Tampering test: one dealer in Q shifts its constant term -> check (a) must fail.
    let mut ftam = r1.f.clone();
    let pos = 3.min(t - 1);
    ftam[pos][0] += g;
    let tamper_caught = !check_a(&qset, &vk, &r1.rp, &taus(&r1.rho, &ftam), &ftam);

    // Retry (Algorithm 1, step 7): dealer qset[0] is disqualified (e.g. it withheld F),
    // the next qualified dealer joins Q, and rounds 2-7 rerun with fresh challenges on
    // the sub-shares already bound by the round-1 digests.
    let (retry_ok, retry_deal, retry_recv, retry_pub) = if n > t {
        let q2: Vec<usize> = (1..=t).collect();
        let r2 = attempt(&q2, b"attempt-2", &fb, &deal_out, &digests, &vk, &xs, &xs_new, n, t, gamma);
        let ok2 = r2.const_ok && r2.recv_ok && r2.newv_ok && (0..gamma.min(50)).all(|i| {
            let s: Scalar = (0..t).map(|k| lam_new[k] * r2.newp[k][i]).sum();
            s == secrets[i]
        });
        (ok2, r2.f_time, r2.recv_time, r2.public_time)
    } else {
        (false, Duration::ZERO, Duration::ZERO, Duration::ZERO)
    };

    // Worst case (Algorithm 1, step 7, repeated): t-1 corrupted dealers of Q are disqualified one
    // per attempt (each after attribution with (a_j)), so t attempts run with Q = {r,...,r+t-1}.
    // Needs n >= 2t-1. Reported as totals over all attempts.
    let (worst_ok, worst_attempts, worst_commit, worst_recv, worst_pub) = if n >= 2 * t - 1 {
        let mut tc = Duration::ZERO; let mut tr = Duration::ZERO; let mut tp = Duration::ZERO;
        let mut ok = true; let mut last_newp: Vec<Vec<Scalar>> = Vec::new();
        for r in 0..t {
            let q: Vec<usize> = (r..r + t).collect();
            let lab = format!("worst-{r}");
            let a = attempt(&q, lab.as_bytes(), &fb, &deal_out, &digests, &vk, &xs, &xs_new, n, t, gamma);
            ok &= a.const_ok && a.recv_ok && a.newv_ok;
            tc += a.f_time; tr += a.recv_time; tp += a.public_time;
            if r == 0 { tr += digest_check.iter().map(|d| d.1).max().unwrap(); }
            if r + 1 < t {
                // attribution: individual checks (a_j) for every dealer of Q
                let st = Instant::now();
                let fl: Vec<bool> = (0..t).map(|qq| msm(&vk[q[qq]], &a.rp) == a.f[qq][0]).collect();
                std::hint::black_box(&fl);
                tp += st.elapsed();
                // attribution at a receiver: individual checks (b_jk) for every dealer of Q
                let st = Instant::now();
                let fb_ok: Vec<bool> = (0..t).map(|qq| {
                    let sub = &deal_out[q[qq]].1[0];
                    let s: Scalar = (0..gamma).map(|i| a.rp[i] * sub[i]).sum();
                    fb.mul(&s) == feldman_eval(&a.f[qq], xs_new[0])
                }).collect();
                std::hint::black_box(&fb_ok);
                tr += st.elapsed();
            } else {
                last_newp = a.newp;
            }
        }
        let lam_w = lagrange_at0(&xs_new[..t]);
        ok &= (0..gamma.min(50)).all(|i| {
            let s: Scalar = (0..t).map(|k| lam_w[k] * last_newp[k][i]).sum();
            s == secrets[i]
        });
        (ok, t, tc, tr, tp)
    } else {
        (false, 0, Duration::ZERO, Duration::ZERO, Duration::ZERO)
    };

    let maxd = |v: &[Duration]| *v.iter().max().unwrap();
    let deal_time: Vec<Duration> = (0..n).map(|j| deal_out[j].2 + if qset.contains(&j) { r1.f_time } else { Duration::ZERO }).collect();
    let recv_first = (0..n).map(|k| r1.recv_each[k] + digest_check[k].1).max().unwrap();
    let tm = Timing { deal: maxd(&deal_time), receive: recv_first, public: r1.public_time };
    println!(
        "{{\"N\":{n},\"t\":{t},\"Gamma\":{gamma},\
\"orig_offline_member_ms\":{:.1},\"orig_handoff_recv_ms\":{:.1},\
\"plus_deal_member_ms\":{:.1},\"plus_recv_member_ms\":{:.1},\"plus_public_ms\":{:.1},\
\"digests_ok\":{digests_ok},\"const_ok\":{},\"recv_ok\":{},\"newv_ok\":{},\"correct\":{correct},\
\"a2_success_of_50\":{a2},\"tamper_caught\":{tamper_caught},\"cancel_attack_caught\":{cancel_ok},\"per_dealer_fallback_ms\":{fallback_ms:.1},\
\"retry_ok\":{retry_ok},\"retry_commit_ms\":{:.1},\"retry_recv_ms\":{:.1},\"retry_public_ms\":{:.1},\
\"audit_ok\":{},\"audit_all_ms\":{:.1},\
\"worst_ok\":{worst_ok},\"worst_attempts\":{worst_attempts},\"worst_commit_ms_total\":{:.1},\"worst_recv_ms_total\":{:.1},\"worst_public_ms_total\":{:.1}}}",
        orig_offline.as_secs_f64() * 1e3,
        orig_recv.as_secs_f64() * 1e3,
        tm.deal.as_secs_f64() * 1e3,
        tm.receive.as_secs_f64() * 1e3,
        tm.public.as_secs_f64() * 1e3,
        r1.const_ok, r1.recv_ok, r1.newv_ok,
        retry_deal.as_secs_f64() * 1e3,
        retry_recv.as_secs_f64() * 1e3,
        retry_pub.as_secs_f64() * 1e3,
        r1.audit_ok,
        r1.audit_time.as_secs_f64() * 1e3,
        worst_commit.as_secs_f64() * 1e3,
        worst_recv.as_secs_f64() * 1e3,
        worst_pub.as_secs_f64() * 1e3,
    );
}

struct Attempt {
    newp: Vec<Vec<Scalar>>,
    rho: Scalar,
    rp: Vec<Scalar>,
    f: Vec<Vec<G1Projective>>, // commitments of the dealers in Q, in Q order
    const_ok: bool,
    recv_ok: bool,
    newv_ok: bool,
    f_time: Duration,      // per dealer in Q: commitment to F_j
    recv_time: Duration,   // max per new member: combine + V'_k + hash h'_k + check (b)
    recv_each: Vec<Duration>,
    public_time: Duration, // check (a) over Q + check (c) for one member
    audit_time: Duration,  // one auditor (multi-threaded MSM in the default build): check (a) + check (c) for all n members
    audit_ok: bool,        // check (c) holds for every member
}

fn taus(rho: &Scalar, f: &[Vec<G1Projective>]) -> Vec<Scalar> {
    let fd = f_digest(f);
    (0..f.len()).map(|q| hash_to_scalar(&[b"tau", &rho.to_bytes_le(), &fd, &(q as u32).to_le_bytes()])).collect()
}

fn check_a(qset: &[usize], vk: &[Vec<G1Projective>], rp: &[Scalar], tau: &[Scalar], f: &[Vec<G1Projective>]) -> bool {
    let gamma = rp.len();
    let mut pts = Vec::with_capacity(qset.len() * (gamma + 1));
    let mut scs = Vec::with_capacity(qset.len() * (gamma + 1));
    for (q, &j) in qset.iter().enumerate() {
        for i in 0..gamma {
            pts.push(vk[j][i]);
            scs.push(rp[i] * tau[q]);
        }
        pts.push(f[q][0]);
        scs.push(-tau[q]);
    }
    bool::from(msm(&pts, &scs).is_identity())
}

#[allow(clippy::too_many_arguments)]
fn attempt(
    qset: &[usize],
    label: &[u8],
    fb: &FixedBase,
    deal_out: &[(Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Duration)],
    digests: &[Vec<u8>],
    vk: &[Vec<G1Projective>],
    xs: &[Scalar],
    xs_new: &[Scalar],
    n: usize,
    t: usize,
    gamma: usize,
) -> Attempt {
    // Round 2: new members combine with Lagrange over Q and post V'_k before the challenge.
    let lam = lagrange_at0(&qset.iter().map(|&j| xs[j]).collect::<Vec<_>>());
    let combine: Vec<(Vec<Scalar>, Vec<G1Projective>, Vec<u8>, Duration)> = (0..n)
        .into_par_iter()
        .map(|k| {
            let st = Instant::now();
            let mut newp = vec![Scalar::ZERO; gamma];
            for (idx, &j) in qset.iter().enumerate() {
                let sub = &deal_out[j].1[k];
                for i in 0..gamma {
                    newp[i] += lam[idx] * sub[i];
                }
            }
            let newv: Vec<G1Projective> = newp.iter().map(|s| fb.mul(s)).collect();
            // hash h'_k of the compressed share-key vector, posted on the ledger
            let mut h = Sha256::new();
            for p in &newv {
                h.update(p.to_compressed());
            }
            let hk = h.finalize().to_vec();
            (newp, newv, hk, st.elapsed())
        })
        .collect();
    let vdig: Vec<Vec<u8>> = combine.iter().map(|c| c.2.clone()).collect();
    // Round 3: beacon challenge after all digests and all V' are posted.
    let mut bc: Vec<&[u8]> = vec![b"VeriHand handoff e=1", label];
    for d in digests.iter().chain(vdig.iter()) {
        bc.push(d);
    }
    let rho = hash_to_scalar(&bc);
    let rp = powers(rho, gamma);
    // Round 4: each dealer in Q commits to F_j = sum_i rho^i Q_ij (t points).
    let fcom: Vec<(Vec<G1Projective>, Duration)> = qset
        .par_iter()
        .map(|&j| {
            let st = Instant::now();
            let mut f = vec![Scalar::ZERO; t];
            for (i, q) in deal_out[j].0.iter().enumerate() {
                for l in 0..t {
                    f[l] += rp[i] * q[l];
                }
            }
            (feldman(fb, &f), st.elapsed())
        })
        .collect();
    let f: Vec<Vec<G1Projective>> = fcom.iter().map(|x| x.0.clone()).collect();
    let f_time = fcom.iter().map(|x| x.1).max().unwrap();
    // Round 5: second challenge tau from all commitments of Q.
    let st = Instant::now();
    let tau = taus(&rho, &f);
    // Round 6 (a): public constant-term check over Q.
    let const_ok = check_a(qset, vk, &rp, &tau, &f);
    let public_a = st.elapsed();
    // Round 6 (b): each receiver checks its sub-shares from Q, batched with tau.
    let recv: Vec<(bool, Duration)> = (0..n)
        .into_par_iter()
        .map(|k| {
            let st = Instant::now();
            let mut lhs = Scalar::ZERO;
            let mut pts = Vec::with_capacity(t * t);
            let mut scs = Vec::with_capacity(t * t);
            for (q, &j) in qset.iter().enumerate() {
                let sub = &deal_out[j].1[k];
                let mut s = Scalar::ZERO;
                for i in 0..gamma {
                    s += rp[i] * sub[i];
                }
                lhs += tau[q] * s;
                let mut xp = Scalar::ONE;
                for l in 0..t {
                    pts.push(f[q][l]);
                    scs.push(tau[q] * xp);
                    xp *= xs_new[k];
                }
            }
            let ok = bool::from((fb.mul(&lhs) - msm(&pts, &scs)).is_identity());
            (ok, st.elapsed() + combine[k].3)
        })
        .collect();
    let recv_ok = recv.iter().all(|r| r.0);
    let recv_each: Vec<Duration> = recv.iter().map(|r| r.1).collect();
    let recv_time = *recv_each.iter().max().unwrap();
    // Round 6 (c): public check of one new member's V'_k.
    let st = Instant::now();
    let k = 0;
    let lhs = msm(&combine[k].1, &rp);
    let rhs = msm(&(0..qset.len()).map(|q| feldman_eval(&f[q], xs_new[k])).collect::<Vec<_>>(), &lam);
    let newv_ok = lhs == rhs;
    let public_time = public_a + st.elapsed();
    // Full audit by one party: check (a) again plus check (c) for every member.
    let st = Instant::now();
    let a_again = check_a(qset, vk, &rp, &tau, &f);
    let mut audit_ok = a_again;
    for kk in 0..n {
        let l = msm(&combine[kk].1, &rp);
        let r = msm(&(0..qset.len()).map(|q| feldman_eval(&f[q], xs_new[kk])).collect::<Vec<_>>(), &lam);
        audit_ok &= l == r;
    }
    let audit_time = st.elapsed();
    Attempt {
        newp: combine.into_iter().map(|c| c.0).collect(),
        rho,
        rp,
        f,
        const_ok,
        recv_ok,
        newv_ok,
        f_time,
        recv_time,
        recv_each,
        public_time,
        audit_time,
        audit_ok,
    }
}

fn f_digest(f: &[Vec<G1Projective>]) -> Vec<u8> {
    let mut h = Sha256::new();
    for row in f {
        for p in row {
            h.update(p.to_compressed());
        }
    }
    h.finalize().to_vec()
}
