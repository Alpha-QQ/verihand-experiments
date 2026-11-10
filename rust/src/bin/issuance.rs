//! DP-DID+ issuance path: GJKR-style DKG, threshold BLS (min-sig: sigma in G1, pk in G2),
//! ledger-anchored credentials and the LA-FS game.
//! Usage: issuance <N> <t> <num_creds>

use blstrs::{pairing, G1Projective, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::time::Instant;

const DST: &[u8] = b"DPDID-PLUS-BLS-SIG-V1";

fn eval(c: &[Scalar], x: Scalar) -> Scalar {
    c.iter().rev().fold(Scalar::ZERO, |a, ci| a * x + ci)
}
fn lagrange_at0(xs: &[Scalar]) -> Vec<Scalar> {
    xs.iter()
        .enumerate()
        .map(|(i, xi)| {
            let (mut n, mut d) = (Scalar::ONE, Scalar::ONE);
            for (j, xj) in xs.iter().enumerate() {
                if i != j {
                    n *= -*xj;
                    d *= *xi - xj;
                }
            }
            n * d.invert().unwrap()
        })
        .collect()
}
fn com_eval(com: &[G2Projective], x: Scalar) -> G2Projective {
    let mut acc = G2Projective::identity();
    let mut xp = Scalar::ONE;
    for c in com {
        acc += c * xp;
        xp *= x;
    }
    acc
}
fn h(data: &[&[u8]]) -> [u8; 32] {
    let mut s = Sha256::new();
    for d in data {
        s.update(d);
    }
    s.finalize().into()
}
fn hm(m: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(m, DST, &[])
}
fn verify(m: &[u8], sig: &G1Projective, pk: &G2Projective) -> bool {
    pairing(&sig.to_affine(), &G2Projective::generator().to_affine()) == pairing(&hm(m).to_affine(), &pk.to_affine())
}

// ---------------- ledger ----------------
struct Block {
    height: u64,
    epoch: u64,
    txs: Vec<[u8; 32]>,
    root: [u8; 32],
}
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut lvl = leaves.to_vec();
    if lvl.is_empty() {
        return [0; 32];
    }
    while lvl.len() > 1 {
        lvl = lvl.chunks(2).map(|c| h(&[&c[0], c.get(1).unwrap_or(&c[0])])).collect();
    }
    lvl[0]
}
fn merkle_path(leaves: &[[u8; 32]], mut idx: usize) -> Vec<[u8; 32]> {
    let mut lvl = leaves.to_vec();
    let mut path = vec![];
    while lvl.len() > 1 {
        let sib = if idx % 2 == 0 { *lvl.get(idx + 1).unwrap_or(&lvl[idx]) } else { lvl[idx - 1] };
        path.push(sib);
        lvl = lvl.chunks(2).map(|c| h(&[&c[0], c.get(1).unwrap_or(&c[0])])).collect();
        idx /= 2;
    }
    path
}
fn merkle_verify(leaf: [u8; 32], mut idx: usize, path: &[[u8; 32]], root: [u8; 32]) -> bool {
    let mut cur = leaf;
    for s in path {
        cur = if idx % 2 == 0 { h(&[&cur, s]) } else { h(&[s, &cur]) };
        idx /= 2;
    }
    cur == root
}
struct Ledger {
    blocks: Vec<Block>, // append-only: assumption L (persistence)
}
impl Ledger {
    fn append(&mut self, epoch: u64, txs: Vec<[u8; 32]>) -> u64 {
        let height = self.blocks.len() as u64;
        let root = merkle_root(&txs);
        self.blocks.push(Block { height, epoch, txs, root });
        height
    }
}

struct Cred {
    did: Vec<u8>,
    claim: Vec<u8>,
    epoch: u64,
    ctr: u64,
    sig: G1Projective,
    height: u64,
    idx: usize,
    path: Vec<[u8; 32]>,
}
fn cred_msg(did: &[u8], claim: &[u8], epoch: u64, ctr: u64) -> Vec<u8> {
    [did, b"|", claim, b"|", &epoch.to_le_bytes(), &ctr.to_le_bytes()].concat()
}
/// Verifier: BLS + ledger anchoring (H(cred) in a block of the claimed epoch).
fn verify_cred(c: &Cred, pk: &G2Projective, ledger: &Ledger) -> (bool, bool) {
    let m = cred_msg(&c.did, &c.claim, c.epoch, c.ctr);
    let sig_ok = verify(&m, &c.sig, pk);
    let leaf = h(&[&m, &c.sig.to_compressed()]);
    let anchored = ledger
        .blocks
        .get(c.height as usize)
        .map(|b| b.epoch == c.epoch && merkle_verify(leaf, c.idx, &c.path, b.root))
        .unwrap_or(false);
    (sig_ok, anchored)
}

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).map(|x| x.parse().unwrap()).collect();
    let (n, t, ncred) = (a[0], a[1], a[2]);
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let g2 = G2Projective::generator();
    let h2 = G2Projective::hash_to_curve(b"pedersen-h", b"DPDID-PLUS-H", &[]);
    let xs: Vec<Scalar> = (1..=n as u64).map(Scalar::from).collect();

    // ---------- DKG (GJKR): phase 1 Pedersen VSS ----------
    let st = Instant::now();
    let mut polys = vec![];
    let mut blinds = vec![];
    let mut ped = vec![];
    for _ in 0..n {
        let f: Vec<Scalar> = (0..t).map(|_| Scalar::random(&mut rng)).collect();
        let b: Vec<Scalar> = (0..t).map(|_| Scalar::random(&mut rng)).collect();
        ped.push((0..t).map(|l| g2 * f[l] + h2 * b[l]).collect::<Vec<_>>());
        polys.push(f);
        blinds.push(b);
    }
    // each member k checks every dealer's share against the Pedersen commitments
    let mut qual = vec![];
    for j in 0..n {
        let ok = (0..n).all(|k| {
            let (s, r) = (eval(&polys[j], xs[k]), eval(&blinds[j], xs[k]));
            let mut acc = G2Projective::identity();
            let mut xp = Scalar::ONE;
            for c in &ped[j] {
                acc += c * xp;
                xp *= xs[k];
            }
            g2 * s + h2 * r == acc
        });
        if ok {
            qual.push(j);
        }
    }
    // phase 2: QUAL members reveal Feldman commitments A_jl = g2^{a_jl}; members check
    let feld: Vec<Vec<G2Projective>> = qual.iter().map(|&j| polys[j].iter().map(|c| g2 * c).collect()).collect();
    let feld_ok = qual.iter().enumerate().all(|(qi, &j)| {
        (0..n).all(|k| g2 * eval(&polys[j], xs[k]) == com_eval(&feld[qi], xs[k]))
    });
    let sk: Vec<Scalar> = (0..n).map(|k| qual.iter().map(|&j| eval(&polys[j], xs[k])).sum()).collect();
    let pk_c: G2Projective = feld.iter().map(|f| f[0]).sum(); // prod_j A_j0 (fix of A3)
    let pk_share: Vec<G2Projective> =
        (0..n).map(|k| feld.iter().map(|f| com_eval(f, xs[k])).sum()).collect();
    let dkg_time = st.elapsed();
    // A3: the paper's pk_C = prod_{j in S1} g^{sk_j}
    let pk_paper: G2Projective = qual.iter().map(|&j| g2 * sk[j]).sum();

    // ---------- issuance in epochs 0..2, with ledger anchoring ----------
    let mut ledger = Ledger { blocks: vec![] };
    let lam = lagrange_at0(&xs[..t]);
    let mut creds = vec![];
    let mut sign_time = std::time::Duration::ZERO;
    let mut partial_verify_time = std::time::Duration::ZERO;
    for epoch in 0..3u64 {
        let mut pending = vec![];
        for c in 0..ncred {
            let did = format!("did:dpdid:holder{c}").into_bytes();
            let claim = format!("age>=18;epoch{epoch}").into_bytes();
            let m = cred_msg(&did, &claim, epoch, c as u64);
            let st = Instant::now();
            let hmm = hm(&m);
            let partials: Vec<G1Projective> = (0..t).map(|k| hmm * sk[k]).collect();
            sign_time += st.elapsed();
            let st = Instant::now();
            for k in 0..t {
                assert!(pairing(&partials[k].to_affine(), &G2Projective::generator().to_affine())
                    == pairing(&hmm.to_affine(), &pk_share[k].to_affine()));
            }
            partial_verify_time += st.elapsed();
            let sig: G1Projective = (0..t).map(|k| partials[k] * lam[k]).sum();
            pending.push((did, claim, c as u64, sig, h(&[&m, &sig.to_compressed()])));
        }
        let leaves: Vec<[u8; 32]> = pending.iter().map(|p| p.4).collect();
        let height = ledger.append(epoch, leaves.clone());
        for (idx, (did, claim, ctr, sig, _)) in pending.into_iter().enumerate() {
            creds.push(Cred { did, claim, epoch, ctr, sig, height, idx, path: merkle_path(&leaves, idx) });
        }
    }
    let st = Instant::now();
    let all_ok = creds.iter().all(|c| verify_cred(c, &pk_c, &ledger) == (true, true));
    let verify_time = st.elapsed() / creds.len() as u32;
    let paper_pk_verifies = verify(&cred_msg(&creds[0].did, &creds[0].claim, 0, 0), &creds[0].sig, &pk_paper);

    // ---------- LA-FS game: adversary learns sk_C in epoch e* = 3 ----------
    let e_star = 3u64;
    let sk_c: Scalar = (0..t).map(|k| lam[k] * sk[k]).sum();
    // (a) backdated forgery labelled epoch 1: valid BLS, but it can only be anchored now
    let m = cred_msg(b"did:dpdid:mallory", b"age>=18;epoch1", 1, 999);
    let sig = hm(&m) * sk_c;
    let leaf = h(&[&m, &sig.to_compressed()]);
    let hgt = ledger.append(e_star, vec![leaf]);
    let forged = Cred { did: b"did:dpdid:mallory".to_vec(), claim: b"age>=18;epoch1".to_vec(), epoch: 1, ctr: 999, sig, height: hgt, idx: 0, path: vec![] };
    let (fs_sig, fs_anch) = verify_cred(&forged, &pk_c, &ledger);
    // (b) pointing at an old epoch-1 block with a fake path
    let mut forged2 = forged;
    forged2.height = 1;
    forged2.path = creds[ncred].path.clone();
    let (_, fs_anch2) = verify_cred(&forged2, &pk_c, &ledger);

    println!(
        "{{\"N\":{n},\"t\":{t},\"qual\":{},\"feldman_ok\":{feld_ok},\"dkg_ms_total_sim\":{:.1},\
\"partial_sign_ms_per_cred_all_t\":{:.3},\"partial_verify_ms_per_cred\":{:.3},\"verify_cred_ms\":{:.3},\
\"all_creds_ok\":{all_ok},\"paper_pkC_verifies\":{paper_pk_verifies},\
\"lafs_backdated_sig_valid\":{fs_sig},\"lafs_backdated_anchored\":{fs_anch},\"lafs_fake_path_anchored\":{fs_anch2}}}",
        qual.len(),
        dkg_time.as_secs_f64() * 1e3,
        sign_time.as_secs_f64() * 1e3 / (3 * ncred) as f64,
        partial_verify_time.as_secs_f64() * 1e3 / (3 * ncred) as f64,
        verify_time.as_secs_f64() * 1e3,
    );
}
