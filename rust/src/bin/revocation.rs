//! DP-DID+ revocation: compact sparse Merkle tree (SMT) of revoked identifiers.
//! The committee threshold-signs (epoch, root) and anchors it on the ledger (see issuance.rs);
//! here we measure build / prove / verify and check soundness against a revoked holder.
//! Node hash: empty = 0^32, single leaf = H(0x00 || key), internal = H(0x01 || left || right).
//! Usage: revocation <revoked_set_size>

use sha2::{Digest, Sha256};
use std::time::Instant;

type H = [u8; 32];
const EMPTY: H = [0u8; 32];

fn h(parts: &[&[u8]]) -> H {
    let mut s = Sha256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}
fn bit(k: &H, d: usize) -> bool {
    (k[d / 8] >> (7 - d % 8)) & 1 == 1
}
fn leaf(k: &H) -> H {
    h(&[&[0u8], k])
}

/// keys must be sorted; all keys in the slice share their first `d` bits.
fn root(keys: &[H], d: usize) -> H {
    match keys.len() {
        0 => EMPTY,
        1 => leaf(&keys[0]),
        _ => {
            let split = keys.partition_point(|k| !bit(k, d));
            h(&[&[1u8], &root(&keys[..split], d + 1), &root(&keys[split..], d + 1)])
        }
    }
}

enum Terminal {
    Empty,
    Leaf(H),
}
struct Proof {
    siblings: Vec<H>, // top-down
    term: Terminal,
}

fn prove_non_member(keys: &[H], k: &H) -> Option<Proof> {
    let mut sibs = vec![];
    let mut cur = keys;
    let mut d = 0;
    loop {
        match cur.len() {
            0 => return Some(Proof { siblings: sibs, term: Terminal::Empty }),
            1 if &cur[0] != k => return Some(Proof { siblings: sibs, term: Terminal::Leaf(cur[0]) }),
            1 => return None, // k is revoked
            _ => {
                let split = cur.partition_point(|x| !bit(x, d));
                let (l, r) = cur.split_at(split);
                if bit(k, d) {
                    sibs.push(root(l, d + 1));
                    cur = r;
                } else {
                    sibs.push(root(r, d + 1));
                    cur = l;
                }
                d += 1;
            }
        }
    }
}

fn verify_non_member(rt: &H, k: &H, p: &Proof) -> bool {
    let depth = p.siblings.len();
    let mut acc = match &p.term {
        Terminal::Empty => EMPTY,
        Terminal::Leaf(other) => {
            // the other leaf must sit on k's path (same first `depth` bits) and differ from k
            if other == k || (0..depth).any(|d| bit(other, d) != bit(k, d)) {
                return false;
            }
            leaf(other)
        }
    };
    for d in (0..depth).rev() {
        acc = if bit(k, d) { h(&[&[1u8], &p.siblings[d], &acc]) } else { h(&[&[1u8], &acc, &p.siblings[d]]) };
    }
    &acc == rt
}

fn main() {
    let n: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    let mut keys: Vec<H> = (0..n as u64).map(|i| h(&[b"did:dpdid:revoked", &i.to_le_bytes()])).collect();
    keys.sort();
    let st = Instant::now();
    let rt = root(&keys, 0);
    let build = st.elapsed();

    // honest non-revoked holders
    let probes: Vec<H> = (0..100u64).map(|i| h(&[b"did:dpdid:valid", &i.to_le_bytes()])).collect();
    let st = Instant::now();
    let proofs: Vec<Proof> = probes.iter().map(|k| prove_non_member(&keys, k).unwrap()).collect();
    let prove = st.elapsed() / probes.len() as u32;
    let st = Instant::now();
    let ok = probes.iter().zip(&proofs).all(|(k, p)| verify_non_member(&rt, k, p));
    let verify = st.elapsed() / probes.len() as u32;
    let avg_sibs = proofs.iter().map(|p| p.siblings.len()).sum::<usize>() as f64 / proofs.len() as f64;
    let avg_bytes = proofs
        .iter()
        .map(|p| 32 * p.siblings.len() + 1 + if matches!(p.term, Terminal::Leaf(_)) { 32 } else { 0 })
        .sum::<usize>() as f64
        / proofs.len() as f64;

    // revoked holder: no honest proof exists; replaying other holders' proofs must fail
    let revoked = keys[n / 2];
    let none = prove_non_member(&keys, &revoked).is_none();
    let replay_rejected = proofs.iter().all(|p| !verify_non_member(&rt, &revoked, p));
    // the revoked holder claims its own leaf position is empty
    let mut sibs = vec![];
    let mut cur: &[H] = &keys;
    let mut d = 0;
    while cur.len() > 1 {
        let split = cur.partition_point(|x| !bit(x, d));
        let (l, r) = cur.split_at(split);
        if bit(&revoked, d) {
            sibs.push(root(l, d + 1));
            cur = r;
        } else {
            sibs.push(root(r, d + 1));
            cur = l;
        }
        d += 1;
    }
    let empty_claim_rejected = !verify_non_member(&rt, &revoked, &Proof { siblings: sibs, term: Terminal::Empty });

    println!(
        "{{\"revoked\":{n},\"build_ms\":{:.1},\"prove_us\":{:.1},\"verify_us\":{:.1},\"avg_siblings\":{:.1},\"avg_proof_bytes\":{:.0},\
\"honest_ok\":{ok},\"revoked_has_no_proof\":{none},\"replay_rejected\":{replay_rejected},\"empty_claim_rejected\":{empty_claim_rejected}}}",
        build.as_secs_f64() * 1e3,
        prove.as_secs_f64() * 1e6,
        verify.as_secs_f64() * 1e6,
        avg_sibs,
        avg_bytes
    );
}
