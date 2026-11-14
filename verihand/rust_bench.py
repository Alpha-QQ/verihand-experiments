"""Builds the Rust prototype (BLS12-381, blstrs) and runs its benchmark binaries.

Each binary prints one JSON line per run; this module parses it. The binaries are
  dpdid_plus <n> <t> <Gamma> [threads]  VeriHand handoff and DP-DID Offline baseline
  baseline   <n> <t> <Gamma>            per-secret Feldman commitments (also derived keys)
  issuance   <n> <t> <credentials>      GJKR, threshold BLS issuance, LA-FS checks
  revocation <revoked>                  sparse-Merkle-tree revocation
"""
import json
import os
import shutil
import subprocess

RUST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rust")


def build(target_dir=None, single_thread_msm=False):
    """cargo build --release; returns the directory that holds the binaries.

    single_thread_msm=True builds with the crate feature single-thread-msm, which turns
    off the thread pool of blst's multi-scalar multiplication, into a separate target
    directory (<target>-st). The single-threaded measurements use these binaries."""
    if shutil.which("cargo") is None:
        raise RuntimeError("cargo not found: install Rust from https://rustup.rs (see README.md)")
    env = dict(os.environ)
    base = target_dir or env.get("CARGO_TARGET_DIR") or os.path.join(RUST_DIR, "target")
    cmd = ["cargo", "build", "--release", "--quiet"]
    if single_thread_msm:
        base = base.rstrip("/\\") + "-st"
        cmd += ["--features", "single-thread-msm"]
    env["CARGO_TARGET_DIR"] = base
    subprocess.run(cmd, cwd=RUST_DIR, env=env, check=True)
    return os.path.join(base, "release")


def run(bin_dir, name, *args):
    """Run one binary once and return its JSON output as a dict."""
    exe = os.path.join(bin_dir, name + (".exe" if os.name == "nt" else ""))
    out = subprocess.run([exe, *map(str, args)], capture_output=True, text=True, check=True)
    lines = [l for l in out.stdout.splitlines() if l.strip().startswith("{")]
    return json.loads(lines[-1])
