# VeriHand experiments

All experiments of the paper run from one file, `main.py`. Edit only its CONFIG block
(or choose a profile on the command line); every parameter and result goes to one JSON file.

## Layout

| Path | Content |
|---|---|
| `main.py` | CONFIG (all parameters, two profiles: `paper`, `quick`), runs everything, writes the JSON |
| `verihand/field.py` | BLS12-381 scalar-field arithmetic, Lagrange interpolation, hash |
| `verihand/attacks.py` | attacks on DP-DID: A1 witness forgery, A2 cross-epoch shares, Q3 refresh, A3 DKG key |
| `verihand/grid.py` | corruption-pattern grid (Fig. 2) |
| `verihand/weights.py` | timing of the aggregation weights (Remark 1); share keys of a rejected dealing (Theorem 1) |
| `verihand/fault_handling.py` | deadlines, complaints, disqualification and restarts of Algorithm 1 |
| `verihand/rust_bench.py` | builds the Rust prototype and runs its binaries |
| `verihand/stats.py` | mean, standard deviation, relative standard deviation |
| `rust/` | Rust prototype on BLS12-381 (`blstrs`): handoff, per-secret baseline, issuance, revocation |

## Requirements

- Python 3.8 or later (standard library only).
- Rust 1.85 or later with Cargo, for the timing experiments. Install once:

      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
      source "$HOME/.cargo/env"

  (Windows: download `rustup-init.exe` from https://rustup.rs.) The first run downloads the
  Rust dependencies, so it needs internet access.

## Windows (step by step, PowerShell)

1. Python: install Python 3.12 from https://www.python.org/downloads/windows/ and tick
   "Add python.exe to PATH" on the first screen (or run `winget install Python.Python.3.12`).
2. C++ build tools (needed by the BLS12-381 library `blst`): install "Build Tools for Visual
   Studio 2022" with the workload "Desktop development with C++":

       winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

   (or download it from https://visualstudio.microsoft.com/visual-cpp-build-tools/).
3. Rust: download and run `rustup-init.exe` from https://rustup.rs and accept the default
   (`1) Proceed with standard installation`), or run `winget install Rustlang.Rustup`.
4. Close and reopen PowerShell, then check: `python --version`, `cargo --version`.
5. Unpack and run:

       Expand-Archive verihand-experiments.zip -DestinationPath .
       cd verihand-experiments
       python main.py --profile quick
       python main.py

## Run (macOS / Linux)

    cd verihand-experiments
    python3 main.py --profile quick     # smoke test, about 1 minute; writes results-quick.json
    python3 main.py                     # all paper experiments; writes results.json

The full run took 205 minutes on the machine of the paper (see below), most of it in the
Gamma = 10^5 handoff and per-secret baseline runs. To run only some experiments, set the
corresponding entries of `"run"` in CONFIG to `False`.

## Output (`results.json`)

- `meta`, `machine`, `config`: profile, runtime, machine description, every parameter.
- `attacks`, `corruption_grid`, `weight_timing`, `fault_handling`: machine-independent outcomes.
- `handoff_multithreaded`, `handoff_single_threaded`, `sweep`, `per_secret_baseline`,
  `issuance`, `revocation`: for each configuration the arguments, `summary` (mean, std,
  rsd_pct, n per metric), `all_checks_pass`, and every raw run.
- `paper_numbers`: the numbers quoted in the text (21 of 49 pairs, speedups, public-data
  ratios with published and with derived share keys, key-derivation cost).
- Per-role costs (`paper_numbers.gamma_*_roles_multithreaded`): dealer, receiver, and an
  auditor that checks (a) and check (c) for all n incoming members (`audit_all_ms`), plus a
  worst-case handoff in which t-1 dealers of Q are disqualified one per attempt
  (`worst_attempts` = t, summed times `worst_*_ms_total`).
- `fault_handling` includes the availability rule of Algorithm 1 (a receiver that posts the
  hash of its share-key vector but withholds the vector).

Every Rust run also reports pass/fail flags; `all_checks_pass` must be `true` everywhere.
Timings depend on the machine; all other values do not.

## Results reported in the paper

`results/results-paper-2026-11-08.json` is the `results.json` of the run whose numbers appear
in the paper: AMD Ryzen 7 7700 (8 cores, 16 threads, 3.8 GHz), 32 GB RAM, Windows 11
(build 26200), stable Rust with `blstrs` 0.7, `python main.py` with the `paper` profile
(ten repetitions of every timing). It contains every parameter, every raw run, the means and
standard deviations, all pass/fail flags, and the derived numbers quoted in the paper.
Timings depend on the machine; the pass/fail flags and the derived ratios should reproduce.

