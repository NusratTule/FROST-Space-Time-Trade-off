# Space–Time Trade-off (FROST precomputation study)

Standalone Rust crate for the supervisory research question:

> How does storing precomputed FROST signing material affect online signing time, memory usage, and storage overhead?

This project depends on the existing [`frost2_rust`](https://github.com/NusratTule/Frost2_rust) library via a **pinned git revision** (`rev = 6b995f358b180d027a34ac0cb0137c9a241f98d9` in `Cargo.toml`). It does **not** edit `frost2_rust`'s `core.rs`, `main.rs`, or `roast.rs` — it reuses that crate's public APIs only. Cargo fetches the dependency automatically, so no manual clone of `frost2_rust` is required.

## Installation

**Prerequisites:** a Rust toolchain (install via [rustup](https://rustup.rs); tested with Rust 2021 edition). `ps` (present on macOS/Linux) is used for coarse RSS sampling.

```bash
# 1. Clone this repository
git clone https://github.com/NusratTule/FROST-Space-Time-Trade-off.git
cd FROST-Space-Time-Trade-off

# 2. Build (Cargo fetches the pinned frost2_rust dependency automatically)
cargo build --release

# 3. Verify the test suite (single-use store invariants + C1/C2/C3 end-to-end)
cargo test
```

> Note: if the `Frost2_rust` repository is private, GitHub read access for that
> repo is required for `cargo build` / `cargo test` to fetch the pinned dependency.

## Configurations

| ID | Label | Offline | Online |
|----|-------|---------|--------|
| C1 | `C1_none` | nothing | `spp_preprocess` → LR → `partial_sign` |
| C2 | `C2_nonces` | secret nonces `d`, `s_scalar` | consume → commitments (+ auth for +/#) → LR → `partial_sign` |
| C3 | `C3_nonces_commitments` | full `spp_preprocess` token | consume → LR → `partial_sign` |

Variants in v1: **Binding** (`Frost2`), **FROST-2+**, **FROST-2#**. ROAST is excluded.

## Experimental methodology

- **Parameter sets:** `(n, t, α) ∈ {(10,5,5), (20,7,7), (20,10,10)}`, with **T = 30** trials per cell (default) and base **seed = 42**. Each trial derives its RNG seed from the base seed plus offsets for trial index, `n`, `t`, configuration, and variant (see `src/main.rs`), so runs are reproducible.
- **Per-trial metrics:**
  - `precomputation_time_ms` — offline generation of retained material only.
  - `online_signing_time_ms` — token consume/assemble + `build_leader_request` + all `partial_sign` calls.
  - `precomputed_storage_bytes` — retained encoding size just before the online phase (64 B/signer for C2; 128 B/signer for C3; 192 B/signer for C3 with FROST-2+/FROST-2# auth fields).
  - `memory_bytes` — coarse process RSS via `ps`.
- **Correctness gate:** every trial's signature is aggregated and verified (`ok` column / `ok_all`). A run is only valid if all trials verify.
- **Security invariant:** secret nonce material is **GENERATED → STORED → CONSUMED ONCE → REMOVED**. Reuse attempts fail (`PrecompStoreError`). See `src/precomp_store.rs` and `tests/reuse_invariant.rs`.
- **Fairness:** this harness does not redesign FROST. C2's online token assembly mirrors `spp_preprocess` exactly (`src/token_build.rs`); any divergence would fail verification.

## Timer boundaries (important for thesis fairness)

| Metric | Includes | Excludes |
|--------|----------|----------|
| `precomputation_time_ms` | Offline generation of retained material | DKG, online path |
| `online_signing_time_ms` | Token assemble/consume + `build_leader_request` + all `partial_sign` | DKG, offline precomp, `aggregate`, `verify` |
| `precomputed_storage_bytes` | Retained encoding size just before online | Working RSS |
| `memory_bytes` | Coarse process RSS via `ps` | Not allocator-precise |

The CRYPTOLOGY 2026 paper timed `preprocess` and `signing` as separate phases. This harness uses a different online boundary (token work + LR + signing). Do not equate `online_signing_time_ms` with Table 3 “signing” without stating the difference.

## Build & benchmark commands

```bash
cargo test                                             # run all unit + integration tests
cargo run --release -- -r 30 -s 42 -o output/spacetime_results.csv   # full study (all variants)
```

Optional: restrict variant

```bash
cargo run --release -- -v binding -r 30 -o output/spacetime_results.csv
# -v frost2plus | frost2hash | all
```

CLI flags (`spacetime_bench`):

| Flag | Meaning | Default |
|------|---------|---------|
| `-o` / `--output` | Trial CSV path (summary written alongside) | `output/spacetime_results.csv` |
| `-r` / `--trials` | Trials per (config, variant, params) cell | `30` |
| `-s` / `--seed` | Base RNG seed | `42` |
| `-v` / `--variant` | `binding`/`frost2`, `frost2plus`, `frost2hash`, or `all` | `all` |

## CSV columns

**Trials** (`spacetime_results.csv`):

`configuration,n,t,alpha,variant,trial,precomputation_time_ms,online_signing_time_ms,precomputed_storage_bytes,memory_bytes,ok`

**Summary** (`spacetime_summary.csv`): mean / median / std for precomp and online times, plus storage and mean RSS.

Parameters: `(n,t,α) ∈ {(10,5,5), (20,7,7), (20,10,10)}`, default **T = 30**, seed **42**.

## Layout

```
FROST-Space-Time-Trade-off/
  Cargo.toml           # frost2_rust pinned via git rev
  README.md
  docs/                # supervisor DOCX + STEP1 map + interpretation notes
  src/
    lib.rs
    main.rs            # spacetime_bench CLI
    precomp_store.rs    # single-use stores
    token_build.rs      # C2 online token assembly (mirrors spp_preprocess)
    benchmark.rs        # run_one + metrics
    csv_report.rs
  tests/reuse_invariant.rs
  output/               # CSV/XLSX results after a run (checked in for the record)
```

## Academic note

Do **not** claim that C2 or C3 is faster until measured results demonstrate it.
This experiment characterises the storage ↔ online-time trade-off; it does not invent new FROST cryptography.
