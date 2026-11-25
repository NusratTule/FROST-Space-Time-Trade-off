# Results interpretation guide

## Do not overclaim

Whether C2 or C3 reduces `online_signing_time_ms` relative to C1 is an **experimental** question.
Populate claims only after inspecting `output/spacetime_summary.csv`.

## Expected analytical storage (encoding sizes)

Per active signer, retained material just before online:

| Config | Binding (Frost2) | FROST-2+ / FROST-2# |
|--------|------------------|---------------------|
| C1 | 0 B | 0 B |
| C2 | 64 B (`d` + `s_scalar`) | 64 B (auth still online) |
| C3 | 128 B | 192 B (`+ u` + `v`) |

For α = 7: C2 ≈ 448 B; C3 Binding ≈ 896 B; C3 +/# ≈ 1344 B.

## Comparing to CRYPTOLOGY 2026 Table 3

Original paper phases:

- `preprocess` ≈ all `spp_preprocess` + `build_leader_request`
- `signing` ≈ `partial_sign` loop only

This study:

- `precomputation_time_ms` ≈ offline share of preprocess work (C2/C3)
- `online_signing_time_ms` ≈ remaining preprocess + LR + signing

State this boundary difference explicitly in thesis writing.

## Memory column

`memory_bytes` is process RSS sampled via `ps`. Treat it as secondary / noisy.
Prefer `precomputed_storage_bytes` for the storage axis of the trade-off.
