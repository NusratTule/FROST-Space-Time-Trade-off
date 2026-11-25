//! Space–Time Trade-off: FROST precomputation study (C1 / C2 / C3).
//!
//! NEW crate — does not modify frost2_rust core/main/roast.
//! Reuses existing frost2_rust APIs only.
//!
//! Configurations:
//! - C1: no precomputation (nonces + commitments generated online)
//! - C2: precomputed secret nonces only (commitments / auth online)
//! - C3: precomputed nonces + commitments (online = LR + partial signing)
//!
//! Variants: Binding (Frost2), FROST-2+, FROST-2#  (ROAST excluded in v1)

use space_time_tradeoff::benchmark::{run_one, BenchVariant, PrecompConfig};
use space_time_tradeoff::csv_report::{
    open_csv, summarize, write_summary_header, write_summary_row, write_trial_header, write_trial_row,
};
use std::env;
use std::io::Write;
use std::path::PathBuf;

fn parse_args() -> (PathBuf, usize, u64, Option<BenchVariant>) {
    let args: Vec<String> = env::args().collect();
    let mut out = PathBuf::from("output/spacetime_results.csv");
    let mut trials: usize = 30;
    let mut seed: u64 = 42;
    let mut variant_filter: Option<BenchVariant> = None; // None = all
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                out = PathBuf::from(&args[i]);
            }
            "-r" | "--trials" => {
                i += 1;
                trials = args[i].parse().expect("trials");
            }
            "-s" | "--seed" => {
                i += 1;
                seed = args[i].parse().expect("seed");
            }
            "-v" | "--variant" => {
                i += 1;
                let v = &args[i];
                if v.eq_ignore_ascii_case("all") {
                    variant_filter = None;
                } else {
                    variant_filter = Some(
                        BenchVariant::parse(v)
                            .unwrap_or_else(|| panic!("unknown variant: {v}")),
                    );
                }
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: spacetime_bench [-o OUT.csv] [-r TRIALS] [-s SEED] [-v VARIANT]\n\
                     VARIANT: frost2|binding|frost2plus|frost2hash|all (default: all)\n\
                     Space–time precomputation study over Binding / FROST-2+ / FROST-2#."
                );
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    (out, trials, seed, variant_filter)
}

fn main() {
    let (out, trials, seed, variant_filter) = parse_args();
    let summary_path = out.with_file_name("spacetime_summary.csv");

    let message = b"spacetime-precomputation-study";
    let configs = PrecompConfig::all();
    let variants: Vec<BenchVariant> = match variant_filter {
        Some(v) => vec![v],
        None => BenchVariant::all().to_vec(),
    };
    // Same parameter sets as prior FROST runtime study (CRYPTOLOGY 2026).
    let param_sets = [(10u32, 5u32, 5u32), (20, 7, 7), (20, 10, 10)];

    let mut trial_file = open_csv(&out).expect("create results csv");
    write_trial_header(&mut trial_file).unwrap();

    let mut summary_file = open_csv(&summary_path).expect("create summary csv");
    write_summary_header(&mut summary_file).unwrap();

    println!("Space–Time Trade-off — FROST precomputation study");
    println!(
        "arch={} trials={} seed={} message={:?}",
        std::env::consts::ARCH,
        trials,
        seed,
        std::str::from_utf8(message).unwrap_or("?")
    );
    println!(
        "online_signing_time = consume/build tokens + LR + all partial_sign \
         (excludes DKG, precomp, aggregate, verify)"
    );
    println!("variants: {:?}", variants.iter().map(|v| v.label()).collect::<Vec<_>>());
    println!();

    for &(n, t, alpha) in &param_sets {
        for &variant in &variants {
            for &config in &configs {
                let mut pre_times = Vec::with_capacity(trials);
                let mut online_times = Vec::with_capacity(trials);
                let mut mem_vals = Vec::with_capacity(trials);
                let mut storage = 0usize;
                let mut all_ok = true;

                for trial in 0..trials {
                    let trial_seed = seed
                        .wrapping_add((trial as u64) * 1_000_003)
                        .wrapping_add((n as u64) * 17)
                        .wrapping_add((t as u64) * 101)
                        .wrapping_add(match config {
                            PrecompConfig::C1None => 0,
                            PrecompConfig::C2Nonces => 1,
                            PrecompConfig::C3NoncesCommitments => 2,
                        })
                        .wrapping_add(match variant {
                            BenchVariant::Frost2 => 0,
                            BenchVariant::Frost2Plus => 10_000,
                            BenchVariant::Frost2Hash => 20_000,
                        });

                    let r = run_one(config, variant, n, t, alpha, message, trial_seed);
                    if !r.ok {
                        all_ok = false;
                        eprintln!(
                            "VERIFY FAIL: {} {} n={} t={} alpha={} trial={}",
                            config.label(),
                            variant.label(),
                            n,
                            t,
                            alpha,
                            trial
                        );
                    }
                    storage = r.precomputed_storage_bytes;
                    pre_times.push(r.precomputation_time_ms);
                    online_times.push(r.online_signing_time_ms);
                    mem_vals.push(r.memory_bytes as f64);

                    write_trial_row(
                        &mut trial_file,
                        config,
                        variant,
                        n,
                        t,
                        alpha,
                        trial,
                        &r,
                    )
                    .unwrap();
                }

                let s = summarize(
                    config,
                    variant,
                    n,
                    t,
                    alpha,
                    trials,
                    seed,
                    &pre_times,
                    &online_times,
                    &mem_vals,
                    storage,
                    all_ok,
                );
                write_summary_row(&mut summary_file, &s).unwrap();

                println!(
                    "{:<22} {:<10} (n,t,α)=({},{},{})  online_mean={:.4} ms  storage={} B ({:.3} KB)  ok={}",
                    config.label(),
                    variant.label(),
                    n,
                    t,
                    alpha,
                    s.online_ms_mean,
                    s.precomputed_storage_bytes,
                    s.storage_kb,
                    s.ok_all
                );
            }
        }
    }

    trial_file.flush().unwrap();
    summary_file.flush().unwrap();
    println!();
    println!("Wrote trials:  {}", out.display());
    println!("Wrote summary: {}", summary_path.display());
}
