//! CSV trial and summary writers for the space–time experiment.

use crate::benchmark::{mean_median_std, BenchVariant, PrecompConfig, TrialResult};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub struct SummaryRow {
    pub configuration: String,
    pub n: u32,
    pub t: u32,
    pub alpha: u32,
    pub variant: String,
    pub trials: usize,
    pub seed: u64,
    pub precomp_ms_mean: f64,
    pub precomp_ms_median: f64,
    pub precomp_ms_std: f64,
    pub online_ms_mean: f64,
    pub online_ms_median: f64,
    pub online_ms_std: f64,
    pub precomputed_storage_bytes: usize,
    pub storage_kb: f64,
    pub memory_bytes_mean: f64,
    pub ok_all: bool,
}

pub fn write_trial_header(w: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        w,
        "configuration,n,t,alpha,variant,trial,precomputation_time_ms,online_signing_time_ms,precomputed_storage_bytes,memory_bytes,ok"
    )
}

pub fn write_trial_row(
    w: &mut impl Write,
    config: PrecompConfig,
    variant: BenchVariant,
    n: u32,
    t: u32,
    alpha: u32,
    trial: usize,
    r: &TrialResult,
) -> std::io::Result<()> {
    writeln!(
        w,
        "{},{},{},{},{},{},{:.6},{:.6},{},{},{}",
        config.label(),
        n,
        t,
        alpha,
        variant.label(),
        trial,
        r.precomputation_time_ms,
        r.online_signing_time_ms,
        r.precomputed_storage_bytes,
        r.memory_bytes,
        r.ok
    )
}

pub fn write_summary_header(w: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        w,
        "configuration,n,t,alpha,variant,trials,seed,precomp_ms_mean,precomp_ms_median,precomp_ms_std,online_ms_mean,online_ms_median,online_ms_std,precomputed_storage_bytes,storage_kb,memory_bytes_mean,ok_all"
    )
}

pub fn summarize(
    config: PrecompConfig,
    variant: BenchVariant,
    n: u32,
    t: u32,
    alpha: u32,
    trials: usize,
    seed: u64,
    pre_times: &[f64],
    online_times: &[f64],
    mem_vals: &[f64],
    storage: usize,
    ok_all: bool,
) -> SummaryRow {
    let (pm, pmed, ps) = mean_median_std(pre_times);
    let (om, omed, os) = mean_median_std(online_times);
    let (mm, _, _) = mean_median_std(mem_vals);
    SummaryRow {
        configuration: config.label().to_string(),
        n,
        t,
        alpha,
        variant: variant.label().to_string(),
        trials,
        seed,
        precomp_ms_mean: pm,
        precomp_ms_median: pmed,
        precomp_ms_std: ps,
        online_ms_mean: om,
        online_ms_median: omed,
        online_ms_std: os,
        precomputed_storage_bytes: storage,
        storage_kb: storage as f64 / 1024.0,
        memory_bytes_mean: mm,
        ok_all,
    }
}

pub fn write_summary_row(w: &mut impl Write, s: &SummaryRow) -> std::io::Result<()> {
    writeln!(
        w,
        "{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{:.6},{:.0},{}",
        s.configuration,
        s.n,
        s.t,
        s.alpha,
        s.variant,
        s.trials,
        s.seed,
        s.precomp_ms_mean,
        s.precomp_ms_median,
        s.precomp_ms_std,
        s.online_ms_mean,
        s.online_ms_median,
        s.online_ms_std,
        s.precomputed_storage_bytes,
        s.storage_kb,
        s.memory_bytes_mean,
        s.ok_all
    )
}

pub fn open_csv(path: &Path) -> std::io::Result<BufWriter<File>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(BufWriter::new(File::create(path)?))
}
