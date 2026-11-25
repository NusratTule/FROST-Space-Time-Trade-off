//! Space–time precomputation benchmark harness.
//!
//! Timer boundaries (research-critical):
//! - precomputation_time_ms: offline generation of retained material ONLY
//! - online_signing_time_ms: consume/build tokens → LR → all partial_sign
//!   (excludes DKG, offline precomp, aggregate, verify)
//!
//! Does not redesign FROST; reuses frost2_rust APIs only.

use crate::precomp_store::{NonceCommitmentMaterial, NonceStore, TokenStore};
use crate::token_build::{build_token_c2_online, generate_nonce_material};
use frost2_rust::backend::{ExperimentRng, Ristretto255GroupAdapter};
use frost2_rust::core::{Frost2Core, FrostVariant, PreprocessToken};
use std::collections::BTreeMap;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecompConfig {
    C1None,
    C2Nonces,
    C3NoncesCommitments,
}

impl PrecompConfig {
    pub fn label(self) -> &'static str {
        match self {
            Self::C1None => "C1_none",
            Self::C2Nonces => "C2_nonces",
            Self::C3NoncesCommitments => "C3_nonces_commitments",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::C1None, Self::C2Nonces, Self::C3NoncesCommitments]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchVariant {
    Frost2,
    Frost2Plus,
    Frost2Hash,
}

impl BenchVariant {
    pub fn label(self) -> &'static str {
        match self {
            Self::Frost2 => "Binding",
            Self::Frost2Plus => "FROST2+",
            Self::Frost2Hash => "FROST2#",
        }
    }

    pub fn to_core(self) -> FrostVariant {
        match self {
            Self::Frost2 => FrostVariant::Frost2,
            Self::Frost2Plus => FrostVariant::Frost2Plus,
            Self::Frost2Hash => FrostVariant::Frost2Hash,
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Frost2, Self::Frost2Plus, Self::Frost2Hash]
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "frost2" | "binding" | "frost1" => Some(Self::Frost2),
            "frost2plus" | "frost2+" | "plus" => Some(Self::Frost2Plus),
            "frost2hash" | "frost2#" | "hash" => Some(Self::Frost2Hash),
            "all" => None,
            _ => None,
        }
    }
}

pub struct TrialResult {
    pub precomputation_time_ms: f64,
    pub online_signing_time_ms: f64,
    pub precomputed_storage_bytes: usize,
    pub memory_bytes: u64,
    pub ok: bool,
}

pub fn ms(dt_secs: f64) -> f64 {
    dt_secs * 1000.0
}

/// Process RSS in bytes via macOS/Linux `ps` (coarse; not allocator-precise).
pub fn process_rss_bytes() -> u64 {
    let pid = std::process::id();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output();
    match out {
        Ok(o) => {
            let kb = String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .unwrap_or(0);
            kb.saturating_mul(1024)
        }
        Err(_) => 0,
    }
}

pub fn mean_median_std(vals: &[f64]) -> (f64, f64, f64) {
    if vals.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    if vals.len() == 1 {
        return (vals[0], vals[0], 0.0);
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    let mut sorted = vals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2]
    } else {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    };
    let variance = vals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
    (mean, median, variance.sqrt())
}

/// Run one trial for one configuration and variant. Does not alter FROST math.
pub fn run_one(
    config: PrecompConfig,
    variant: BenchVariant,
    n: u32,
    t: u32,
    alpha: u32,
    message: &[u8],
    seed: u64,
) -> TrialResult {
    let group = Ristretto255GroupAdapter;
    let core = Frost2Core::new(group, variant.to_core());
    let mut rng = ExperimentRng::new(Some(seed));

    // Keygen and participant selection are outside Study C timing (fairness vs prior work).
    let (signer_states, y) = core.keygen_dkg(n, t, &mut rng, "SPACETIME-DKG");
    let population: Vec<u32> = (1..=n).collect();
    let mut s_ids = rng.sample(&population, alpha as usize);
    s_ids.sort_unstable();

    let mut nonce_store = NonceStore::new();
    let mut token_store = TokenStore::new();

    // ----- OFFLINE PRECOMPUTATION (timed separately) -----
    let (precomputation_time_ms, precomputed_storage_bytes) = match config {
        PrecompConfig::C1None => (0.0, 0usize),
        PrecompConfig::C2Nonces => {
            let t_pre = Instant::now();
            for &sid in &s_ids {
                nonce_store.insert(sid, generate_nonce_material(&mut rng));
            }
            (
                ms(t_pre.elapsed().as_secs_f64()),
                nonce_store.retained_storage_bytes(),
            )
        }
        PrecompConfig::C3NoncesCommitments => {
            let t_pre = Instant::now();
            for &sid in &s_ids {
                let tok = core.spp_preprocess(signer_states.get(&sid).unwrap(), &mut rng);
                token_store.insert(sid, NonceCommitmentMaterial::from_token(tok));
            }
            (
                ms(t_pre.elapsed().as_secs_f64()),
                token_store.retained_storage_bytes(),
            )
        }
    };

    // ----- ONLINE SIGNING (must NOT include offline precomputation) -----
    let t_online = Instant::now();
    let mut tokens: BTreeMap<u32, PreprocessToken> = BTreeMap::new();

    match config {
        PrecompConfig::C1None => {
            for &sid in &s_ids {
                tokens.insert(
                    sid,
                    core.spp_preprocess(signer_states.get(&sid).unwrap(), &mut rng),
                );
            }
        }
        PrecompConfig::C2Nonces => {
            for &sid in &s_ids {
                let nm = nonce_store
                    .consume(sid)
                    .expect("C2: precomputed nonce must exist and be unused");
                tokens.insert(
                    sid,
                    build_token_c2_online(
                        &group,
                        variant.to_core(),
                        signer_states.get(&sid).unwrap(),
                        nm,
                        &mut rng,
                    ),
                );
            }
        }
        PrecompConfig::C3NoncesCommitments => {
            for &sid in &s_ids {
                let mat = token_store
                    .consume(sid)
                    .expect("C3: precomputed token must exist and be unused");
                tokens.insert(sid, mat.into_token());
            }
        }
    }

    let lr = core.build_leader_request(message, &s_ids, &tokens);
    let mut partials = Vec::new();
    for &sid in &s_ids {
        let ps = core.partial_sign(
            signer_states.get(&sid).unwrap(),
            tokens.get(&sid).unwrap(),
            &y,
            &lr,
        );
        partials.push(ps);
    }
    let online_signing_time_ms = ms(t_online.elapsed().as_secs_f64());

    // Correctness check outside online timer.
    let sig = core.aggregate(&y, &lr, &partials);
    let ok = core.verify(&y, &sig, message);

    debug_assert!(nonce_store.is_empty());
    debug_assert!(token_store.is_empty());

    TrialResult {
        precomputation_time_ms,
        online_signing_time_ms,
        precomputed_storage_bytes,
        memory_bytes: process_rss_bytes(),
        ok,
    }
}
