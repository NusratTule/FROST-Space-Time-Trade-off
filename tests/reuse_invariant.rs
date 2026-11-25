//! Integration tests: single-use nonce material and end-to-end C1/C2/C3 correctness.

use curve25519_dalek::scalar::Scalar;
use space_time_tradeoff::benchmark::{run_one, BenchVariant, PrecompConfig};
use space_time_tradeoff::precomp_store::{NonceMaterial, NonceStore, PrecompStoreError, TokenStore};
use space_time_tradeoff::precomp_store::NonceCommitmentMaterial;

#[test]
fn consumed_nonce_cannot_be_reused() {
    let mut store = NonceStore::new();
    store.insert(
        1,
        NonceMaterial {
            d: Scalar::from(1u64),
            s_scalar: Scalar::from(2u64),
        },
    );
    assert!(store.consume(1).is_ok());
    assert_eq!(store.consume(1).unwrap_err(), PrecompStoreError::MissingEntry(1));
}

#[test]
fn consumed_token_cannot_be_reused() {
    let mut store = TokenStore::new();
    store.insert(
        7,
        NonceCommitmentMaterial {
            d: Scalar::from(3u64),
            s_scalar: Scalar::from(4u64),
            r: [9u8; 32],
            s: [8u8; 32],
            u: None,
            v: None,
        },
    );
    assert!(store.consume(7).is_ok());
    assert!(store.consume(7).is_err());
}

#[test]
fn run_one_all_configs_binding_verifies() {
    let message = b"integration-binding";
    for config in PrecompConfig::all() {
        let r = run_one(config, BenchVariant::Frost2, 10, 5, 5, message, 42);
        assert!(r.ok, "config {:?} failed verify", config);
        match config {
            PrecompConfig::C1None => assert_eq!(r.precomputed_storage_bytes, 0),
            PrecompConfig::C2Nonces => assert_eq!(r.precomputed_storage_bytes, 5 * 64),
            PrecompConfig::C3NoncesCommitments => assert_eq!(r.precomputed_storage_bytes, 5 * 128),
        }
    }
}

#[test]
fn run_one_c3_frost2plus_storage_192_per_signer() {
    let r = run_one(
        PrecompConfig::C3NoncesCommitments,
        BenchVariant::Frost2Plus,
        10,
        5,
        5,
        b"plus-storage",
        7,
    );
    assert!(r.ok);
    assert_eq!(r.precomputed_storage_bytes, 5 * 192);
}

#[test]
fn run_one_c3_frost2hash_verifies() {
    let r = run_one(
        PrecompConfig::C3NoncesCommitments,
        BenchVariant::Frost2Hash,
        10,
        5,
        5,
        b"hash-c3",
        9,
    );
    assert!(r.ok);
}
