//! Single-use precomputation stores for the space–time trade-off study.
//!
//! Security rule: secret nonce material is GENERATED → STORED → CONSUMED ONCE → REMOVED.
//! Public commitment material is stored alongside secrets for C3 only.
//!
//! This module does not alter FROST mathematics; it only controls WHEN existing
//! values are produced and how they are retained.

use curve25519_dalek::scalar::Scalar;
use frost2_rust::backend::GroupPoint;
use frost2_rust::core::PreprocessToken;
use std::collections::BTreeMap;

/// Secret nonce pair only (C2). Never reuse after consume.
#[derive(Clone, Debug)]
pub struct NonceMaterial {
    pub d: Scalar,
    pub s_scalar: Scalar,
}

impl NonceMaterial {
    pub fn storage_bytes() -> usize {
        // Two 32-byte scalars (canonical encoding size).
        64
    }
}

/// Nonce + commitment material (C3). Includes optional auth fields for FROST-2+ / FROST-2#.
#[derive(Clone, Debug)]
pub struct NonceCommitmentMaterial {
    pub d: Scalar,
    pub s_scalar: Scalar,
    pub r: GroupPoint,
    pub s: GroupPoint,
    pub u: Option<Scalar>,
    pub v: Option<GroupPoint>,
}

impl NonceCommitmentMaterial {
    /// Encoding size for this retained entry (secrets + public commitments + optional auth).
    pub fn storage_bytes(&self) -> usize {
        let mut n = 128; // d + s_scalar + r + s
        if self.u.is_some() {
            n += 32;
        }
        if self.v.is_some() {
            n += 32;
        }
        n
    }

    pub fn from_token(tok: PreprocessToken) -> Self {
        Self {
            d: tok.d,
            s_scalar: tok.s_scalar,
            r: tok.r,
            s: tok.s,
            u: tok.u,
            v: tok.v,
        }
    }

    pub fn into_token(self) -> PreprocessToken {
        PreprocessToken {
            r: self.r,
            s: self.s,
            d: self.d,
            s_scalar: self.s_scalar,
            u: self.u,
            v: self.v,
        }
    }
}

/// Error when material is missing or already consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecompStoreError {
    MissingEntry(u32),
    AlreadyConsumed(u32),
}

impl std::fmt::Display for PrecompStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEntry(id) => write!(f, "no precomputed entry for signer {id}"),
            Self::AlreadyConsumed(id) => {
                write!(f, "precomputed entry for signer {id} already consumed")
            }
        }
    }
}

impl std::error::Error for PrecompStoreError {}

/// One-time store for C2 nonce material.
pub struct NonceStore {
    entries: BTreeMap<u32, Option<NonceMaterial>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, signer_id: u32, material: NonceMaterial) {
        self.entries.insert(signer_id, Some(material));
    }

    /// Consume and remove secret nonce material. Second call fails.
    pub fn consume(&mut self, signer_id: u32) -> Result<NonceMaterial, PrecompStoreError> {
        match self.entries.get_mut(&signer_id) {
            None => Err(PrecompStoreError::MissingEntry(signer_id)),
            Some(slot) => match slot.take() {
                Some(m) => {
                    self.entries.remove(&signer_id);
                    Ok(m)
                }
                None => Err(PrecompStoreError::AlreadyConsumed(signer_id)),
            },
        }
    }

    pub fn retained_storage_bytes(&self) -> usize {
        self.entries
            .values()
            .filter(|v| v.is_some())
            .count()
            * NonceMaterial::storage_bytes()
    }

    pub fn len(&self) -> usize {
        self.entries.values().filter(|v| v.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One-time store for C3 nonce+commitment material.
pub struct TokenStore {
    entries: BTreeMap<u32, Option<NonceCommitmentMaterial>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, signer_id: u32, material: NonceCommitmentMaterial) {
        self.entries.insert(signer_id, Some(material));
    }

    pub fn consume(
        &mut self,
        signer_id: u32,
    ) -> Result<NonceCommitmentMaterial, PrecompStoreError> {
        match self.entries.get_mut(&signer_id) {
            None => Err(PrecompStoreError::MissingEntry(signer_id)),
            Some(slot) => match slot.take() {
                Some(m) => {
                    self.entries.remove(&signer_id);
                    Ok(m)
                }
                None => Err(PrecompStoreError::AlreadyConsumed(signer_id)),
            },
        }
    }

    pub fn retained_storage_bytes(&self) -> usize {
        self.entries
            .values()
            .filter_map(|v| v.as_ref())
            .map(|m| m.storage_bytes())
            .sum()
    }

    pub fn len(&self) -> usize {
        self.entries.values().filter(|v| v.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;

    fn dummy_nonce() -> NonceMaterial {
        NonceMaterial {
            d: Scalar::from(7u64),
            s_scalar: Scalar::from(11u64),
        }
    }

    fn dummy_token_mat() -> NonceCommitmentMaterial {
        NonceCommitmentMaterial {
            d: Scalar::from(3u64),
            s_scalar: Scalar::from(5u64),
            r: [1u8; 32],
            s: [2u8; 32],
            u: None,
            v: None,
        }
    }

    fn dummy_token_mat_auth() -> NonceCommitmentMaterial {
        NonceCommitmentMaterial {
            d: Scalar::from(3u64),
            s_scalar: Scalar::from(5u64),
            r: [1u8; 32],
            s: [2u8; 32],
            u: Some(Scalar::from(9u64)),
            v: Some([3u8; 32]),
        }
    }

    #[test]
    fn nonce_store_consume_once_ok() {
        let mut store = NonceStore::new();
        store.insert(1, dummy_nonce());
        assert_eq!(store.retained_storage_bytes(), 64);
        let m = store.consume(1).expect("first consume");
        assert_eq!(m.d, Scalar::from(7u64));
        assert!(store.is_empty());
        assert_eq!(store.retained_storage_bytes(), 0);
    }

    #[test]
    fn nonce_store_rejects_reuse() {
        let mut store = NonceStore::new();
        store.insert(2, dummy_nonce());
        store.consume(2).unwrap();
        let err = store.consume(2).unwrap_err();
        assert_eq!(err, PrecompStoreError::MissingEntry(2));
    }

    #[test]
    fn token_store_rejects_reuse() {
        let mut store = TokenStore::new();
        store.insert(3, dummy_token_mat());
        assert_eq!(store.retained_storage_bytes(), 128);
        let _ = store.consume(3).unwrap();
        assert!(store.consume(3).is_err());
        assert_eq!(store.retained_storage_bytes(), 0);
    }

    #[test]
    fn token_store_auth_fields_sized_192() {
        let mut store = TokenStore::new();
        store.insert(4, dummy_token_mat_auth());
        assert_eq!(store.retained_storage_bytes(), 192);
    }

    #[test]
    fn missing_entry_errors() {
        let mut store = NonceStore::new();
        assert_eq!(
            store.consume(99).unwrap_err(),
            PrecompStoreError::MissingEntry(99)
        );
    }
}
