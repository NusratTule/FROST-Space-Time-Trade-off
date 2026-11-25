//! Build PreprocessToken for Configuration 2 without modifying frost2_rust::core.
//!
//! Mirrors the post-nonce steps of Frost2Core::spp_preprocess exactly:
//! - Frost2: commitments only (r, s)
//! - Frost2Plus / Frost2Hash: commitments + authenticated (u, v) fields
//!
//! WARNING: This must stay byte-identical to spp_preprocess after (d, s_scalar) exist.
//! Any divergence will fail verify().

use frost2_rust::backend::{int_to_bytes_be, rand_scalar_nonzero, ExperimentRng, Ristretto255GroupAdapter};
use frost2_rust::core::{FrostVariant, PreprocessToken, SignerState};

use crate::precomp_store::NonceMaterial;

/// Assemble a full PreprocessToken from precomputed secret nonces (C2 online path).
pub fn build_token_c2_online(
    group: &Ristretto255GroupAdapter,
    variant: FrostVariant,
    state: &SignerState,
    nonces: NonceMaterial,
    rng: &mut ExperimentRng,
) -> PreprocessToken {
    let NonceMaterial { d, s_scalar } = nonces;
    let r = group.point_mul_base(&d);
    let s = group.point_mul_base(&s_scalar);

    match variant {
        FrostVariant::Frost2 => PreprocessToken {
            r,
            s,
            d,
            s_scalar,
            u: None,
            v: None,
        },
        FrostVariant::Frost2Plus | FrostVariant::Frost2Hash => {
            // Exact mirror of frost2_rust::core::Frost2Core::spp_preprocess auth block.
            let mut transcript = int_to_bytes_be(state.signer_id as u64, 4);
            transcript.extend_from_slice(&r);
            transcript.extend_from_slice(&s);

            let domain = b"FROST2P_HPP";
            let parts: Vec<&[u8]> = vec![&transcript];
            let e = group.hash_to_scalar_nonzero(domain, &parts);
            let u = rand_scalar_nonzero(rng) + e;
            let v = group.point_mul_base(&u);

            PreprocessToken {
                r,
                s,
                d,
                s_scalar,
                u: Some(u),
                v: Some(v),
            }
        }
    }
}

/// Generate C2 secret nonce material (offline). Message-independent.
pub fn generate_nonce_material(rng: &mut ExperimentRng) -> NonceMaterial {
    NonceMaterial {
        d: rand_scalar_nonzero(rng),
        s_scalar: rand_scalar_nonzero(rng),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost2_rust::core::Frost2Core;

    #[test]
    fn c2_frost2_token_verifies() {
        let group = Ristretto255GroupAdapter;
        let core = Frost2Core::new(group, FrostVariant::Frost2);
        let mut rng = ExperimentRng::new(Some(99));
        let (states, y) = core.keygen_dkg(5, 3, &mut rng, "C2-TEST-DKG");
        let s_ids = vec![1u32, 2, 3];
        let message = b"c2-frost2";
        let mut tokens = std::collections::BTreeMap::new();
        let mut rng2 = ExperimentRng::new(Some(11));
        for &id in &s_ids {
            let st = states.get(&id).unwrap();
            let nm = generate_nonce_material(&mut rng2);
            tokens.insert(
                id,
                build_token_c2_online(&group, FrostVariant::Frost2, st, nm, &mut rng2),
            );
        }
        let lr = core.build_leader_request(message, &s_ids, &tokens);
        let mut partials = Vec::new();
        for &id in &s_ids {
            partials.push(core.partial_sign(states.get(&id).unwrap(), tokens.get(&id).unwrap(), &y, &lr));
        }
        let sig = core.aggregate(&y, &lr, &partials);
        assert!(core.verify(&y, &sig, message));
    }

    #[test]
    fn c2_frost2plus_token_verifies() {
        let group = Ristretto255GroupAdapter;
        let core = Frost2Core::new(group, FrostVariant::Frost2Plus);
        let mut rng = ExperimentRng::new(Some(42));
        let (states, y) = core.keygen_dkg(5, 3, &mut rng, "C2-PLUS-DKG");
        let s_ids = vec![1u32, 2, 3];
        let message = b"c2-plus";
        let mut tokens = std::collections::BTreeMap::new();
        let mut rng2 = ExperimentRng::new(Some(13));
        for &id in &s_ids {
            let st = states.get(&id).unwrap();
            let nm = generate_nonce_material(&mut rng2);
            tokens.insert(
                id,
                build_token_c2_online(&group, FrostVariant::Frost2Plus, st, nm, &mut rng2),
            );
        }
        let lr = core.build_leader_request(message, &s_ids, &tokens);
        let mut partials = Vec::new();
        for &id in &s_ids {
            let tok = tokens.get(&id).unwrap();
            assert!(tok.u.is_some() && tok.v.is_some());
            partials.push(core.partial_sign(states.get(&id).unwrap(), tok, &y, &lr));
        }
        let sig = core.aggregate(&y, &lr, &partials);
        assert!(core.verify(&y, &sig, message));
    }

    #[test]
    fn c2_frost2hash_token_verifies() {
        let group = Ristretto255GroupAdapter;
        let core = Frost2Core::new(group, FrostVariant::Frost2Hash);
        let mut rng = ExperimentRng::new(Some(55));
        let (states, y) = core.keygen_dkg(5, 3, &mut rng, "C2-HASH-DKG");
        let s_ids = vec![1u32, 2, 3];
        let message = b"c2-hash";
        let mut tokens = std::collections::BTreeMap::new();
        let mut rng2 = ExperimentRng::new(Some(17));
        for &id in &s_ids {
            let st = states.get(&id).unwrap();
            let nm = generate_nonce_material(&mut rng2);
            tokens.insert(
                id,
                build_token_c2_online(&group, FrostVariant::Frost2Hash, st, nm, &mut rng2),
            );
        }
        let lr = core.build_leader_request(message, &s_ids, &tokens);
        let mut partials = Vec::new();
        for &id in &s_ids {
            partials.push(core.partial_sign(states.get(&id).unwrap(), tokens.get(&id).unwrap(), &y, &lr));
        }
        let sig = core.aggregate(&y, &lr, &partials);
        assert!(core.verify(&y, &sig, message));
    }
}
