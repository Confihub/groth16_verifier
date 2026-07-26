//! Tests for the groth16_verifier.
//!
//! Producing a circuit-derived proof requires its circuit artifacts and
//! ceremony output, which are intentionally outside this standalone contract
//! crate. The suite still exercises the real pairing path with a
//! self-consistent degenerate instance to lock public-input ordering.

use super::*;
use soroban_sdk::{BytesN, Env};

/// Placeholder bytes used only by storage and pre-pairing error-path tests.
fn dummy_g1(env: &Env) -> G1Affine {
    G1Affine::from_array(env, &[0u8; 96])
}

fn dummy_g2(env: &Env) -> G2Affine {
    G2Affine::from_array(env, &[0u8; 192])
}

/// vk whose `ic` length matches `n_public + 1`.
fn vk_for(env: &Env, n_public: u32) -> VerifyingKey {
    let mut ic = Vec::new(env);
    for _ in 0..(n_public + 1) {
        ic.push_back(dummy_g1(env));
    }
    VerifyingKey {
        alpha: dummy_g1(env),
        beta: dummy_g2(env),
        gamma: dummy_g2(env),
        delta: dummy_g2(env),
        ic,
    }
}

#[test]
fn public_input_encoding_must_be_canonical() {
    let env = Env::default();
    let zero = BytesN::from_array(&env, &[0u8; 32]);
    let modulus = BytesN::from_array(&env, &FR_MODULUS);
    let mut below = FR_MODULUS;
    below[31] -= 1;
    let below = BytesN::from_array(&env, &below);

    assert!(is_canonical_fr(&zero));
    assert!(is_canonical_fr(&below));
    assert!(!is_canonical_fr(&modulus));
}

fn dummy_proof(env: &Env) -> Proof {
    Proof {
        a: dummy_g1(env),
        b: dummy_g2(env),
        c: dummy_g1(env),
    }
}

/// A representative nine-element public-input vector.
fn nine_inputs(env: &Env) -> Vec<BytesN<32>> {
    let mut v = Vec::new(env);
    for i in 0..9u8 {
        v.push_back(BytesN::from_array(env, &[i; 32]));
    }
    v
}

#[test]
fn init_is_idempotent() {
    let env = Env::default();
    let id = env.register(Groth16Verifier, ());
    let client = Groth16VerifierClient::new(&env, &id);

    let vk = vk_for(&env, 9);
    client.init(&vk);

    // Second init must error AlreadyInitialized.
    let res = client.try_init(&vk);
    assert_eq!(res, Err(Ok(Groth16Error::AlreadyInitialized)));
}

#[test]
fn verify_before_init_errors() {
    let env = Env::default();
    let id = env.register(Groth16Verifier, ());
    let client = Groth16VerifierClient::new(&env, &id);

    let res = client.try_verify(&dummy_proof(&env), &nine_inputs(&env));
    assert_eq!(res, Err(Ok(Groth16Error::NotInitialized)));
}

#[test]
fn vk_roundtrips() {
    let env = Env::default();
    let id = env.register(Groth16Verifier, ());
    let client = Groth16VerifierClient::new(&env, &id);

    let vk = vk_for(&env, 9);
    client.init(&vk);
    assert_eq!(client.vk().ic.len(), 10); // 9 public inputs + 1
}

#[test]
fn malformed_vk_is_rejected() {
    // ic length must equal n_public + 1. Here vk has 6 public-slots but we feed
    // 9 inputs -> mismatch.
    let env = Env::default();
    let id = env.register(Groth16Verifier, ());
    let client = Groth16VerifierClient::new(&env, &id);

    let vk = vk_for(&env, 5); // ic.len() == 6
    client.init(&vk);

    let res = client.try_verify(&dummy_proof(&env), &nine_inputs(&env));
    assert_eq!(res, Err(Ok(Groth16Error::MalformedVerifyingKey)));
}

/// Negative test: reordering two public inputs must break verification.
///
/// We can't run the real-pairing happy path with a circuit-derived proof
/// in-crate (see the module header), but the order-dependent part of the
/// equation — `vk_x = ic[0] + Σ public_inputs[i]·ic[i+1]` — is reachable on
/// its own. We hand-build a *self-consistent* degenerate instance: every
/// other pairing term is the identity, so the whole check reduces to
/// `e(vk_x, gamma) == 1`, which holds iff `vk_x` is the identity point.
///
/// With `ic[1] = H`, `ic[2] = 2H` and inputs `[−2, 1]`, `vk_x = (−2 + 2·1)H`
/// = identity, so the *correct* order verifies. Swapping the two inputs gives
/// `vk_x = (1 − 4)H ≠ identity`, so the *reordered* order must fail. This
/// locks the order-dependent `vk_x` binding against accidental circuit/contract
/// drift in the public-input layout.
#[test]
fn reordered_public_inputs_break_verification() {
    use soroban_sdk::{crypto::bls12_381::Fr, vec, Bytes};

    let env = Env::default();
    let id = env.register(Groth16Verifier, ());
    let client = Groth16VerifierClient::new(&env, &id);
    let bls = env.crypto().bls12_381();
    let dst = Bytes::from_slice(&env, b"CONFIBATCH-TEST");

    // Encodings of the point at infinity (identity): flag bit 1 set, rest zero.
    let mut g1_inf = [0u8; 96];
    g1_inf[0] = 0x40;
    let mut g2_inf = [0u8; 192];
    g2_inf[0] = 0x40;
    let g1_inf = G1Affine::from_array(&env, &g1_inf);
    let g2_inf = G2Affine::from_array(&env, &g2_inf);

    // Distinct, valid ic points: ic[1] = H, ic[2] = 2H (so input order matters).
    let h = bls.hash_to_g1(&Bytes::from_slice(&env, b"ic-base"), &dst);
    let two = Fr::from_bytes(BytesN::from_array(&env, &fr_be_small(2)));
    let two_h = bls.g1_mul(&h, &two);
    // gamma must be a non-degenerate G2 so e(vk_x, gamma) == 1 iff vk_x == inf.
    let gamma = bls.hash_to_g2(&Bytes::from_slice(&env, b"gamma"), &dst);

    // Scalars chosen so the CORRECT order cancels: (-2)·H + 1·(2H) = identity.
    let one = Fr::from_bytes(BytesN::from_array(&env, &fr_be_small(1)));
    let neg_two = bls.fr_sub(&bls.fr_sub(&one, &one), &two); // 0 - 2 = -2 (mod r)
    let a: BytesN<32> = neg_two.to_bytes();
    let b: BytesN<32> = one.to_bytes();

    // Every term except e(vk_x, gamma) is the identity pairing (1).
    let vk = VerifyingKey {
        alpha: g1_inf.clone(),
        beta: g2_inf.clone(),
        gamma,
        delta: g2_inf.clone(),
        ic: vec![&env, g1_inf.clone(), h, two_h],
    };
    client.init(&vk);
    let proof = Proof {
        a: g1_inf.clone(),
        b: g2_inf.clone(),
        c: g1_inf,
    };

    let correct = vec![&env, a.clone(), b.clone()];
    let reordered = vec![&env, b, a]; // same multiset, swapped positions

    assert_eq!(client.try_verify(&proof, &correct), Ok(Ok(true)));
    assert_eq!(client.try_verify(&proof, &reordered), Ok(Ok(false)));
}

/// Big-endian 32-byte encoding of a small `u8` scalar (for `Fr::from_bytes`).
fn fr_be_small(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = n;
    b
}

#[test]
fn decode_proof_rejects_wrong_length() {
    let env = Env::default();
    let bad = Bytes::from_array(&env, &[0u8; 10]);
    assert!(decode_proof(&env, &bad).is_none());
}

#[test]
fn decode_proof_accepts_384_bytes() {
    let env = Env::default();
    let raw = Bytes::from_array(&env, &[0u8; 384]);
    assert!(decode_proof(&env, &raw).is_some());
}
