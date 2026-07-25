#![no_std]
//! # groth16_verifier
//!
//! On-chain Groth16 (BLS12-381) verifier for ConfiSwap, adapted from the
//! official `stellar/soroban-examples/groth16_verifier`:
//!
//! - `init(vk: VerifyingKey)` — store a verifying key in instance storage.
//! - `verify(proof: Proof, public_inputs: Vec<BytesN<32>>)` — a single
//!   `pairing_check` (multi-pairing) over the BLS12-381 host functions.
//!
//! Public inputs are canonical 32-byte big-endian scalar-field elements. Their
//! order and count are defined by the verifying key and calling contract.
//!
//! ## Crate layout (avoiding duplicate wasm exports)
//! The cross-contract client is generated from the `#[contractclient]` trait
//! `Groth16VerifierInterface` (-> `Groth16VerifierClient`). The deployable
//! contract's wasm export functions are emitted only when the default
//! `export-contract` feature is on. Sibling crates depend with
//! `default-features = false`, so they import the types and client without pulling
//! the `init`/`verify` export symbols (which would collide at link time).

use soroban_sdk::{
    contractclient, contracterror, contracttype,
    crypto::bls12_381::{G1Affine, G2Affine},
    crypto::bls12_381::Fr, vec, Bytes, BytesN, Env, Vec,
};

/// Instance-storage key for the stored verifying key.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    Vk,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Groth16Error {
    /// `init` called more than once.
    AlreadyInitialized = 1,
    /// `verify` called before `init`.
    NotInitialized = 2,
    /// `public_inputs.len() + 1 != vk.ic.len()` — vk does not match the
    /// number of public signals supplied.
    MalformedVerifyingKey = 3,
    /// A public input is not the canonical big-endian encoding of an Fr
    /// element. Reject instead of allowing `Fr::from_bytes` to reduce it.
    NonCanonicalPublicInput = 4,
}

// BLS12-381 scalar-field modulus r, big-endian.
const FR_MODULUS: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

fn is_canonical_fr(input: &BytesN<32>) -> bool {
    let bytes = input.to_array();
    for i in 0..32 {
        if bytes[i] < FR_MODULUS[i] { return true; }
        if bytes[i] > FR_MODULUS[i] { return false; }
    }
    false // equal to the modulus is zero modulo r, but is not canonical zero
}

/// Groth16 verifying key. Field/point layout matches snarkjs's `verification_key.json`
/// when serialized to uncompressed BLS12-381 points:
/// - `alpha` ∈ G1 (BytesN<96>), `beta`/`gamma`/`delta` ∈ G2 (BytesN<192>).
/// - `ic` is the input-commitment vector; `ic.len() == num_public_inputs + 1`.
///
/// Point byte order is the SDK uncompressed encoding used by
/// `G1Affine::from_bytes` and `G2Affine::from_bytes`.
#[derive(Clone)]
#[contracttype]
pub struct VerifyingKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: Vec<G1Affine>,
}

/// Groth16 proof: `a, c ∈ G1`, `b ∈ G2`.
#[derive(Clone)]
#[contracttype]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

/// Contract interface. `#[contractclient]` generates `Groth16VerifierClient`,
/// used by sibling contracts for cross-contract verification without linking
/// this contract's export symbols.
#[contractclient(name = "Groth16VerifierClient")]
pub trait Groth16VerifierInterface {
    fn init(env: Env, vk: VerifyingKey) -> Result<(), Groth16Error>;
    fn vk(env: Env) -> Result<VerifyingKey, Groth16Error>;
    fn verify(
        env: Env,
        proof: Proof,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, Groth16Error>;
    fn verify_with(
        env: Env,
        vk: VerifyingKey,
        proof: Proof,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, Groth16Error>;
}

// The deployable contract + its wasm exports. Emitted only for the standalone
// build (default `export-contract` feature). See crate-layout note above.
#[cfg(feature = "export-contract")]
mod contract {
    use super::*;
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    pub struct Groth16Verifier;

    #[contractimpl]
    impl Groth16VerifierInterface for Groth16Verifier {
        /// Store the verifying key. Idempotent: a second call errors.
        fn init(env: Env, vk: VerifyingKey) -> Result<(), Groth16Error> {
            if env.storage().instance().has(&DataKey::Vk) {
                return Err(Groth16Error::AlreadyInitialized);
            }
            env.storage().instance().set(&DataKey::Vk, &vk);
            Ok(())
        }

        /// Read back the stored verifying key.
        fn vk(env: Env) -> Result<VerifyingKey, Groth16Error> {
            env.storage()
                .instance()
                .get(&DataKey::Vk)
                .ok_or(Groth16Error::NotInitialized)
        }

        /// Verify `proof` against `public_inputs` using the stored vk.
        fn verify(
            env: Env,
            proof: Proof,
            public_inputs: Vec<BytesN<32>>,
        ) -> Result<bool, Groth16Error> {
            let vk: VerifyingKey = env
                .storage()
                .instance()
                .get(&DataKey::Vk)
                .ok_or(Groth16Error::NotInitialized)?;
            verify_with_vk(&env, &vk, &proof, &public_inputs)
        }

        /// Stateless variant: verify against a caller-supplied vk.
        fn verify_with(
            env: Env,
            vk: VerifyingKey,
            proof: Proof,
            public_inputs: Vec<BytesN<32>>,
        ) -> Result<bool, Groth16Error> {
            verify_with_vk(&env, &vk, &proof, &public_inputs)
        }
    }
}

#[cfg(feature = "export-contract")]
pub use contract::{Groth16Verifier, Groth16VerifierArgs};

/// Core Groth16 check, shared by the stored-vk and inline-vk entry points.
pub fn verify_with_vk(
    env: &Env,
    vk: &VerifyingKey,
    proof: &Proof,
    public_inputs: &Vec<BytesN<32>>,
) -> Result<bool, Groth16Error> {
    // `ic[0]` is the constant term, followed by one point per public input.
    if public_inputs.len() + 1 != vk.ic.len() {
        return Err(Groth16Error::MalformedVerifyingKey);
    }
    for input in public_inputs.iter() {
        if !is_canonical_fr(&input) {
            return Err(Groth16Error::NonCanonicalPublicInput);
        }
    }

    let bls = env.crypto().bls12_381();

    // vk_x = ic[0] + Σ_i public_inputs[i] · ic[i+1].
    let ic0 = vk.ic.get(0).unwrap();
    let mut ic_tail: Vec<G1Affine> = Vec::new(env);
    let mut scalars: Vec<Fr> = Vec::new(env);
    for (input_be, ic_point) in public_inputs.iter().zip(vk.ic.iter().skip(1)) {
        ic_tail.push_back(ic_point);
        scalars.push_back(Fr::from_bytes(input_be));
    }
    let vk_x = if scalars.is_empty() {
        ic0
    } else {
        bls.g1_add(&ic0, &bls.g1_msm(ic_tail, scalars))
    };

    // Groth16 pairing equation, batched into one multi-pairing check:
    //   e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
    let neg_a = -proof.a.clone();
    let g1s = vec![env, neg_a, vk.alpha.clone(), vk_x, proof.c.clone()];
    let g2s = vec![
        env,
        proof.b.clone(),
        vk.beta.clone(),
        vk.gamma.clone(),
        vk.delta.clone(),
    ];

    Ok(bls.pairing_check(g1s, g2s))
}

/// Helper exposed for sibling crates: decode a serialized Groth16 proof.
/// ConfiSwap passes proofs around as `Bytes` (per the token/swap ABIs);
/// the canonical encoding is the concatenation of the three uncompressed
/// points `a (96) || b (192) || c (96)` = 384 bytes, in SDK byte order.
///
/// Returns `None` if the length is wrong.
pub fn decode_proof(env: &Env, raw: &Bytes) -> Option<Proof> {
    const G1: u32 = 96;
    const G2: u32 = 192;
    if raw.len() != G1 + G2 + G1 {
        return None;
    }
    let a = BytesN::<96>::from_array(env, &slice_96(raw, 0));
    let b = BytesN::<192>::from_array(env, &slice_192(raw, G1));
    let c = BytesN::<96>::from_array(env, &slice_96(raw, G1 + G2));
    Some(Proof {
        a: G1Affine::from_bytes(a),
        b: G2Affine::from_bytes(b),
        c: G1Affine::from_bytes(c),
    })
}

fn slice_96(raw: &Bytes, off: u32) -> [u8; 96] {
    let mut out = [0u8; 96];
    for i in 0..96u32 {
        out[i as usize] = raw.get(off + i).unwrap();
    }
    out
}

fn slice_192(raw: &Bytes, off: u32) -> [u8; 192] {
    let mut out = [0u8; 192];
    for i in 0..192u32 {
        out[i as usize] = raw.get(off + i).unwrap();
    }
    out
}
