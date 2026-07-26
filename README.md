# groth16_verifier

`groth16_verifier` is a reusable on-chain Groth16 verifier for Soroban using the
Stellar host's BLS12-381 operations. ConfiBatch deploys one verifier instance
per circuit/verifying key and stores that contract address in
`confibatch_pool`.

This repository is the standalone build of the latest contract implementation.
It targets Soroban SDK `25.3.2`, Rust `1.91`, and Apache-2.0.

## Verification equation

For public inputs `x[0..n)`, the verifier calculates:

```text
vk_x = IC[0] + Σ x[i] × IC[i + 1]
```

It then checks the Groth16 equation as one host multi-pairing:

```text
e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) = 1
```

The implementation uses the native `g1_msm` host operation for the input
linear combination.

## Data types

### `VerifyingKey`

```rust
pub struct VerifyingKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: Vec<G1Affine>,
}
```

The invariant is:

```text
ic.len() = public_inputs.len() + 1
```

### `Proof`

```rust
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}
```

For byte-oriented callers, `decode_proof` accepts exactly 384 bytes:

```text
a: uncompressed G1,  96 bytes
b: uncompressed G2, 192 bytes
c: uncompressed G1,  96 bytes
```

The byte order and point encoding must match
`soroban_sdk::crypto::bls12_381::{G1Affine,G2Affine}`.

## Public-input encoding

Each public input is a `BytesN<32>` containing one BLS12-381 scalar-field
element in canonical big-endian form.

The verifier rejects a value greater than or equal to:

```text
0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Inputs are not reduced modulo the field. Rejecting non-canonical encodings
prevents multiple byte strings from representing the same scalar.

This contract is circuit-agnostic: it preserves the order supplied by the
caller. The calling pool entrypoint and the circuit's declared public signals
must agree exactly on length, meaning, and order.

## Contract interface

| Function | State | Description |
| --- | --- | --- |
| `init(vk)` | writes instance storage | Stores the verifier instance's one verifying key. A second call returns `AlreadyInitialized`. |
| `vk()` | reads instance storage | Returns the stored verifying key. |
| `verify(proof, public_inputs)` | reads instance storage | Verifies against the stored key. |
| `verify_with(vk, proof, public_inputs)` | stateless | Verifies against a caller-supplied key without reading or writing the stored key. |

The library also exports Rust helpers:

- `verify_with_vk(env, vk, proof, public_inputs)`;
- `decode_proof(env, raw) -> Option<Proof>`; and
- `Groth16VerifierClient`, generated from the public interface.

## Errors

| Code | Name | Meaning |
| ---: | --- | --- |
| 1 | `AlreadyInitialized` | The stored-key initializer was called more than once. |
| 2 | `NotInitialized` | `vk` or stored-key `verify` was called before initialization. |
| 3 | `MalformedVerifyingKey` | `IC` length does not equal public-input length plus one. |
| 4 | `NonCanonicalPublicInput` | At least one public input is outside canonical Fr range. |

Malformed elliptic-curve point encodings are handled by the Soroban host/SDK
point types before or during cryptographic operations.

## Feature flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `export-contract` | yes | Emits the deployable contract and Wasm exports. |

Sibling contract crates should depend on this crate with:

```toml
groth16_verifier = {
  git = "https://github.com/Confihub/groth16_verifier",
  branch = "main",
  default-features = false
}
```

Disabling default features imports the shared types and generated client without
linking a second set of contract Wasm exports into the caller.

## Deployment model

Use a separate verifier contract for every circuit because each instance stores
exactly one immutable verifying key.

Typical ConfiBatch wiring is:

```text
deposit circuit             ──► deposit verifier instance
transfer circuit            ──► transfer verifier instance
withdraw circuit            ──► withdraw verifier instance
withdraw-change circuit     ──► withdraw-change verifier instance
split circuit               ──► split verifier instance
order-spend circuit         ──► order-spend verifier instance
clearing circuits           ──► their own verifier instances
swap commit/claim circuits  ──► their own verifier instances
mobile-v2 append circuit    ──► append verifier instance
```

### Initialization safety

`init` is first-call-wins and has no admin authorization. The contract currently
has no constructor. Deployment automation must therefore initialize the
verifying key immediately, avoid exposing an uninitialized verifier address,
and read `vk()` back before wiring the address into the pool.

The verifying key lives in instance storage and this contract does not expose a
TTL keeper. Operations must monitor archival/TTL behavior and restore or extend
the verifier contract/state according to the target network's Soroban
operational policy.

## Build

Prerequisites:

- Rust `1.91` with the `wasm32v1-none` target;
- Stellar CLI compatible with Soroban SDK 25; and
- network access for the first Cargo dependency fetch.

```bash
rustup target add wasm32v1-none
stellar contract build
```

The optimized Wasm is produced under:

```text
target/wasm32v1-none/release/groth16_verifier.wasm
```

## Tests

The published suite covers initialization and key readback, canonical public
inputs, verifying-key length guards, proof decoding, public-input ordering, and
comparative BLS12-381 host-operation costs.

```bash
cargo +1.91.0 test --locked
```

## Deployment outline

```bash
stellar contract build

stellar contract deploy \
  --wasm target/wasm32v1-none/release/groth16_verifier.wasm \
  --source-account <DEPLOYER> \
  --network <NETWORK>
```

Then marshal the circuit's verified key into the exact Soroban
`VerifyingKey` value, invoke `init`, and confirm:

1. `vk()` returns the same key;
2. a known valid proof returns `true`;
3. a known invalid proof returns `false`;
4. reordered or changed public inputs return `false`; and
5. the pool setter points to this exact contract.

Inspect the generated contract specification for the installed CLI:

```bash
stellar contract info interface \
  --wasm target/wasm32v1-none/release/groth16_verifier.wasm
```

## Operational checklist

- Pin and publish the circuit source, R1CS, proving key, verifying key, and
  ceremony/transcript hashes.
- Confirm the verifier Wasm was produced by the guarded default release build.
- Use one instance per circuit and never reuse a key for a different public
  signal layout.
- Read back the stored key and run positive/negative proof vectors.
- Wire the verifier into the correct pool slot before any irreversible verifier
  or upgrade freeze.
- Monitor contract and instance-storage TTL.
- Record contract IDs, Wasm hashes, key hashes, network passphrase, deployment
  transaction hashes, and wiring transaction hashes.

## Repository contents

```text
src/lib.rs        Contract, types, generated client, and core verifier
Cargo.toml        Standalone Soroban build configuration
Cargo.lock        Reproducible dependency lock
```

## Security and license

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
The source is licensed under the [Apache License 2.0](LICENSE).
