//! Comparative BLS12-381 host-function cost benchmark.
//!
//! The test environment uses the SDK's shipped calibration. These values are
//! useful for detecting major cost-shape regressions, but they are not a
//! substitute for measuring the target network and exact deployment build.
//!
//! Run: `cargo test --test bench_bls -- --nocapture`.

use soroban_sdk::{
    crypto::bls12_381::{Fr, G1Affine, G2Affine},
    Bytes, BytesN, Env, Vec,
};

fn fr(env: &Env, i: u8) -> Fr {
    let mut a = [0u8; 32];
    a[31] = i.wrapping_add(1);
    a[0] = i.wrapping_add(7); // keep it a non-trivial scalar
    Fr::from_bytes(BytesN::from_array(env, &a))
}

#[test]
fn bench_bls_primitives() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited(); // unlimit BEFORE the (expensive) point generation
    let bls = env.crypto().bls12_381();
    let dst = Bytes::from_slice(&env, b"CONFIBATCH-BENCH-DST");

    // Pre-generate VALID curve points (hash-to-curve) OUTSIDE the metered region.
    let g1: std::vec::Vec<G1Affine> = (0..70u8)
        .map(|i| bls.hash_to_g1(&Bytes::from_slice(&env, &[i, 1, 2, 3]), &dst))
        .collect();
    let g2: std::vec::Vec<G2Affine> = (0..70u8)
        .map(|i| bls.hash_to_g2(&Bytes::from_slice(&env, &[i, 9, 8, 7]), &dst))
        .collect();
    let frs: std::vec::Vec<Fr> = (0..70u8).map(|i| fr(&env, i)).collect();

    // measure before/after deltas (budget already unlimited from the top).
    let cpu = || env.cost_estimate().budget().cpu_instruction_cost();
    let meas = |label: &str, f: &dyn Fn()| {
        let a = cpu();
        f();
        let b = cpu();
        std::println!("{:<34} {:>12}", label, b - a);
    };

    std::println!("\n=== BLS12-381 host-fn metered CPU (soroban-sdk test calibration) ===");

    // pairing_check with k pairs (k drives the Groth16 + SnarkPack-batched-pairing cost)
    for k in [1usize, 2, 4, 6, 8] {
        let mut v1 = Vec::new(&env);
        let mut v2 = Vec::new(&env);
        for i in 0..k {
            v1.push_back(g1[i].clone());
            v2.push_back(g2[i].clone());
        }
        meas(&std::format!("pairing_check({} pairs)", k), &|| {
            let _ = bls.pairing_check(v1.clone(), v2.clone());
        });
    }

    // native G1 MSM of size n
    for n in [2usize, 9, 16, 32, 64] {
        let mut vp = Vec::new(&env);
        let mut vs = Vec::new(&env);
        for i in 0..n {
            vp.push_back(g1[i].clone());
            vs.push_back(frs[i].clone());
        }
        meas(&std::format!("g1_msm({})", n), &|| {
            let _ = bls.g1_msm(vp.clone(), vs.clone());
        });
    }
    // native G2 MSM of size n
    for n in [2usize, 16, 32] {
        let mut vp = Vec::new(&env);
        let mut vs = Vec::new(&env);
        for i in 0..n {
            vp.push_back(g2[i].clone());
            vs.push_back(frs[i].clone());
        }
        meas(&std::format!("g2_msm({})", n), &|| {
            let _ = bls.g2_msm(vp.clone(), vs.clone());
        });
    }

    // single ops
    meas("g1_mul x1", &|| {
        let _ = bls.g1_mul(&g1[0], &frs[0]);
    });
    meas("g1_add x1", &|| {
        let _ = bls.g1_add(&g1[0], &g1[1]);
    });

    // Historical manual MSM shape for comparison with the native operation.
    meas("manual MSM(9) = 9x(mul+add)", &|| {
        let mut acc = g1[0].clone();
        for i in 0..9 {
            let t = bls.g1_mul(&g1[i + 1], &frs[i]);
            acc = bls.g1_add(&acc, &t);
        }
        let _ = acc;
    });

    // Historical verify shape: manual MSM(9) + pairing_check(4).
    meas("=> 1 verify OLD (manual MSM9 + pc4)", &|| {
        let mut acc = g1[0].clone();
        for i in 0..9 {
            let t = bls.g1_mul(&g1[i + 1], &frs[i]);
            acc = bls.g1_add(&acc, &t);
        }
        let mut v1 = Vec::new(&env);
        let mut v2 = Vec::new(&env);
        for i in 0..4 {
            v1.push_back(g1[i].clone());
            v2.push_back(g2[i].clone());
        }
        let _ = bls.pairing_check(v1, v2);
    });

    // Current verify shape: native g1_msm(9) + 1 g1_add + pairing_check(4).
    meas("=> 1 verify NEW (g1_msm9 + add + pc4)", &|| {
        let mut vp = Vec::new(&env);
        let mut vs = Vec::new(&env);
        for i in 0..9 {
            vp.push_back(g1[i + 1].clone());
            vs.push_back(frs[i].clone());
        }
        let _vkx = bls.g1_add(&g1[0], &bls.g1_msm(vp, vs));
        let mut v1 = Vec::new(&env);
        let mut v2 = Vec::new(&env);
        for i in 0..4 {
            v1.push_back(g1[i].clone());
            v2.push_back(g2[i].clone());
        }
        let _ = bls.pairing_check(v1, v2);
    });

    std::println!("=== end ===\n");
}
