//! End-to-end demonstration of the UltraKeccakZK Libra forgery (REPORT.md §7).
//!
//! The circuit is `simple_circuit` (`assert(x != y)`, `y` public, `y = 2`).
//! The forged proof is generated from a witness with `x = y = 2`, which
//! violates the circuit constraint, using a patched Barretenberg v0.87.0
//! prover (`forgery/bb-libra-forgery.patch`). See `FORGERY.md`.

use soroban_sdk::{testutils::Ledger, Bytes, Env};
use std::{fs, path::Path};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

fn run(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);
    let env = Env::default();
    env.ledger().set_protocol_version(28);
    env.cost_estimate().budget().reset_unlimited();

    let proof_bytes: Vec<u8> = fs::read(path.join("proof")).map_err(|e| e.to_string())?;
    let proof = Bytes::from_slice(&env, &proof_bytes);

    let vk_bytes = fs::read(path.join("vk")).map_err(|e| e.to_string())?;
    let vk = Bytes::from_slice(&env, &vk_bytes);
    let verifier = UltraHonkVerifier::new(&env, &vk).map_err(|e| format!("{e:?}"))?;

    let public_inputs = fs::read(path.join("public_inputs")).map_err(|e| e.to_string())?;
    let public_inputs = Bytes::from_slice(&env, &public_inputs);
    verifier
        .verify(&proof, &public_inputs)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

/// The forged proof: witness `x = y = 2` violates `assert(x != y)`, yet the
/// UltraKeccakZK verifier accepts it.
#[test]
fn forged_zk_proof_verifies() -> Result<(), String> {
    run("../../forgery/forged")
}

/// Control: the unmodified Barretenberg prover on the same false witness
/// produces a proof that the same verifier rejects.
#[test]
fn stock_proof_for_same_false_witness_is_rejected() {
    assert!(run("../../forgery/false_honest").is_err());
}
