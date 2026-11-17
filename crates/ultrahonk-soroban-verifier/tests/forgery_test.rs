//! End-to-end demonstration of the UltraKeccakZK Libra forgery (REPORT.md §7)
//! and of the boundary opening that closes it.
//!
//! The circuit is `simple_circuit` (`assert(x != y)`, `y` public, `y = 2`).
//! The forged proof is generated from a witness with `x = y = 2`, which
//! violates the circuit constraint, using the patched Barretenberg v0.87.0
//! prover (`forgery/bb-libra-forgery.patch`). The verifier fix
//! (`forgery/bb-libra-boundary.patch`, mirrored in `zk_shplemini.rs`) adds
//! the fixed Shplonk claim `A(1) = 0`, which removes the one-dimensional
//! kernel of the SmallSubgroupIPA identity at `X = 1` that the forgery
//! exploits. See `FORGERY.md`.

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

/// The forged proof: witness `x = y = 2` violates `assert(x != y)`. Before the
/// boundary-opening fix the UltraKeccakZK verifier accepted it (FORGERY.md);
/// with the fix it must be rejected, because the forged grand sum has
/// `A(1) != 0` and no longer satisfies the Shplonk batch.
#[test]
fn forged_zk_proof_is_rejected() {
    assert!(run("../../forgery/forged").is_err());
}

/// The same forgery recipe replayed against the Libra-boundary-patched
/// prover: the proof no longer verifies either, confirming the fix kills the
/// attack at the source and not merely this particular artifact.
#[test]
fn forged_zk_proof_from_patched_prover_is_rejected() {
    assert!(run("../../forgery/forged_v2").is_err());
}

/// A stock Barretenberg v0.87.0 proof for an honest witness is still
/// rejected: it lacks the `A(1) = 0` boundary opening, so its Shplonk
/// quotient does not match the fixed batch.
#[test]
fn stock_format_zk_proof_is_rejected() {
    assert!(run("../../forgery/stock_format").is_err());
}

/// The honest proof produced by the Libra-boundary-patched prover verifies.
#[test]
fn boundary_patched_honest_zk_proof_verifies() -> Result<(), String> {
    run("../../forgery/fixed")
}

/// Control: the unmodified Barretenberg prover on the same false witness
/// produces a proof that the same verifier rejects.
#[test]
fn stock_proof_for_same_false_witness_is_rejected() {
    assert!(run("../../forgery/false_honest").is_err());
}
