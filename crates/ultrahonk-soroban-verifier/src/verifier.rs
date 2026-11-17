//! Top-level UltraHonk verifier orchestration.
//!
//! Implements the verifier flow that BB splits across `ultra_verifier.cpp`,
//! `oink_verifier.cpp`, and `decider_verifier.cpp`.  The Rust code inlines the
//! Oink and Decider steps into a single `verify` method.
//!
//! BB reference (v0.87.0):
//!   - `ultra_honk/ultra_verifier.cpp::UltraVerifier_::verify_proof`
//!   - `ultra_honk/oink_verifier.cpp::OinkVerifier::verify`
//!   - `ultra_honk/decider_verifier.cpp::DeciderVerifier_::verify`

use crate::{
    field::Fr,
    shplemini::verify_shplemini,
    sumcheck::verify_sumcheck,
    transcript::generate_transcript,
    types::PAIRING_POINTS_SIZE,
    utils::{
        load_proof, load_vk_from_bytes, validate_gemini_padding, validate_public_inputs_canonical,
    },
    zk_shplemini::verify_zk_shplemini,
    zk_sumcheck::verify_zk_sumcheck,
    zk_transcript::generate_zk_transcript,
    zk_utils::load_zk_proof,
    PROOF_BYTES, ZK_PROOF_BYTES,
};
use soroban_sdk::{Bytes, Env};

/// Error type describing why a verification key could not be loaded from bytes.
///
/// Intentionally minimal: the VK is public data, so callers do not need a
/// fine-grained oracle. The three variants distinguish an incorrect byte count,
/// invalid structural parameters, and malformed G1 commitments.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VkLoadError {
    /// Byte slice length does not match the exact expected VK size (1760 bytes).
    WrongLength,
    /// Header parsed successfully but contains out-of-range or inconsistent values.
    InvalidParameters,
    /// A verification-key G1 commitment was malformed: either a coordinate at or
    /// above the base field modulus, or a point that is not on the BN254 curve.
    ///
    /// Note there is no limb-canonicality case here, unlike the proof path: the VK
    /// stores each point as a plain 64-byte `x || y`, so there are no limbs to
    /// decode and `PointError::NonCanonicalLimb` is unreachable from this path.
    InvalidPoint,
}

/// Error type describing the specific reason verification failed.
#[derive(Debug)]
pub enum VerifyError {
    /// Proof parsing, padding or public-input validation, or transcript/public-input
    /// calculations failed. This includes an incorrect proof length, non-canonical
    /// encodings, and a public-input count that does not match the key.
    InvalidInput,
    /// The sumcheck rounds or final relation evaluation failed verification.
    SumcheckFailed,
    /// The Gemini/Shplonk/KZG batch-opening checks failed verification.
    ShplonkFailed,
}

/// UltraHonk proof flavors accepted by this verifier.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProofFlavor {
    /// Barretenberg v0.87 `UltraKeccakFlavor` (non-zero-knowledge).
    UltraKeccak,
    /// Barretenberg v0.87 `UltraKeccakZKFlavor` (Libra + hiding polynomial).
    UltraKeccakZk,
}

impl ProofFlavor {
    pub const fn proof_bytes(self) -> usize {
        match self {
            Self::UltraKeccak => PROOF_BYTES,
            Self::UltraKeccakZk => ZK_PROOF_BYTES,
        }
    }

    pub fn from_proof_len(len: usize) -> Option<Self> {
        match len {
            PROOF_BYTES => Some(Self::UltraKeccak),
            ZK_PROOF_BYTES => Some(Self::UltraKeccakZk),
            _ => None,
        }
    }
}

/// A verifier bound to a Soroban environment and a validated verification key.
///
/// Construct with [`Self::new`], then use [`Self::verify`] for proofs of the
/// circuit represented by that key. Key validation checks its encoding and
/// structural consistency; the application must establish that it is the
/// intended circuit's key.
pub struct UltraHonkVerifier {
    env: Env,
    vk: crate::types::VerificationKey,
}

impl UltraHonkVerifier {
    /// Build a verifier from an already-parsed key.
    ///
    /// Crate-internal: a `VerificationKey` can only be obtained from
    /// [`load_vk_from_bytes`], which validates every commitment, so this cannot be
    /// reached with an unvalidated key. Exposing it would reintroduce that path,
    /// since the struct's fields are public. Use [`Self::new`] instead, which parses
    /// and validates the key bytes.
    pub(crate) fn new_with_vk(env: &Env, vk: crate::types::VerificationKey) -> Self {
        Self {
            env: env.clone(),
            vk,
        }
    }

    /// Parse and validate a binary UltraKeccak verification key.
    ///
    /// `vk_bytes` must belong to `env` and contain exactly 1,760 bytes: four
    /// big-endian `u64` header fields followed by 27 uncompressed BN254 G1
    /// commitments. Use the binary output of the supported Barretenberg
    /// `write_vk` command, not its JSON field representation.
    ///
    /// The v0.87 byte format has no recursion discriminator. Callers must not
    /// supply a recursive VK: this verifier does not aggregate its pairing
    /// accumulator.
    ///
    /// The verifier retains a clone of the environment handle and the parsed key,
    /// so the input byte buffer does not need to outlive it.
    ///
    /// # Errors
    ///
    /// Returns [`VkLoadError::WrongLength`] for an incorrect byte count,
    /// [`VkLoadError::InvalidParameters`] for inconsistent or out-of-range header
    /// values, or [`VkLoadError::InvalidPoint`] for a non-canonical or off-curve
    /// G1 commitment.
    pub fn new(env: &Env, vk_bytes: &Bytes) -> Result<Self, VkLoadError> {
        load_vk_from_bytes(env, vk_bytes).map(|vk| Self::new_with_vk(env, vk))
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
    }

    /// Verify an UltraKeccak or UltraKeccakZK proof against the loaded VK.
    ///
    /// Both byte buffers must belong to the environment passed to [`Self::new`].
    /// `proof_bytes` must contain exactly [`crate::PROOF_BYTES`] bytes for the
    /// non-ZK flavor or [`crate::ZK_PROOF_BYTES`] bytes for the ZK flavor; the
    /// flavor is selected by the exact proof length.
    /// `public_inputs_bytes` contains the circuit's public inputs in circuit
    /// order, each encoded as a canonical big-endian 32-byte field element.
    /// Do not prepend the proof's pairing-point object to the public inputs.
    ///
    /// Returns `Ok(())` when the proof verifies. This does not authenticate a
    /// transaction submitter or provide replay protection.
    ///
    /// # Errors
    ///
    /// See [`VerifyError`] for input, sumcheck, and batch-opening failures.
    ///
    /// # Verification steps
    ///
    /// Steps (matching BB verifier flow). The numbers match the `// n)` labels in
    /// the body, so a step traced by number lands on the block that performs it:
    /// 1. Select the proof flavor from the exact proof length and validate public
    ///    inputs against VK metadata.
    /// 2. Parse and validate the canonical proof encoding (non-ZK also rejects
    ///    non-zero padding in the unused Gemini evaluation slots).
    /// 3. Generate Fiat–Shamir challenges (Oink rounds).
    /// 4. Compute `public_inputs_delta` (grand-product permutation argument).
    /// 5. Run sumcheck verification.
    /// 6. Run Shplemini batch-opening (Gemini + Shplonk + KZG pairing check).
    ///
    /// BB: `ultra_verifier.cpp::UltraVerifier_::verify_proof`
    /// The verifier's stored environment handle is used throughout; callers must
    /// still ensure that the input buffers belong to that environment.
    pub fn verify(
        &self,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
    ) -> Result<(), VerifyError> {
        let flavor = ProofFlavor::from_proof_len(proof_bytes.len() as usize)
            .ok_or(VerifyError::InvalidInput)?;
        self.verify_with_flavor(proof_bytes, public_inputs_bytes, flavor)
    }

    /// Verify a proof while requiring an explicit flavor.
    ///
    /// Rejects proofs whose length does not match `flavor`, so a non-ZK
    /// deployment cannot be handed a ZK proof (or vice versa) by mistake.
    pub fn verify_with_flavor(
        &self,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
        flavor: ProofFlavor,
    ) -> Result<(), VerifyError> {
        if proof_bytes.len() as usize != flavor.proof_bytes() {
            return Err(VerifyError::InvalidInput);
        }
        let provided = self.validate_public_inputs(public_inputs_bytes)?;
        let env = &self.env;
        match flavor {
            ProofFlavor::UltraKeccak => {
                self.verify_non_zk(env, proof_bytes, public_inputs_bytes, provided)
            }
            ProofFlavor::UltraKeccakZk => {
                self.verify_zk(env, proof_bytes, public_inputs_bytes, provided)
            }
        }
    }

    /// Validate the public inputs: 32-byte alignment, canonical encodings, and
    /// count against VK metadata.
    fn validate_public_inputs(&self, public_inputs_bytes: &Bytes) -> Result<u64, VerifyError> {
        if !public_inputs_bytes.len().is_multiple_of(32) {
            return Err(VerifyError::InvalidInput);
        }
        validate_public_inputs_canonical(public_inputs_bytes)
            .map_err(|_| VerifyError::InvalidInput)?;
        let provided = (public_inputs_bytes.len() / 32) as u64;
        let expected = self
            .vk
            .public_inputs_size
            .checked_sub(PAIRING_POINTS_SIZE as u64)
            .ok_or(VerifyError::InvalidInput)?;
        if expected != provided {
            return Err(VerifyError::InvalidInput);
        }
        Ok(provided)
    }

    fn verify_non_zk(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
        provided: u64,
    ) -> Result<(), VerifyError> {
        // 1) parse proof
        let proof = load_proof(env, proof_bytes).map_err(|_| VerifyError::InvalidInput)?;

        // 2) reject non-canonical padding in the unused Gemini evaluation slots.
        // Done here rather than in `load_proof` because it needs log_circuit_size,
        // which comes from the VK. Runs before transcript generation.
        validate_gemini_padding(&proof, self.vk.log_circuit_size as usize)
            .map_err(|_| VerifyError::InvalidInput)?;

        // 3) Fiat–Shamir transcript
        let pis_total = provided + PAIRING_POINTS_SIZE as u64;
        let pub_inputs_offset = self.vk.pub_inputs_offset;
        let mut t = generate_transcript(
            env,
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_inputs_offset,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        // 4) Public delta
        t.rel_params.public_inputs_delta = Self::compute_public_input_delta(
            env,
            public_inputs_bytes,
            &proof.pairing_point_object,
            &t.rel_params.beta,
            &t.rel_params.gamma,
            pub_inputs_offset,
            self.vk.circuit_size,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        // 5) Sum-check
        verify_sumcheck(env, &proof, &t, &self.vk).map_err(|_| VerifyError::SumcheckFailed)?;

        // 6) Shplemini (Gemini + Shplonk + KZG)
        verify_shplemini(env, &proof, &self.vk, &t).map_err(|_| VerifyError::ShplonkFailed)?;

        Ok(())
    }

    fn verify_zk(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
        provided: u64,
    ) -> Result<(), VerifyError> {
        let proof = load_zk_proof(env, proof_bytes).map_err(|_| VerifyError::InvalidInput)?;
        let pis_total = provided + PAIRING_POINTS_SIZE as u64;
        let pub_inputs_offset = self.vk.pub_inputs_offset;

        // 3) Fiat–Shamir transcript (ZK flavor)
        let mut transcript = generate_zk_transcript(
            &self.env,
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_inputs_offset,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        // 4) Public delta
        transcript.rel_params.public_inputs_delta = Self::compute_public_input_delta(
            env,
            public_inputs_bytes,
            &proof.pairing_point_object,
            &transcript.rel_params.beta,
            &transcript.rel_params.gamma,
            pub_inputs_offset,
            self.vk.circuit_size,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        // 5) ZK sum-check
        verify_zk_sumcheck(env, &proof, &transcript, &self.vk)
            .map_err(|_| VerifyError::SumcheckFailed)?;
        // 6) ZK Shplemini (Gemini + Shplonk + KZG + Libra SmallSubgroupIPA)
        verify_zk_shplemini(&self.env, &proof, &self.vk, &transcript)
            .map_err(|_| VerifyError::ShplonkFailed)?;

        Ok(())
    }

    /// Compute the public-input delta factor for the permutation grand-product argument.
    ///
    /// Formula (matching BB):
    ///   numerator   = ∏ᵢ (γ + xᵢ + β·(n + i + offset))
    ///   denominator = ∏ᵢ (γ + xᵢ − β·(1 + i + offset))
    ///   delta       = numerator · denominator⁻¹
    ///
    /// The pairing-point object values are appended after the user-supplied public inputs.
    ///
    /// BB: `honk/library/grand_product_delta.hpp::compute_public_input_delta`
    fn compute_public_input_delta(
        env: &Env,
        public_inputs: &Bytes,
        pairing_point_object: &[Fr],
        beta: &Fr,
        gamma: &Fr,
        offset: u64,
        n: u64,
    ) -> Result<Fr, &'static str> {
        let mut numerator = Fr::one(env);
        let mut denominator = Fr::one(env);

        let beta_n = beta * &Fr::from_u64(env, n + offset);
        let beta_off = beta * &Fr::from_u64(env, offset + 1);
        let mut numerator_acc = gamma + beta_n;
        let mut denominator_acc = gamma - &beta_off;

        let mut idx = 0u32;
        while idx < public_inputs.len() {
            let mut arr = [0u8; 32];
            public_inputs.slice(idx..idx + 32).copy_into_slice(&mut arr);
            let public_input = Fr::from_array(env, &arr);
            numerator = numerator * (&numerator_acc + &public_input);
            denominator = denominator * (&denominator_acc + &public_input);
            numerator_acc = &numerator_acc + beta;
            denominator_acc = &denominator_acc - beta;
            idx += 32;
        }
        for public_input in pairing_point_object {
            numerator = &numerator * &(&numerator_acc + public_input);
            denominator = &denominator * &(&denominator_acc + public_input);
            numerator_acc = &numerator_acc + beta;
            denominator_acc = &denominator_acc - beta;
        }
        if denominator.is_zero() {
            return Err("denominator is zero in public_input_delta");
        }
        let denominator_inv = denominator.inverse();
        Ok(numerator * denominator_inv)
    }
}
