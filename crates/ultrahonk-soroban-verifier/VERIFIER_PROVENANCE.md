# Verifier Provenance

This document records the protocol variants implemented by
`ultrahonk-soroban-verifier` and the Barretenberg sources against which they
must be checked.

- **Supported toolchain (target):** `aztec-packages` tag **v0.87.0**,
  commit `9081b0ed38c43c120afb7c80f8f6cd418ca5ad70`
- **Port lineage (origin):** `aztec-packages` tag **v0.82.2**, inherited from the
  original `rs-soroban-ultrahonk`
- **Implemented flavors:** **`UltraKeccakFlavor`** (non-ZK) and
  **`UltraKeccakZKFlavor`** (ZK), both Keccak transcript
- **Audit date:** 2026-05-28 (internal); OpenZeppelin external audit
  2026-08-10 → 2026-08-28 (non-ZK flavor); ZK cryptographic review 2026-11
  (`REPORT.md`, forgery in `FORGERY.md`)
- **Scope:** non-recursive, native BN254 UltraHonk paths only

> **Version note — lineage versus target.** These are two different facts and
> earlier revisions of this document conflated them by recording only the first.
>
> *Lineage:* the port was written from `v0.82.2`, inherited from the original
> `rs-soroban-ultrahonk`. That is accurate history and is retained here; it is
> why the module headers previously cited `v0.82.2`, and it is the right
> starting point for anyone tracing a line of this crate back to its origin.
>
> *Target:* the serialization surface the crate actually parses is the `v0.87.0`
> default layout — 456 field elements for the non-ZK flavor (440-element proof
> body plus the 16-element pairing-point object) and 507 field elements for the
> ZK flavor. `v0.82.2` emits the non-ZK layout only when invoked as
> `bb prove -s ultra_honk --oracle_hash keccak --init_kzg_accumulator`.
> Both versions therefore *work*, each with its own verification key, but they
> are not interchangeable.
>
> The supported toolchain is `v0.87.0`, and module headers now cite it for that
> reason rather than because the code was written against it. Note that
> version mismatches are **not** detectable by the proof-length check alone —
> they surface later as a failed pairing check. Proofs and verification keys
> must come from the same version.

## Supported flavors

| Flavor | Proof words | Support |
|---|---:|---|
| `UltraKeccakFlavor` | 456 | Full |
| `UltraKeccakZKFlavor` | 507 | Full |
| Recursive UltraHonk | — | Not supported |
| Poseidon2 transcript | — | Not supported |
| Mega/Goblin/Rollup/IPA | — | Not supported |

Both flavors use the same 1,760-byte verification-key encoding: four `u64`
header fields followed by 27 BN254 G1 commitments. The proof length selects the
flavor automatically; callers can also require an explicit `ProofFlavor`.

## Common protocol

The two flavors share:

- 16 proof-contained pairing-point-object field elements;
- eight Ultra witness/lookup/permutation commitments;
- 26 Ultra relations and 25 batching alphas;
- 40 multilinear entity evaluations (35 unshifted, five shifted);
- Gemini multilinear reduction, Shplonk batching, and BN254 KZG pairing;
- Keccak Fiat-Shamir challenges split into 128-bit field challenges.

Public inputs must use their unique big-endian BN254 scalar encoding. Values
greater than or equal to the scalar modulus are rejected before transcript or
proof checks so byte-oriented application logic (such as nullifier tracking)
cannot observe aliases of the same circuit field element.

Proof scalars are likewise required to be canonical. Proof commitments require
zero padding in the `(lo136, hi118)` limb encoding, canonical base-field
coordinates, and on-curve G1 points; VK commitments receive the same coordinate
and curve checks. Malformed encodings return verifier/VK errors instead of
reaching an MSM or pairing host trap.

```
Rust Module                         BB Component (v0.87.0)
─────────────────────────────────────────────────────────────────────────────
transcript.rs    ─────────────────► transcript/transcript.hpp
                                    oink_verifier.cpp (challenge rounds)
                                    ultra_verifier.cpp (gate challenges)
                                    sumcheck/sumcheck.hpp (sumcheck challenges)
                                    commitment_schemes/shplonk/shplemini.hpp

verifier.rs      ─────────────────► ultra_verifier.cpp::verify_proof
                                    oink_verifier.cpp::OinkVerifier::verify
                                    decider_verifier.cpp::DeciderVerifier_::verify

sumcheck.rs      ─────────────────► sumcheck/sumcheck.hpp::SumcheckVerifier::verify
                                    sumcheck/sumcheck_round.hpp
                                    polynomials/barycentric.hpp
                                    polynomials/gate_separator.hpp

relations.rs     ─────────────────► relations/ultra_arithmetic_relation.hpp
                                    relations/permutation_relation.hpp
                                    relations/logderiv_lookup_relation.hpp
                                    relations/delta_range_constraint_relation.hpp
                                    relations/elliptic_relation.hpp
                                    relations/auxiliary_relation.hpp
                                    relations/poseidon2_external_relation.hpp
                                    relations/poseidon2_internal_relation.hpp
                                    sumcheck_round.hpp::compute_full_relation_purported_value

shplemini.rs     ─────────────────► commitment_schemes/shplonk/shplemini.hpp
                                    commitment_schemes/kzg/kzg.hpp

types.rs         ─────────────────► stdlib_circuit_builders/ultra_flavor.hpp
                                    relations/relation_parameters.hpp

utils.rs         ─────────────────► honk/proof_system/types/proof.hpp
                                    ultra_flavor.hpp:110 PROOF_LENGTH_WITHOUT_PUB_INPUTS
                                    ultra_flavor.hpp:683-760 Transcript_ (de)serialisation
                                    ultra_keccak_flavor.hpp:132 VerificationKey MSGPACK_FIELDS

ec.rs            ─────────────────► Host bn254_g1_msm / pairing_check
                                    (same cryptographic primitives as BB native)
```

| Rust Function                          | BB Equivalent                                      |
|----------------------------------------|----------------------------------------------------|
| `load_proof`                           | `ultra_flavor.hpp:110` (`PROOF_LENGTH_WITHOUT_PUB_INPUTS`) + `:683-760` (`Transcript_::{de,}serialize_full_transcript`) — there is no `Proof` type |
| `load_zk_proof`                        | `ultra_zk_flavor.hpp::Transcript_` (de)serialisation, 507-word layout |
| `load_vk_from_bytes`                   | `ultra_keccak_flavor.hpp:132` (`UltraKeccakFlavor::VerificationKey::MSGPACK_FIELDS`) — **not** `UltraFlavor::VerificationKey` (`ultra_flavor.hpp:450-454`), which serialises a fifth header field |
| `coord_to_halves_be` / `combine_limbs` | `field_conversion::calc_num_bn254_frs`             |

## Non-ZK UltraKeccak

| Rust | Barretenberg v0.87 |
|---|---|
| `transcript.rs` | `honk_contract.hpp::TranscriptLib` |
| `sumcheck.rs` | non-ZK `SumcheckVerifier` / 8-value univariates |
| `shplemini.rs` | non-ZK `ShpleminiVerifier_` |

The fixed proof layout is `PROOF_FIELDS = 456` (`PROOF_BYTES = 14,592`).

## ZK UltraKeccak

The ZK implementation follows `UltraKeccakZKFlavor` and the generated
`honk_zk_contract.hpp` verifier.

| Rust | Barretenberg v0.87 |
|---|---|
| `zk_types.rs`, `zk_utils.rs` | `ultra_zk_flavor.hpp::Transcript_`, ZK proof loader |
| `zk_transcript.rs` | `honk_zk_contract.hpp::ZKTranscriptLib` |
| `zk_sumcheck.rs` | ZK `SumcheckVerifier`, row-disabling polynomial |
| `zk_shplemini.rs` | ZK `ShpleminiVerifier_`, `SmallSubgroupIPAVerifier` |

The fixed proof layout is `ZK_PROOF_FIELDS = 507`
(`ZK_PROOF_BYTES = 16,224`). Relative to the non-ZK proof it adds:

- a commitment to concatenated Libra masking univariates and their claimed sum;
- 9-value rather than 8-value sumcheck univariates;
- the Libra evaluation used in the masked sumcheck identity;
- grand-sum and quotient commitments for the SmallSubgroupIPA;
- a Gemini hiding-polynomial commitment and evaluation;
- four Libra opening evaluations.

The verifier checks the order-256 Libra subgroup identity, batches the hiding
polynomial at `rho^0`, starts ordinary entity claims at `rho^1`, and batches
the Libra openings at fixed Shplonk powers before the final KZG pairing,
including the boundary opening of the grand sum at `1` (see `REPORT.md` §7).

Two properties inherited from the reference that reviewers should know
(`REPORT.md` §8 #4–5): the ZK row-disabling factor leaves the last four rows
of the circuit unconstrained by design — v0.87 reserves those rows in both
flavors and the VKs are byte-identical across flavors, so this is safe for
bb-generated VKs; and every Fiat–Shamir challenge is 128 bits (or about 126
bits for the high half), a Barretenberg design choice that sizes the
soundness error terms accordingly.

## Intentional exclusions

Recursive proofs are not supported. The 16 pairing-point-object limbs are
included in the transcript and permutation public-input delta, but nested
pairing accumulators are not reconstructed or aggregated. Only VKs for
non-recursive circuits may be used.

The implementation is version-specific. Proofs or VKs from another
Barretenberg version must not be assumed compatible even when their lengths
match.

| Feature              | BB Component                      | Reason                                                     |
|----------------------|-----------------------------------|------------------------------------------------------------|
| Recursive verifier   | `stdlib/honk_verifier/`           | Circuit-native verification only; no recursive composition |
| Mega / ECC / Goblin  | `mega_flavor.hpp`, `goblin/`      | Different flavor with ECC op wires, databus columns        |
| Rollup / IPA         | `ultra_rollup_flavor.hpp`         | IPA claim handling, Grumpkin MSM                           |
| Poseidon2 transcript  | `UltraFlavor` (poseidon2 variant) | Only Keccak-256 path is implemented                        |

### 4.2 Verified-Aligned Behaviours

The following were checked line-by-line during the 2026-05-28 internal review,
against BB **v0.82.2** — the version the port was written from.

**The review was re-run against the declared target, BB v0.87.0, on 2026-09-04.**
It followed the procedure in section 7; the checked behaviors and relevant
implementation differences are summarized below.
The outcome: **no soundness or completeness divergence found**.
Two behavioral differences were found that change only the stage and type of
rejection, never the accept/reject outcome:

- A G1 coordinate encoded as `x + p` is rejected at parse time (`fp_in_range`),
  where bb reduces it and then rejects via the transcript, which absorbs the raw
  limbs. This is a *different surface* from the limb-width rule §4.3 already
  recorded, and §4.3 now carries a row for it.
- Verification-key header fields are structurally validated here
  (`circuit_size == 1 << log_circuit_size` and friends); bb v0.87.0 deserializes
  them without re-validation. A narrowing on trusted, public, deployer-supplied data.

The review also corrected two source comments that cited bb symbols which do not
exist at v0.87.0 — `ultra_flavor.hpp::Proof` and `ultra_flavor.hpp::VerificationKey_`.
The second was the more misleading: it resolves to `UltraFlavor::VerificationKey`,
whose `MSGPACK_FIELDS` carries a fifth header field this crate must *not* parse. The
layout implemented here is `UltraKeccakFlavor`'s. Sections 2 and 3.6 are corrected
to match.

Three further differences are unreachable degenerate-input paths where this
verifier returns a clean error and bb calls `throw_or_abort`; these need no action.

The entries below state what was checked on 2026-05-28, and the
v0.87.0 review re-confirmed each of them. The relation algebra and transcript
construction are unchanged between the two versions; the serialization surface is
not, and the deserialization entry was therefore the one re-derived most carefully.

- **Transcript:** All 13 challenge rounds, Keccak-256 hashing, 128-bit challenge splitting, G1 point serialization (lo136/hi118), uint64 serialization.
- **Public-input delta:** Formula, loop bounds, pairing-point-object inclusion, offset handling.
- **Sumcheck:** Univariate degree (8), barycentric weights (all 8 values verified mod BN254 scalar field), `check_sum`, barycentric evaluation, `pow_β` partial evaluation, padded dummy rounds.
- **Relations:** All 26 subrelations across 8 families match exactly. Key constants verified: `neg_half`, `LIMB_SIZE = 1<<68`, `SUBLIMB_SHIFT = 1<<14`, `B_NEG = 17` (Grumpkin), Poseidon2 internal diagonal values.
- **Shplemini:** Gemini challenge powers, batch inversion layout, Shplonk unshifted/shifted weights, batched evaluation accumulation, commitment order, Gemini fold reconstruction, constant-term accumulator, further folding scalars, dummy commitment padding, generator + quotient placement, KZG pairing check.
- **Deserialization:** Proof byte offsets, VK header fields, G1 limb reconstruction, big-endian field decoding.

The ZK flavor was reviewed equation-by-equation in 2026-11 (`REPORT.md`),
including the nine-point masked sumcheck, the Libra SmallSubgroupIPA
consistency identity, the Gemini hiding claim, and the fixed Shplonk powers for
the Libra openings. The one soundness gap that review found — the unbound
`A(1)` boundary of the grand sum — is closed by the extra Shplonk boundary
opening described in the ZK section above, and the end-to-end forgery that
demonstrated the gap is kept as a rejection test (`FORGERY.md`).

---

## 4.3 Accepted Proof Language (compatibility contract)

Following the OpenZeppelin audit (findings L-01, L-02, N-05), the crate declares
its accepted proof language explicitly rather than leaving it implicit:

| Surface | Policy | Relative to bb v0.87.0 |
|---|---|---|
| G1 limb encodings | **Canonical only** — `lo < 2^136`, `hi < 2^118`, at parse time | Removes a divergence: bb reconstructs by addition and rejects these |
| G1 coordinates | **Canonical only** — rejected at or above `p`, at parse time | Same outcome, earlier: bb reduces mod `p` but hashed the raw limbs, so rejects at the pairing check. Distinct from the limb widths above — `x + p` can satisfy both bounds. |
| Proof scalar words | **Canonical only** — rejected at or above `r` | **Deliberate narrowing**: bb's native decode reduces silently |
| Public inputs | **Canonical only** — rejected at or above `r` | Stricter than a bare reduction; see note 3 |
| Padded Gemini evaluations | **Zero required** — rejected at parse time (slots `log_n..28`) | Matches bb: bb binds these via its constant-term accumulator and rejects non-zero |
| Padded sumcheck rounds, unused fold commitments | Unconstrained | Matches bb, which masks both |
| Libra grand-sum boundary | **`A(1) = 0` opened in the Shplonk batch** | Deliberate hardening beyond stock v0.87.0 (see `REPORT.md` §7.4); requires the patched prover |

Two consequences a reader must not have to infer:

1. **The scalar rule is a deliberate divergence from the reference version.** bb
   v0.87.0 accepts `v + k·r`; this verifier does not. Honest proofs are unaffected —
   bb's serializer emits canonical scalars by construction — but a hand-built proof
   that bb accepts may be rejected here, and that is intended.
2. **Padding is constrained only where bb constrains it.** Of the three padded
   surfaces, bb masks the sumcheck rounds and the unused fold commitments exactly as
   this verifier does; the one divergence was the Gemini evaluations, which bb binds
   through its Shplonk constant-term accumulator
   (`shplemini.hpp::batch_gemini_claims_received_from_prover`) while this verifier
   ignored beyond `log_n`. `validate_gemini_padding` now rejects non-zero values in
   those slots at parse time, reaching bb's accept/reject outcome without
   reimplementing its constant-term accumulation over the fixed 28-slot layout.

   The unused fold commitments are deliberately left unconstrained. Rejecting
   non-generator values there would make this verifier *stricter* than bb, and would
   rest on a padding convention confirmed only at `log_circuit_size` 12 and 13.

3. **Public inputs are canonicality-checked, but not because they were malleable.**
   Unlike the proof scalars, public inputs are *not* a malleability surface:
   `generate_eta_challenge` absorbs the raw public-input bytes into the transcript, so
   `v` and `v + k·r` already produce different challenges and a proof for one does not
   verify against the other. Verification failed closed before this check existed —
   with `SumcheckFailed`, as the negative test demonstrates when the check is removed.

   What the check removes is an internal asymmetry: the transcript bound the raw bytes
   while `compute_public_input_delta` decoded through `Fr::from_array`, which reduces,
   so for a non-canonical input the two paths disagreed about the value. That was
   harmless only because the transcript mismatch rejected first. Enforcing canonicality
   makes "both paths see the same value" an invariant rather than an accident of
   ordering, so a future change to how the transcript absorbs public inputs cannot
   silently reintroduce L-02's malleability on this surface.

   Integrator note: a caller that passes an unreduced digest as a public input, relying
   on the verifier's reduction to match what the prover committed, will now be rejected.
   Reduce before calling.

The contract is therefore: **canonical encodings throughout the verified tuple —
proof and public inputs — zero-padded Gemini evaluations, a sound Libra grand-sum
boundary, and bb-compatible padding elsewhere.**

Note that proof bytes remain non-unique as a statement identifier even under a fully
canonical policy: an active prover can still vary padding. Do not key deduplication,
replay protection or nullifiers on raw proof bytes.

---

## 6. Test Fixtures and generation

All verification is validated against BB-generated fixtures in `circuits/`:

| Fixture          | Circuit Size | Description                          |
|------------------|--------------|--------------------------------------|
| `simple_circuit` | 2^12         | Basic arithmetic + permutation       |
| `fib_chain`      | 2^12         | Fibonacci sequence in-circuit        |
| `small_circuit`  | 2^12         | Minimal gate set                     |
| `lookup_heavy`   | 2^13         | Heavy lookup-table usage             |
| `range_heavy`    | 2^13         | Heavy range-check usage               |
| `many_pubs`      | 2^12         | Many public inputs                   |
| `identity`       | 2^12         | Identity circuit (contract e2e)      |
| `tornado`        | 2^13         | Tornado-style circuit (contract e2e) |

`circuits/scripts/build_all.sh` generates both variants for every circuit:

- `circuits/<name>/target/{proof,vk,public_inputs}` — non-ZK;
- `circuits/<name>/target/zk/{proof,vk,public_inputs}` — ZK.

Set `GENERATE_ZK=0` only when the companion ZK fixtures are not needed.

Test commands:
```bash
# Full Rust test matrix
cargo test --package ultrahonk_soroban_verifier

# WASM release build (Soroban target)
cargo build --package ultrahonk_soroban_verifier --target wasm32v1-none --release

# E2E scripts
./scripts/run_identity_e2e.sh
./scripts/run_localnet_e2e.sh
```

---

## 7. Re-Auditing Instructions

When Barretenberg is upgraded, follow these steps to validate the Rust verifier:

1. **Update the BB source tree** to the new tag and note the old→new tag in this file.
2. **Check constants** in `types.rs` against `ultra_flavor.hpp`. Any change to `NUM_ALL_ENTITIES`, `NUM_PRECOMPUTED`, `NUM_WITNESS`, `NUM_SHIFTED`, `NUM_SUBRELATIONS`, `BATCHED_RELATION_PARTIAL_LENGTH`, or `CONST_PROOF_SIZE_LOG_N` is **CRITICAL**.
3. **Check proof size** in `lib.rs` (`PROOF_FIELDS`, `PROOF_BYTES`, `ZK_PROOF_FIELDS`, `ZK_PROOF_BYTES`) against
   `stdlib_circuit_builders/ultra_flavor.hpp::PROOF_LENGTH_WITHOUT_PUB_INPUTS`, remembering
   that `PROOF_FIELDS` adds `PAIRING_POINTS_SIZE` on top of it.
4. **Audit transcript** (`transcript.rs`, `zk_transcript.rs`) against `transcript.hpp` and `oink_verifier.cpp`. Challenge labels are **not** hashed in either codebase, but the *order* of absorptions must match exactly.
5. **Audit sumcheck** (`sumcheck.rs`, `zk_sumcheck.rs`) against `sumcheck.hpp`. Verify barycentric weights if `BATCHED_RELATION_PARTIAL_LENGTH` changes.
6. **Audit relations** (`relations.rs`) against the 8 relation headers. Even a single coefficient change breaks verification.
7. **Audit Shplemini** (`shplemini.rs`, `zk_shplemini.rs`) against `shplemini.hpp` and `small_subgroup_ipa.hpp`. The MSM layout is especially fragile.
8. **Run the full test matrix** (`cargo test --workspace`) and all e2e scripts.
9. **Update this file** with the new BB tag, any changed constants, and the new audit date.

Additional validation when upgrading Barretenberg:

1. Regenerate both proof variants with the pinned `nargo` and `bb` versions.
2. Verify both variants with native `bb` and the Rust verifier.
3. Recheck proof layouts and every transcript absorption boundary.
4. Recheck 8- and 9-point barycentric constants.
5. Recheck the row-disabling factor, Libra subgroup constants and consistency identity.
6. Recheck fixed Shplonk powers for the Libra claims, including the boundary opening at `1`.
7. Run `cargo test --workspace --all-features` and the Soroban Wasm build.

---

## 8. Glossary

| Term               | Meaning                                                                                                                                      |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| **Oink**           | The first phase of UltraHonk verification: transcript preamble, wire commitments, lookup commitments, and challenge generation (η, β, γ, α). |
| **Sumcheck**       | Multivariate polynomial identity protocol. The verifier checks round univariates and derives round challenges.                               |
| **Shplemini**      | Batch-opening protocol combining Gemini (folding), Shplonk (batching), and KZG (pairing).                                                    |
| **PPO**            | Pairing Point Object — 16 Fr values appended to public inputs in the permutation argument.                                                   |
| **Gate separator** | Polynomial `pow_β = ∏((1−Xᵢ) + Xᵢ·βᵢ)` used to combine multiple relations into one sumcheck claim.                                           |
| **Domain sep**     | The partial evaluation of `pow_β` at the sumcheck challenges, scaling each relation contribution.                                            |
| **Libra**          | ZK sumcheck masking: a random multilinear polynomial whose claimed sum masks the relation sum.                                               |
| **SmallSubgroupIPA** | The ZK argument binding the Libra claimed evaluation to committed grand-sum and quotient polynomials over the order-256 subgroup.           |

---

*Last updated: 2026-11-17 — Barretenberg tag (target): v0.87.0*
