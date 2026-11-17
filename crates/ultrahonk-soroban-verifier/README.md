# UltraHonk Soroban Verifier

Rust verifier library for Noir UltraHonk proofs on BN254, designed for Soroban
contracts and `soroban-sdk`. It verifies both the non-ZK `UltraKeccakFlavor`
and the zero-knowledge `UltraKeccakZKFlavor` produced by Nargo 1.0.0-beta.9
and Barretenberg v0.87.0, built with `soroban-sdk` 28.x. Contracts built with
this SDK require Stellar protocol **28 or newer**.

> **Supported flavors: `UltraKeccakFlavor` (non-ZK) and `UltraKeccakZKFlavor` (ZK),
> both non-recursive.** The non-ZK flavor provides **no witness-hiding
> guarantee**: a proof carries witness-dependent protocol messages, and on-chain
> wrappers accept the full proof as public transaction input. Use the ZK flavor
> for privacy-sensitive circuits. Even for ZK proofs, a successful verification
> does **not** bind the proof to the transaction submitter and provides no
> replay protection; see the contract READMEs.
>
> **Proof bytes are not a unique identifier.** Canonical encodings are enforced
> at parse time (see [verifier provenance](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/VERIFIER_PROVENANCE.md) §4.3), but an active prover can still
> vary the fixed-slot padding, so distinct byte strings can verify for one statement.
> Do not key deduplication, replay protection or nullifiers on raw proof bytes.

## Features
- Soroban-focused verifier built on `soroban-sdk`
- Verifies proofs generated from Noir (UltraHonk) using Nargo 1.0.0-beta.9 / Barretenberg v0.87.0
- Supports 456-field non-ZK proofs and 507-field ZK proofs (Libra + hiding polynomial)
- Pure Rust `no_std` core; needs no global allocator
- Expects `bb write_vk`
- Non-ZK fixtures under `circuits/<name>/target`
- ZK fixtures under `circuits/<name>/target/zk`

## Installation

For applications consuming the published 0.1.0 release:

```toml
[dependencies]
ultrahonk_soroban_verifier = "0.1.0"
soroban-sdk = { version = "28.0.0", default-features = false }
```

The verifier is a library, not a prover or circuit compiler. Nargo and
Barretenberg are needed to generate proofs; they are not needed to compile a
Rust application that depends on this crate.

## Quick start from a repository checkout

```bash
just build-circuits
cargo test --workspace --all-features
```

## How it works
- Typical pipeline: Noir circuit → Nargo execute → `bb prove` → this library verifies `proof`, `public_inputs`, and `vk`.
- Circuit artifacts are generated locally and gitignored. The build script emits:
  - `proof`
  - `public_inputs`
  - `vk`
- `target/` uses `UltraKeccakFlavor`; `target/zk/` uses `bb prove --zk` and `UltraKeccakZKFlavor`.

## Usage in a Soroban contract

Pass the contract's `Env` and binary inputs to the verifier. This helper maps
errors to strings for illustration; a contract should map them to its own
`#[contracterror]` enum.

```rust
use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::{ProofFlavor, UltraHonkVerifier};

fn verify(
    env: &Env,
    vk: &Bytes,
    proof: &Bytes,
    public_inputs: &Bytes,
) -> Result<(), &'static str> {
    let verifier = UltraHonkVerifier::new(env, vk)
        .map_err(|_| "invalid verification key")?;
    // The default API safely dispatches by the fixed proof length.
    verifier.verify(proof, public_inputs)
        .map_err(|_| "invalid proof")
}
```

To require a specific flavor explicitly — for example, to make a
privacy-sensitive contract reject non-ZK proofs:

```rust
verifier
    .verify_with_flavor(proof, public_inputs, ProofFlavor::UltraKeccakZk)
    .map_err(|_| "expected a ZK proof")?;
```

All `Bytes` arguments must belong to the same `Env`:

- `vk`: the 1,760-byte binary verification key produced by `bb write_vk`.
- `proof`: the 14,592-byte non-ZK proof (`PROOF_BYTES`) or the 16,224-byte
  ZK proof (`ZK_PROOF_BYTES`).
- `public_inputs`: canonical, big-endian 32-byte field elements concatenated in
  circuit order. The verifier checks their count against the key.

The verifier re-derives the Fiat–Shamir transcript, checks sumcheck, then checks
Shplemini batch openings with BN254 host operations. The ZK flavor adds the
Libra-masked sumcheck, the Gemini hiding polynomial, the SmallSubgroupIPA
consistency check, and the Libra openings in the Shplonk batch. The two flavors
share a VK but have distinct proof lengths, so a truncated or cross-flavor proof
cannot be silently reinterpreted. Only non-recursive UltraHonk VKs are
supported: the v0.87 VK byte format has no recursion marker, so deployers must
enforce that provenance. The application must select a trusted verification key
and enforce its own authorization and replay policy.

See the [contract wrapper](https://github.com/NethermindEth/rs-soroban-ultrahonk/tree/main/contracts/rs-soroban-ultrahonk)
for a complete integration and the
[verifier provenance](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/VERIFIER_PROVENANCE.md)
for the supported proof format.

## Building and testing from the repository

The minimum supported Rust version (MSRV) is **1.92.0**, declared as
`rust-version = "1.92"` in the manifest. CI checks the extracted crate with
default and all features on Rust 1.92.0 and builds the Soroban contract that
embeds it for `wasm32v1-none`. These checks use the committed dependency lockfile;
dependency updates must continue to pass them. The other CI jobs use stable Rust.

Install the `wasm32v1-none` target and Stellar CLI 28.0.0, then build the example
contract that embeds the verifier. From the repository root:

```bash
rustup target add wasm32v1-none
stellar contract build --package rs-soroban-ultrahonk
```

Tests need the private workspace helper crate and circuit fixtures. Run them
from a repository checkout, not from the downloaded crates.io archive:

```bash
# Requires Nargo 1.0.0-beta.9 and Barretenberg 0.87.0.
./circuits/scripts/build_all.sh simple_circuit fib_chain small_circuit lookup_heavy range_heavy many_pubs
cargo test -p ultrahonk_soroban_verifier --locked
cargo test -p ultrahonk_soroban_verifier --locked --all-features
```

Fixtures are generated under `circuits/<name>/target/` (and `target/zk/`
for the ZK flavor) and are not distributed in the crate. Cargo removes the
path-only `ultrahonk-test-utils` development dependency when packaging; it is
not a dependency of applications using this library.

## Audit status

OpenZeppelin audited the repository at commit
[`661db07200f890b1bd9a7349ed787c70a706dd12`](https://github.com/NethermindEth/rs-soroban-ultrahonk/tree/661db07200f890b1bd9a7349ed787c70a706dd12)
between 10 and 28 August 2026 (UltraHonk Verifier Audit, report dated
**18 September 2026**), with five Low severity findings and six notes, and no
Critical, High, or Medium findings. All findings are resolved; the fixes are
present from commit
[`15703c1`](https://github.com/NethermindEth/rs-soroban-ultrahonk/commit/15703c16a8ec69df27f9e14a9069b3f8d9896f5b)
onwards and are included in this release. Later commits also contain SDK
upgrades, so the audited revision is not the release revision. The audit covers
the non-ZK `UltraKeccakFlavor` verifier at that commit; the ZK flavor added by
this branch is covered by the cryptographic review committed as
[`REPORT.md`](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/REPORT.md)
and the end-to-end forgery in
[`FORGERY.md`](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/FORGERY.md).

The full report is committed in the repository:
[OpenZeppelin UltraHonk Verifier Audit (PDF)](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/audits/2026-09-18-openzeppelin-ultrahonk-verifier-audit.pdf).
Its checksum is recorded in
[`audits/README.md`](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/audits/README.md).

## Publishing

Maintainers should follow the repository's
[publishing guide](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/PUBLISHING.md).

## Cargo features
- `std`: enables standard-library debug formatting.
- `trace`: prints detailed verifier internals (for debugging); off by default.

## References

- [Barretenberg](https://github.com/AztecProtocol/aztec-packages)
- [Noir](https://noir-lang.org/)
- [Nargo](https://github.com/noir-lang/noir#nargo)

## License

Licensed under either
[MIT](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/LICENSE-MIT)
or [Apache License 2.0](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/LICENSE-APACHE),
at your option (`MIT OR Apache-2.0`). Both license texts are included in the
crate archive. Retain the existing copyright notices in `LICENSE-MIT` when
redistributing the code. Dependencies retain their own licenses and notice
requirements.
