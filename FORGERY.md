# Forged UltraKeccakZK proof for `ultrahonk-soroban-verifier` — and the fix that kills it

This document has two halves. The first closes the gap left by `REPORT.md`
§1.3 / §7.3: a **complete forged proof, produced end-to-end by a modified
Barretenberg prover, that the pre-fix `UltraHonkVerifier::verify` accepted**
for a witness that violates the circuit — verified natively, in the Rust test
suite, and on-chain on public Stellar testnet. The second half describes the
**fix now merged into this branch** (the Libra boundary opening, §3), which
makes the verifier reject that same forged proof while keeping honest proofs
verifiable, and records the end-to-end regression results.

| | |
|---|---|
| Circuit | `circuits/simple_circuit` — `fn main(x: Field, y: pub Field) { assert(x != y) }` |
| False statement | public input $y = 2$, witness $x = 2$ — $\mathrm{assert}(x \neq y)$ is violated |
| Prover | Barretenberg **v0.87.0** (commit `9081b0e`), patched — sources in `forgery/bb.zip`, diffs in `forgery/bb-libra-forgery.patch` and `forgery/bb-libra-boundary.patch` |
| Pre-fix verifier | stock, unmodified: `bb v0.87.0 verify`, `crates/ultrahonk-soroban-verifier`, and the Soroban contract accepted the forged proof |
| Fixed verifier | same code plus the boundary opening `A(1) = 0` in the Shplonk batch (`zk_shplemini.rs`, prover patch `forgery/bb-libra-boundary.patch`): the forged proof, and every stock-format ZK proof, is **rejected**; honest boundary-format proofs are accepted |

## 1. Was a modified prover needed? Yes.

`REPORT.md` Appendix B lists the three missing pieces (SRS points, the
circuit's precomputed polynomials, a complete proving run). The deciding
constraint is the last one: **every Fiat–Shamir challenge is a Keccak hash of
everything sent before it**, so a proof cannot be edited after the fact — the
cheating happens in the first sumcheck round and every later message must be
recomputed consistently. Editing an existing honest proof is not possible, and
a from-scratch reimplementation would still need the 27 selector/perm/table
polynomials, which only Barretenberg's trace construction produces. Hence the
only realistic route is a patched Barretenberg prover, exactly as the report
suggested ("install bb 0.87.0, patch its ZK prover to do steps 4, 6 and 7").

The forgery patch touches four files, ~50 lines total, and is gated behind the
environment variable `BB_FORGE_LIBRA` so the patched binary still produces
ordinary honest proofs when the variable is unset:

| File | Change |
|---|---|
| `sumcheck/sumcheck.hpp` | forgery: fake round univariates + solve `Libra:claimed_evaluation` |
| `commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.cpp` | forgery: shift the grand sum $A$ along the identity kernel |
| `transcript/transcript.hpp` | build fix for Apple clang 21 (C++23 `template` disambiguator) |
| `stdlib_circuit_builders/circuit_builder_base_impl.hpp` | build fix for Apple clang 21 (`[[nodiscard]]` under `-Werror`) |

## 2. What the forgery patch does (Appendix B, steps 4–7)

The attack is the one-dimensional kernel of the SmallSubgroupIPA identity at
$X = 1$ (`REPORT.md` §7.1). The verifier checks, at the Gemini challenge $r$,
that the four openings satisfy

$$L_1(r)\,A(r) + (r - g^{-1})\bigl(A(gr) - A(r) - F(r)\,G(r)\bigr) + L_{\mathrm{last}}(r)\bigl(A(r) - s\bigr) = Z_H(r)\,Q_L(r),$$

where $H = \langle g \rangle$ is the order-256 subgroup, $Z_H(X) = X^{256} - 1$
its vanishing polynomial, and $s$ is the claimed inner product. The identity is
meant to enforce three things: $A(1) = 0$, the running-sum step
$A(g^{i+1}) = A(g^i) + F(g^i)\,G(g^i)$ on $H$, and $A(g^{-1}) = s$. But the three
terms are added without separating challenges, so at $X = 1$ the two intended
constraints collapse into **one** equation,

$$A(1) + (1 - g^{-1})\bigl(A(g) - A(1) - F(1)\,G(1)\bigr) = 0,$$

leaving $A(1)$ as a free parameter that shifts the claimed inner product $s$
arbitrarily.

**Step 4 — round univariates.** The ZK sumcheck proves
$\sum_{x} \bigl[R'(x) + \rho_L\,G(x)\bigr] = \rho_L\,\sigma$, and the verifier's
only per-round check on the sent univariate $S_i$ is

$$S_i(0) + S_i(1) = T_i, \qquad T_0 = \rho_L \cdot \sigma, \qquad T_{i+1} = S_i(u_i).$$

In every real sumcheck round the patch replaces the honest univariate with the
constant $T_i/2$ (all nine evaluations), so every round check still passes and
the fake telescoped target after the last of the $d$ rounds is

$$T_d = \frac{T_0}{2^d} = \frac{\rho_L\,\sigma}{2^d}.$$

No honest sumcheck of the (false) relation is needed. The honest univariate of
the final round is kept aside.

**Step 5 — claimed evaluations.** Untouched: bb extracts the true evaluations
of all 40 entities at the (fake-derived) challenge point $u$, so every
Gemini/Shplonk/KZG opening claim remains a true opening of a committed
polynomial.

**Step 6 — solving for `libra_evaluation`.** The final ZK sumcheck check is

$$R(\mathrm{evals}) \cdot \Bigl(1 - \prod_{i=2}^{d-1} u_i\Bigr) + \rho_L \cdot s = T_d,$$

where the first factor is the row-disabling correction and $R(\mathrm{evals})$
is the relation value the verifier recomputes from the claimed evaluations. The
recorded honest final-round univariate $S^*_{d-1}$ evaluated at $u_{d-1}$
equals $R'(u) + \rho_L\,s_{\mathrm{honest}}$ (this is precisely why honest
proofs verify), so the patch computes

$$s_{\mathrm{forged}} = \frac{T_d - \bigl(S^*_{d-1}(u_{d-1}) - \rho_L\,s_{\mathrm{honest}}\bigr)}{\rho_L}$$

and sends it as `Libra:claimed_evaluation`.

**Step 7 — forging the grand sum $A$.** In
`SmallSubgroupIPAProver::compute_grand_sum_polynomial`, the honest grand sum has
$A(1) = 0$ and $A(g^{-1}) = \langle F, G \rangle$. With

$$\Delta = \langle F, G \rangle - s_{\mathrm{forged}}$$

the patch adds the kernel vector of the identity:

$$A(1) \mathrel{+}= \Delta \cdot (g - 1), \qquad A(g^i) \mathrel{-}= \Delta \quad \text{for } i \geq 1.$$

The step relation $A(g^{i+1}) = A(g^i) + F(g^i)\,G(g^i)$ still holds for
$i \geq 1$, and $A(g^{-1}) = \langle F, G \rangle - \Delta = s_{\mathrm{forged}}$
exactly, while the value at $X = 1$ still satisfies the combined equation above,
so the left-hand side of the SmallSubgroupIPA identity vanishes on all of $H$
and the quotient $Q_L$ (computed by unmodified bb code from the patched $A$)
stays exact. Every one of the four openings $G(r)$, $A(gr)$, $A(r)$, $Q_L(r)$
is a true evaluation of a committed polynomial.

**Step 8 — everything else honest.** Gemini folds, Shplonk quotient, KZG
opening are untouched; they succeed because all claims they prove are true.

## 3. The fix: the Libra boundary opening

The fix adopted in this branch (and, later, upstream Barretenberg in
`small_subgroup_ipa_utils.hpp`) is a **fifth Shplonk claim on the grand-sum
commitment**:

$$A(1) = 0.$$

The evaluation is the fixed value zero, so nothing new is transmitted on the
transcript and the proof length stays 507 words. The claim enters only the
Shplonk batch — the verifier adds $-\nu^{61}/(z-1)$ to the $[A]$ commitment
scalar, and the prover must include $(A(X) - 0)/(X - 1)\cdot\nu^{61}$ in its
Shplonk quotient, which is possible only if $A(1)$ really is zero, i.e. only
if the polynomial is divisible by $(X-1)$. With $A(1)$ bound, the three
constraints the identity was meant to enforce separate, and $s$ is pinned to
$\langle F, G \rangle$ (`REPORT.md` §7.5).

Two consequences:

1. **The verifier rejects every stock-format ZK proof** (including the forged
   one): their Shplonk quotients do not include the boundary term, so the
   final pairing check fails. Honest proofs must be generated by the patched
   prover (`forgery/bb-libra-boundary.patch`); a binary carrying the fix
   reports `0.87.0-libra-boundary`. The prover patch also updates bb's own
   Shplemini verifier, so the patched `bb verify` accepts the fixed format and
   rejects stock ZK proofs, mirroring the Rust verifier.
2. **The forgery recipe is dead.** Re-running the forgery against the
   boundary-patched prover produces a proof whose grand sum has
   $A(1) = \Delta\,(g-1) \neq 0$; the boundary claim is then false, the
   Shplonk quotient is inexact, and the pairing check fails (the
   `forged_v2` artifacts below demonstrate this end to end).

In the Rust verifier the fix lives in `zk_shplemini.rs`: the batch inversion
gains the denominator $z - 1$, and the Libra batching loop covers five claims
(`G(r)`, `A(gr)`, `A(r)`, `A(1) = 0`, `Q(r)` at $\nu^{58}..\nu^{62}$) with the
three grand-sum scalars merged onto the single $[A]$ commitment. The
SmallSubgroupIPA consistency identity itself is unchanged, exactly as upstream
documents it ("soundness additionally requires the boundary opening
$A(1) = 0$, which is enforced by the Shplemini/Shplonk batched opening on the
committed $[A]$").

## 4. Artifacts

```
forgery/
  bb.zip                  patched bb v0.87.0 source files (drop-in replacement
                          over the aztec-packages v0.87.0 tarball; includes
                          the two Apple-clang-21 build fixes, the
                          BB_FORGE_LIBRA forgery mode, and the Libra boundary
                          opening)
  bb-libra-forgery.patch   the forgery changes as a diff against pristine v0.87.0
  bb-libra-boundary.patch  the boundary-opening fix as a diff against pristine v0.87.0
  false_witness.gz        witness with x = y = 2 (assert(x != y) violated);
                          identical to the honest witness except x: 1 → 2
  forged/                 the forged proof in the STOCK format: accepted by the
                          pre-fix verifier, rejected by the fixed verifier
  forged_v2/              the same forgery recipe replayed with the
                          boundary-patched prover: rejected by the fixed
                          verifier (the attack is dead at the source)
  stock_format/           honest stock-format proof: rejected by the fixed
                          verifier (missing boundary opening)
  fixed/                  honest proof from the boundary-patched prover:
                          accepted by the fixed verifier
  false_honest/           control: stock prover, same false witness — rejected
  forge.sh                reproduction script (see below)
```

## 5. Reproduce

```bash
# 1. Build the patched prover (one-time, ~20 min on an M-series Mac):
cd /tmp && curl -sL \
  https://github.com/AztecProtocol/aztec-packages/archive/refs/tags/v0.87.0.tar.gz \
  -o aztec-v0.87.0.tar.gz
tar -xzf aztec-v0.87.0.tar.gz && mv aztec-packages-0.87.0 aztec-0.87.0
unzip <PATH-TO-REPO>/forgery/bb.zip -d aztec-0.87.0   # forgery + boundary + build fixes
cd aztec-0.87.0/barretenberg/cpp
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target bb -j16

# 2. Regenerate the artifacts (uses ~/.bb-crs; the stock ~/.bb/bin/bb and the
#    pinned nargo are used for the controls):
cd <PATH-TO-REPO>
BB_PATCHED=/tmp/aztec-0.87.0/barretenberg/cpp/build/bin/bb ./forgery/forge.sh

# 3. Check the results against the Rust verifier (the code the Soroban
#    contracts use):
cargo test -p ultrahonk_soroban_verifier --test forgery_test
```

The one artifact `forge.sh` cannot regenerate with the current patch set is
`forged/` itself: it predates the boundary fix and was produced with a prover
carrying only the forgery patch. Regenerate it, if desired, by applying only
`bb-libra-forgery.patch` (plus the two build fixes) to a pristine v0.87.0
tree. The committed artifact is the regression input for
`forged_zk_proof_is_rejected`.

If the msgpack-c FetchContent clone fails (a pinned commit that no branch
contains), fetch it manually and re-run the build:

```bash
cd <bb-build>/_deps/msgpack-c/src/msgpack-c
git fetch --depth 1 origin 5ee9a1c8c325658b29867829677c7eb79c433a98
git checkout 5ee9a1c8c325658b29867829677c7eb79c433a98
touch ../msgpack-c-stamp/msgpack-c-download ../msgpack-c-stamp/msgpack-c-gitclone-lastrun.txt
```

## 6. Results

| Check | Result |
|---|---|
| stock `bb v0.87.0 verify` on `forged/proof` (pre-fix format) | **accepted** — the pre-fix verifier's flaw, demonstrated natively |
| fixed Rust `UltraHonkVerifier::verify` on `forged/proof` | **rejected** — the committed forgery no longer passes |
| fixed Rust verifier on `forged_v2/proof` (forgery replayed against the boundary-patched prover) | **rejected** — the recipe itself is dead |
| fixed Rust verifier on `stock_format/proof` (honest stock-format proof) | **rejected** — the boundary opening is required |
| fixed Rust verifier on `fixed/proof` (honest boundary-format proof) | **accepted** |
| patched `bb verify` on `fixed/proof` | **accepted** — the prover-side verifier mirrors the fix |
| stock `bb v0.87.0 verify` on `fixed/proof` | **rejected** — stock bb cannot verify the fixed format |
| stock `bb verify` on `false_honest/proof` (control) | rejected |
| patched bb, `BB_FORGE_LIBRA` unset, honest witness | accepted (regression) |
| patched bb, `BB_FORGE_LIBRA` unset, false witness | rejected (the flag does the cheating) |
| `forgery_test::stock_proof_for_same_false_witness_is_rejected` | rejected, as expected |
| on-chain `verify_proof` on **Stellar testnet**, forged proof (pre-fix artifact, pre-fix verifier) | **Ok** — [tx](https://stellar.expert/explorer/testnet/tx/2f356de45aac5bb06020005b46aa1352ff0eb8d19ade09490345f78d182d219c) |
| on-chain `verify_proof`, stock proof for the same false witness | `Error(Contract, #4)` (VerificationFailed) |
| on-chain `verify_proof`, honest proof | Ok — [tx](https://stellar.expert/explorer/testnet/tx/7c28626acf7adf91b00d5eb2412cbec8c4bc084d73c40e81b9e6d6be14da2190) |

The on-chain rows record the pre-fix demonstration (testnet contract
`CDYS…XJS`, instantiated with the `simple_circuit` ZK VK): the deployed
verifier accepted the forged proof whose witness violates `assert(x != y)`.
Under the fixed verifier that deployment would reject it.

The smoking gun is visible in `forged/proof_fields.json`: every round
univariate of the first $\log_2 n = 12$ rounds is constant (all nine
evaluations equal — an honest prover sends random-looking masked univariates),
and `libra_evaluation` is not the mask's true value at $u$,
$s_{\mathrm{honest}} = \langle F, G \rangle$, which is exactly the degree of
freedom the SmallSubgroupIPA identity failed to bind.

## 7. What this proves

`REPORT.md` §7 claimed the ZK flavor is unsound but demonstrated only the two
halves of the attack. The forgery closed that loop: the pre-fix verifier
accepts a proof whose witness violates the circuit relation, using only the two
patched steps above — both of which exploit the missing $A(1) = 0$ boundary
check documented upstream. Nothing about the verifier, the VK, or the proof
format was modified to make the forgery verify.

The boundary opening then restores soundness end to end: the same forged
artifact, the same forgery recipe replayed against a patched prover, and every
stock-format ZK proof are rejected, while honest proofs from the patched prover
verify natively, in Rust, and on-chain. Any deployment accepting
`UltraKeccakZK` proofs must regenerate them with the boundary-patched prover
(or wait for a Barretenberg release that includes the upstream fix); the
`identity` and `tornado_classic` contracts and the generic contract's ZK path
all enforce the new format by construction.
