# Forged UltraKeccakZK proof for `ultrahonk-soroban-verifier`

This closes the gap left by `REPORT.md` §1.3 / §7.3: a **complete forged proof,
produced end-to-end by a modified Barretenberg prover, that
`UltraHonkVerifier::verify` accepts** for a witness that violates the circuit —
verified natively, in the Rust test suite, and on-chain on public Stellar
testnet.

| | |
|---|---|
| Circuit | `circuits/simple_circuit` — `fn main(x: Field, y: pub Field) { assert(x != y) }` |
| False statement | public input $y = 2$, witness $x = 2$ — $\mathrm{assert}(x \neq y)$ is violated |
| Prover | Barretenberg **v0.87.0** (commit `9081b0e`), patched — sources in `forgery/bb.zip`, diff in `forgery/bb-libra-forgery.patch` |
| Verifier | stock, unmodified: `bb v0.87.0 verify`, `crates/ultrahonk-soroban-verifier`, and the Soroban contract |
| Result | forged proof accepted; stock proof for the same false witness rejected |

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

The patch touches four files, ~50 lines total, and is gated behind the
environment variable `BB_FORGE_LIBRA` so the patched binary still produces
ordinary honest proofs when the variable is unset:

| File | Change |
|---|---|
| `sumcheck/sumcheck.hpp` | forgery: fake round univariates + solve `Libra:claimed_evaluation` |
| `commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.cpp` | forgery: shift the grand sum $A$ along the identity kernel |
| `transcript/transcript.hpp` | build fix for Apple clang 21 (C++23 `template` disambiguator) |
| `stdlib_circuit_builders/circuit_builder_base_impl.hpp` | build fix for Apple clang 21 (`[[nodiscard]]` under `-Werror`) |

## 2. What the patch does (Appendix B, steps 4–7)

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

## 3. Artifacts

```
forgery/
  bb.zip                  the forged bb v0.87.0 prover source files (drop-in
                         replacement over the aztec-packages v0.87.0 tarball;
                         includes the two Apple-clang-21 build fixes)
  bb-libra-forgery.patch  the same changes as a diff against pristine v0.87.0
  false_witness.gz        witness with x = y = 2 (assert(x != y) violated);
                          identical to the honest witness except x: 1 → 2
  forged/                 proof, public_inputs (y = 2), vk
  false_honest/           control: same witness, stock prover
  forge.sh                reproduction script (see below)
```

## 4. Reproduce

```bash
# 1. Build the patched prover (one-time, ~20 min on an M-series Mac):
cd /tmp && curl -sL \
  https://github.com/AztecProtocol/aztec-packages/archive/refs/tags/v0.87.0.tar.gz \
  -o aztec-v0.87.0.tar.gz
tar -xzf aztec-v0.87.0.tar.gz && mv aztec-packages-0.87.0 aztec-0.87.0
unzip <PATH-TO-REPO>/forgery/bb.zip -d aztec-0.87.0   # or: patch -p1 < forgery/bb-libra-forgery.patch
cd aztec-0.87.0/barretenberg/cpp
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target bb -j16

# 2. Forge and verify (uses ~/.bb-crs and the stock ~/.bb/bin/bb as verifier):
cd <PATH-TO-REPO>
BB_PATCHED=/tmp/aztec-0.87.0/barretenberg/cpp/build/bin/bb ./forgery/forge.sh

# 3. Verify with the Rust verifier (the code the Soroban contracts use):
cargo test -p ultrahonk_soroban_verifier --test forgery_test
```

If the msgpack-c FetchContent clone fails (a pinned commit that no branch
contains), fetch it manually and re-run the build:

```bash
cd <bb-build>/_deps/msgpack-c/src/msgpack-c
git fetch --depth 1 origin 5ee9a1c8c325658b29867829677c7eb79c433a98
git checkout 5ee9a1c8c325658b29867829677c7eb79c433a98
touch ../msgpack-c-stamp/msgpack-c-download ../msgpack-c-stamp/msgpack-c-gitclone-lastrun.txt
```

## 5. Results

| Check | Result |
|---|---|
| stock `bb v0.87.0 verify` on `forged/proof` | **accepted** |
| stock `bb verify` on `false_honest/proof` (control) | rejected |
| patched bb, `BB_FORGE_LIBRA` unset, honest witness | accepted (regression) |
| patched bb, `BB_FORGE_LIBRA` unset, false witness | rejected (the flag does the cheating) |
| `forgery_test::forged_zk_proof_verifies` (Rust `UltraHonkVerifier::verify`) | **accepted** |
| `forgery_test::stock_proof_for_same_false_witness_is_rejected` | rejected, as expected |
| on-chain `verify_proof` on **Stellar testnet**, forged proof (artifact committed here) | **Ok** — [tx](https://stellar.expert/explorer/testnet/tx/2f356de45aac5bb06020005b46aa1352ff0eb8d19ade09490345f78d182d219c) |
| on-chain `verify_proof`, stock proof for the same false witness | `Error(Contract, #4)` (VerificationFailed) |
| on-chain `verify_proof`, honest proof | Ok — [tx](https://stellar.expert/explorer/testnet/tx/7c28626acf7adf91b00d5eb2412cbec8c4bc084d73c40e81b9e6d6be14da2190) |

On-chain deployment (testnet contract `CDYS…XJS`, instantiated with the
`simple_circuit` ZK VK): the deployed verifier accepts the forged proof whose
witness violates `assert(x != y)`.

The smoking gun is visible in `forged/proof_fields.json`: every round
univariate of the first $\log_2 n = 12$ rounds is constant (all nine
evaluations equal — an honest prover sends random-looking masked univariates),
and `libra_evaluation` is not the mask's true value at $u$,
$s_{\mathrm{honest}} = \langle F, G \rangle$, which is exactly the degree of
freedom the SmallSubgroupIPA identity fails to bind.

## 6. What this proves

`REPORT.md` §7 claimed the ZK flavor is unsound but demonstrated only the two
halves of the attack. This forgery closes the loop: the verifier accepts a
proof whose witness violates the circuit relation, using only the two patched
steps above — both of which exploit the missing $A(1) = 0$ boundary check
documented upstream. Nothing about the verifier, the VK, or the proof format
was modified; any deployment accepting `UltraKeccakZK` proofs (the `identity`
and `tornado_classic` contracts, and the generic contract's ZK path) accepts
such proofs.
