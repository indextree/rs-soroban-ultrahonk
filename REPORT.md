# Cryptographic audit of `ultrahonk-soroban-verifier`

| Scope | |
|---|---|
| **Target** | `crates/ultrahonk-soroban-verifier` |
| **Commit** | `de1dfa7` (branch `feat/zk`) |
| **Proof flavors** | `UltraKeccak`, `UltraKeccakZK` |
| **Proof format** | Barretenberg v0.87.0 |

> [!NOTE]
> Math is written in LaTeX (`$…$` and `$$…$$`) and renders on GitHub and in any
> Markdown viewer with MathJax or KaTeX support.

## Contents

1. [Verdict](#1-verdict)
2. [Method](#2-method)
3. [Notation and assumptions](#3-notation-and-assumptions)
4. [Protocol as implemented](#4-protocol-as-implemented)
5. [Equation-by-equation check](#5-equation-by-equation-check)
6. [Soundness of the non-ZK flavor](#6-soundness-of-the-non-zk-flavor)
7. [The ZK flavor is not sound](#7-the-zk-flavor-is-not-sound)
8. [Other observations](#8-other-observations)
9. [References](#9-references)

[Appendix A. Libra forgery script](#appendix-a-libra-forgery-script)

## 1. Verdict

| Flavor | Result | Details |
|---|---|---|
| `UltraKeccak` (non-ZK) | **Sound** | Every verifier equation is correct. Section 6 gives the soundness argument and concrete error bounds. |
| `UltraKeccakZK` | **Not sound** | The Libra / SmallSubgroupIPA consistency check does not bind the claimed Libra evaluation. A prover can make the sumcheck final check pass for evaluations that violate the circuit relations. No soundness proof exists for this flavor as specified; Section 7 shows exactly where the proof breaks and what restores it. |

### 1.1 Origin of the ZK flaw

The ZK flaw is not a porting error. The Rust code reproduces the Barretenberg
v0.87.0 verifier equation exactly, and the flaw is in that equation. Current
upstream Barretenberg documents the same gap and closes it with an additional
opening (Section 7.4). It cannot be fixed in this verifier alone, because the
fix changes what the prover must send.

### 1.2 Affected contracts

All three contracts in this repository inherit the flaw.

| Contract | Proofs accepted | Why it is exposed |
|---|---|---|
| `contracts/identity` | ZK only | Every proof goes through the ZK path |
| `contracts/tornado_classic` | ZK only | Every proof goes through the ZK path |
| `contracts/rs-soroban-ultrahonk` | Both | The flavor is selected from the proof length (`verifier.rs:119-121`), so a prover can always choose the ZK path |

### 1.3 What was and was not demonstrated

> [!IMPORTANT]
> The two halves of the attack were reproduced against the real Rust functions
> (Section 7.3). A complete forged proof accepted by
> `UltraHonkVerifier::verify` was **not** built: that needs a modified prover
> with the SRS and the circuit's selector polynomials, which was out of reach
> in this audit. The step from the two halves to a full forgery is argued in
> Section 7.2 and uses only honest polynomial openings.

### 1.4 Findings at a glance

| Severity | Finding | Where |
|---|---|---|
| Critical | `UltraKeccakZK`: the Libra consistency identity does not bind `libra_evaluation`, which breaks soundness | Section 7 |
| Low | `load_vk_from_bytes` accepts `log_circuit_size` 1 and 2, for which the ZK relation term vanishes | Section 8, #1 |
| Info | Soundness is per-VK; pairing-point words are not aggregated; the ZK path leaves the last four rows unconstrained; challenges are 128 or about 126 bits | Section 8, #2–5 |
| Doc | Two stale comments in `ec.rs` and `relations.rs` | Section 8, #6 |

## 2. Method

1. Each verifier equation was re-derived from the underlying protocol
   (sumcheck, Libra masking, Gemini folding, Shplonk batching, KZG) and compared
   with the code.
2. The code was compared with the Barretenberg v0.87.0 sources
   (`honk_contract.hpp`, `honk_zk_contract.hpp`, `small_subgroup_ipa.hpp`,
   `decider_proving_key.cpp`) fetched from the `v0.87.0` tag.
3. An independent numerical model (Python, arithmetic mod $r$, commitments
   modelled as evaluations at a secret point) re-implemented the Shplemini and
   Libra equations and checked honest acceptance, rejection of tampered claims,
   and every hard-coded constant against the Rust source.
4. Temporary probes were run against the real Rust code and then removed; the
   working tree contains no changes other than this file.

> [!NOTE]
> **Limits.** The papers listed in Section 9 were cited from memory and were
> not re-fetched; the derivations below are self-contained instead. The
> soundness argument is a proof sketch at the level of detail of the protocol
> papers, in the algebraic group model and random oracle model. It is not
> machine-checked.

## 3. Notation and assumptions

### 3.1 Notation

| Symbol | Meaning |
|---|---|
| $\mathbb{F}$ | The BN254 scalar field, of size about $2^{254}$. |
| $n = 2^d$ | The circuit size, with $d$ = `log_circuit_size`, $1 \le d \le 28$. |
| $[f]$ | $f(\tau)\cdot G_1$, the KZG commitment to $f$ for the SRS trapdoor $\tau$. |
| $D$ | Bound on the degree of any polynomial an adversary can commit to (the number of public $G_1$ SRS points; below $2^{27}$ for the Aztec Ignition SRS). |
| $\mathrm{MLE}_f(u)$ | The multilinear extension of the coefficient vector of $f$ (length $n$), with $u_0$ attached to the lowest index bit. |
| $\lambda$ | Upper bound on the probability of any single Fiat–Shamir challenge value. Each challenge is half of a Keccak-256 output reduced mod $r$: the low 128 bits, or the high bits (about 125.6 bits). $\lambda \le 2^{-125}$ covers both halves. |
| $H = \langle g \rangle$ | The multiplicative subgroup of order 256 used by Libra. |
| $Z_H(X)$ | $X^{256} - 1$, the vanishing polynomial of $H$. |

### 3.2 Assumptions

| ID | Assumption | Statement |
|---|---|---|
| **A1** | AGM + $q$-DLOG | The adversary is algebraic: every $G_1$ element it outputs comes with a polynomial of degree at most $D$ that it commits to. |
| **A2** | ROM | Keccak-256 is modelled as a random oracle. $Q$ is the number of oracle queries the adversary makes. |
| **A3** | SRS | `LHS_G2_BYTES` in `ec.rs` is $\tau\cdot G_2$ for the same $\tau$ as the $G_1$ SRS, and nobody knows $\tau$. `RHS_G2_BYTES` was checked to be the standard BN254 $G_2$ generator; the $\tau\cdot G_2$ constant matches the Barretenberg contract but cannot be verified independently. |
| **A4** | VK | The verification key is fixed before the proof is produced and contains commitments to the circuit's precomputed polynomials, each of degree below $n$, for a **non-recursive** circuit. The v0.87 transcript does not absorb the VK commitments, so soundness is for a fixed VK only. |
| **A5** | Host | The Soroban BN254 host functions implement field arithmetic, MSM, on-curve checks and the pairing correctly. |

## 4. Protocol as implemented

Prover messages and challenges, in transcript order. Items marked ZK exist only
in the ZK flavor.

| # | Prover sends | Challenge derived |
|---|---|---|
| 0 | $n$, number of public inputs, offset, public inputs, 16 pairing-point words, $[w_1], [w_2], [w_3]$ | $\eta, \eta_2, \eta_3$ |
| 1 | $[\mathrm{read\_counts}], [\mathrm{read\_tags}], [w_4]$ | $\beta, \gamma$ |
| 2 | $[\mathrm{lookup\_inverses}], [z_{\mathrm{perm}}]$ | $\alpha_0, \dots, \alpha_{24}$, then gate challenges $\beta_0, \dots, \beta_{27}$ |
| 3 (ZK) | $[G]$ (Libra concatenation), $\sigma$ = `libra_sum` | $\rho_L$ |
| 4 | round univariates $S_i$, 28 rounds (8 values each; 9 in ZK) | $u_i$ after each round |
| 5 | 40 entity evaluations; ZK adds $s$ = `libra_evaluation`, $[A]$, $[Q_L]$, $[M]$, $M(u)$ | $\rho$ |
| 6 | 27 Gemini fold commitments $[A_1], \dots, [A_{27}]$ | $r$ |
| 7 | 28 values $A_l(-r^{2^l})$; ZK adds $G(r), A(gr), A(r), Q_L(r)$ | $\nu$ |
| 8 | Shplonk quotient $[Q]$ | $z$ |
| 9 | KZG quotient $[W]$ | none |

Every prover message is absorbed before the first challenge that depends on it.
$[W]$ is absorbed nowhere, which is correct: no challenge follows it and it is
fixed by the pairing equation. A single-word mutation sweep over all 456 and
507 proof words of a real fixture produced zero acceptances.

## 5. Equation-by-equation check

Each subsection states the equations, then maps them to the code. Two tags
appear in the result column:

- **Model**: the equation was also checked numerically in the independent
  model.
- **Reference**: the equation was compared with the v0.87.0 source text.

### 5.1 Sumcheck

Round check, with initial target $T_0 = 0$:

$$S_i(0) + S_i(1) = T_i, \qquad T_{i+1} = S_i(u_i).$$

Barycentric evaluation on the domain $\lbrace 0, \dots, 7 \rbrace$:

$$S_i(z) = B(z) \sum_{j=0}^{7} \frac{S_i(j)}{d_j\,(z - j)}, \qquad B(z) = \prod_{j=0}^{7} (z - j), \qquad d_j = \prod_{k \ne j} (j - k).$$

Gate separator (the multilinear extension of $x \mapsto \prod_i \beta_i^{x_i}$):

$$\mathrm{pow}_\beta(u) = \prod_{i=0}^{d-1} \bigl(1 + u_i(\beta_i - 1)\bigr).$$

Final check, where $R_k$ are the 26 subrelations and $\mathrm{pow}_\beta(u)$
multiplies the per-row subrelations inside $R_k$:

$$R_0(\mathrm{evals}) + \sum_{k=1}^{25} \alpha_{k-1}\, R_k(\mathrm{evals}) = T_d.$$

| Equation | Code | Result |
|---|---|---|
| Round check, $T_0 = 0$ | `sumcheck.rs:66-69,164` | Correct |
| Barycentric evaluation and the constants $d_j$ | `sumcheck.rs:19-60,80-119` | Correct. Constants recomputed (model) |
| Domain-point shortcut when $u_i \in \lbrace 0, \dots, 7 \rbrace$ | `sumcheck.rs:91-95` | Correct |
| Gate separator | `sumcheck.rs:128-135` | Correct (model) |
| Final check | `sumcheck.rs:193-201` | Correct |
| Batching with independent $\alpha_k$ | `relations.rs:443-449` | Correct |
| Degree: each subrelation has degree at most 6, times $\mathrm{pow}$ gives 7, so 8 points; ZK adds the row-disabling factor, so 9 points | `types.rs:14`, `zk_types.rs:10` | Correct |

### 5.2 Relations

All 26 subrelations were compared term by term with the v0.87.0 relation
library: arithmetic (2), permutation (2), log-derivative lookup (2), delta
range (4), elliptic (2), auxiliary (6), Poseidon2 external (4), Poseidon2
internal (4). All match, including wire/selector roles, $-\tfrac{1}{2}$,
$2^{68}$, $2^{14}$, the Grumpkin constant 17 and the four Poseidon2 diagonal
constants.

Two points that look odd but are right:

- Subrelation 5 (the lookup sum) is **not** multiplied by $\mathrm{pow}_\beta$
  (`relations.rs:149`). It is a statement about a sum over all rows, not a
  per-row identity, so scaling it per row would be wrong.
- The public-input term (`verifier.rs:276-315`) matches the reference, runs
  over the user inputs followed by the 16 pairing-point words, and a zero
  denominator is rejected. With $\mathrm{off}$ = `pub_inputs_offset`:

$$\delta = \prod_{i} \frac{\gamma + x_i + \beta\,(n + \mathrm{off} + i)}{\gamma + x_i - \beta\,(1 + \mathrm{off} + i)}.$$

### 5.3 Gemini

Let $f_0, \dots, f_{34}$ be the unshifted entities and $g_0, \dots, g_4$ the
to-be-shifted entities ($w_1, w_2, w_3, w_4, z_{\mathrm{perm}}$). Define

$$F = \sum_{i=0}^{34} \rho^{\,i} f_i, \qquad G = \sum_{j=0}^{4} \rho^{\,35+j} g_j, \qquad A_0(X) = F(X) + \frac{G(X)}{X},$$

$$A_{l+1}(X^2) = (1 - u_l)\,\frac{A_l(X) + A_l(-X)}{2} + u_l\,\frac{A_l(X) - A_l(-X)}{2X}.$$

Batched evaluation and fold reconstruction, starting from $A_d = v$:

$$v = \sum_{i=0}^{39} \rho^{\,i} v_i, \qquad A_l\bigl(r^{2^l}\bigr) = \frac{2\,r^{2^l} A_{l+1}\bigl(r^{2^{l+1}}\bigr) - A_l\bigl(-r^{2^l}\bigr)\bigl(r^{2^l}(1 - u_l) - u_l\bigr)}{r^{2^l}(1 - u_l) + u_l}.$$

$A_0$ is not committed. It is opened through two derived polynomials that agree
with it at the opening points:

$$A_0(r) = \Bigl(F + \tfrac{1}{r}\,G\Bigr)(r), \qquad A_0(-r) = \Bigl(F - \tfrac{1}{r}\,G\Bigr)(-r).$$

| Equation | Code | Result |
|---|---|---|
| Batched evaluation $v$ | `shplemini.rs:138-155` | Correct |
| Fold reconstruction | `shplemini.rs:234-244` | Correct (derived; model) |
| $A_0$ opened through $F \pm G/r$ | `shplemini.rs:129-130` | Correct (model) |
| Shifted scalars merged onto $w_1, \dots, w_4, z_{\mathrm{perm}}$ | `shplemini.rs:160-162` | Correct; index map matches `Wire` |
| Zero denominators rejected | `shplemini.rs:96-98` | Correct; stricter than the reference |

### 5.4 Shplonk and KZG

For claims $f_k(x_k) = v_k$, the prover's quotient and the verifier's linearised
polynomial are

$$Q(X) = \sum_k \nu^k\, \frac{f_k(X) - v_k}{X - x_k}, \qquad L_z(X) = Q(X) - \sum_k \nu^k\, \frac{f_k(X) - v_k}{z - x_k},$$

so that $L_z(z) = 0$ and $W(X) = L_z(X)/(X - z)$. The verifier computes

$$P_0 = [Q] - \sum_k \frac{\nu^k}{z - x_k}\,[f_k] + \Bigl(\sum_k \frac{\nu^k v_k}{z - x_k}\Bigr) G_1 + z\,[W] = [L_z] + z\,[W]$$

and checks

$$e(P_0,\, G_2)\cdot e(-[W],\, \tau G_2) = 1 \iff L_z(\tau) = (\tau - z)\,W(\tau).$$

| Equation | Code | Result |
|---|---|---|
| Powers: $\nu^0$ for $A_0$ at $r$, $\nu^1$ at $-r$, $\nu^{2l}$ and $\nu^{2l+1}$ for $A_l$ at $\pm r^{2^l}$ | `shplemini.rs:246-265` | Correct |
| Constant term on the $G_1$ generator | `shplemini.rs:247-248,260,275-276` | Correct |
| $P_0 = [L_z] + z\,[W]$ | `shplemini.rs:285` | Correct (model) |
| Pairing check | `ec.rs:91-99` | Correct. The doc comment calling `LHS_G2_BYTES` "negated generator" is wrong; the bytes are right |
| $G_1$ inputs: canonical coordinates, zero padding, on curve | `utils.rs:85-112` | Correct. BN254 $G_1$ has cofactor 1, so no subgroup check is needed |

### 5.5 ZK additions

Initial target and final check, where $R$ is the batched relation value:

$$T_0 = \rho_L\,\sigma, \qquad R(\mathrm{evals})\cdot\Bigl(1 - \prod_{i=2}^{d-1} u_i\Bigr) + \rho_L\, s = T_d.$$

The factor $1 - \prod_{i \ge 2} u_i$ is one minus the sum of the Lagrange basis
polynomials of the last four rows. Lagrange evaluations on $H$ and the challenge
polynomial (given by its values on $H$):

$$L_{g^i}(r) = \frac{Z_H(r)}{256\,\bigl(r\,g^{-i} - 1\bigr)}, \qquad F = \bigl(1,\; 1, u_0, \dots, u_0^8,\; \dots,\; 1, u_{27}, \dots, u_{27}^8,\; 0, 0, 0\bigr).$$

Consistency identity checked at $r$, with $L_1 = L_{g^0}$ and
$L_{\mathrm{last}} = L_{g^{255}}$:

$$L_1(r)\,A(r) + (r - g^{-1})\bigl(A(gr) - A(r) - F(r)\,G(r)\bigr) + L_{\mathrm{last}}(r)\bigl(A(r) - s\bigr) = Z_H(r)\,Q_L(r).$$

| Equation | Code | Result |
|---|---|---|
| Initial target $T_0 = \rho_L\,\sigma$ | `zk_sumcheck.rs:170` | Correct |
| Row-disabling factor | `zk_sumcheck.rs:132-142` | Correct (model) |
| Final check | `zk_sumcheck.rs:205-209` | Matches reference |
| Masking polynomial $M$ batched at $\rho^0$, entities from $\rho^1$ | `zk_shplemini.rs:226-243` | Correct (model) |
| Libra openings at $r,\ gr,\ r,\ r$ with powers $\nu^{58}, \dots, \nu^{61}$, disjoint from the Gemini powers (at most 55) | `zk_shplemini.rs:359-379` | Correct (model) |
| $g$ has order exactly 256, $g\cdot g^{-1} = 1$; $r \notin H$ enforced | `zk_shplemini.rs:33-56,80-85` | Correct (model) |
| Lagrange evaluations and challenge polynomial | `zk_shplemini.rs:87-121` | Correct (model) |
| Consistency identity | `zk_shplemini.rs:128-134` | **Matches reference, but the identity itself is insufficient. See Section 7** |

## 6. Soundness of the non-ZK flavor

### 6.1 Statement

**Theorem 1.** Assume A1–A5. Fix a VK and public inputs. Suppose an adversary
making $Q$ random-oracle queries outputs an `UltraKeccak` proof that
`verify_non_zk` accepts. Then, except with probability at most

$$(Q + 1)\,\varepsilon + \mathrm{Adv}_{q\text{-DLOG}} + \frac{Q^2}{2^{253}},$$

$$\varepsilon = \max\bigl(\, d(2D + 2)\lambda,\;\; (D + 2d)\lambda,\;\; 55\lambda,\;\; (40 + 40d + 1)\lambda,\;\; 7\lambda,\;\; (25 + d)\lambda \,\bigr),$$

there are polynomials $w_1, w_2, w_3, w_4, z_{\mathrm{perm}}$ and the three
lookup polynomials, all of degree below $n$ and extractable from the adversary,
such that for the derived $\eta, \eta_2, \eta_3, \beta, \gamma$:

1. subrelations 0–4 and 6–25 vanish on every row of the hypercube, and
2. subrelation 5 sums to zero over the hypercube,

with the public-input term $\delta$ computed from the supplied public inputs.

With $D < 2^{27}$, $d \le 28$ and $\lambda \le 2^{-125}$ the dominant term is
the Gemini one, and $\varepsilon < 2^{-91}$.

The theorem states soundness relative to Barretenberg's relation system. That
1–2 imply the copy constraints and lookup membership is the standard
grand-product and log-derivative argument: both are polynomial identities in
$(\beta, \gamma)$ and $(\gamma, \eta, \eta_2, \eta_3)$ of degree $O(n)$ over
polynomials committed before those challenges, adding $O(n)\,\lambda$. That the
relation system encodes the Noir program is a property of the circuit compiler
and outside this audit.

### 6.2 Proof

The proof works backwards through the verifier. Each step turns what the
previous one established into a stronger statement, at the cost of one error
term:

| Step | Establishes | Error |
|---|---|---|
| Lemma 1 (KZG) | Pairing check passes ⇒ $L_z(z) = 0$ | $\mathrm{Adv}_{q\text{-DLOG}}$ |
| Lemma 2 (Shplonk) | $L_z(z) = 0$ ⇒ every opening claim holds | $(D + 2d)\lambda + 55\lambda$ |
| Lemma 3 (Gemini) | Opening claims ⇒ degree bounds, and the 40 evaluations are true MLE values at $u$ | $d(2D + 2)\lambda + (40 + 40d + 1)\lambda$ |
| Lemma 4 (sumcheck) | True evaluations ⇒ the batched relation sums to zero over the hypercube | $7\lambda$ per round |
| Lemma 5 (batching) | Batched sum is zero ⇒ statements 1–2 of Theorem 1 | $(25 + d)\lambda$ |
| Fiat–Shamir | Interactive ⇒ non-interactive | factor $Q + 1$, plus $Q^2 / 2^{253}$ |

**Lemma 1 (KZG).** If the pairing check passes then
$L_z(X) + z\,W(X) = X\,W(X)$ as polynomials, hence $L_z(z) = 0$, unless the
adversary breaks $q$-DLOG.

*Proof.* By A1 all commitments in $P_0$ and $[W]$ come with polynomials. The
pairing equation says the polynomial $L_z(X) - (X - z)\,W(X)$ vanishes at
$\tau$. If it is non-zero, $\tau$ is one of its roots and can be found by
factoring. $\blacksquare$

**Lemma 2 (Shplonk).** If $L_z(z) = 0$ then every claim $f_k(x_k) = v_k$ holds,
except with probability $(D + 2d)\lambda + 55\lambda$.

*Proof.* Let $T$ be the set of distinct opening points; the verifier rejects
if $z \in T$. Multiplying $L_z(z) = 0$ by $\prod_{t \in T}(z - t)$ gives
$P(z) = 0$ for

$$P(X) = Q(X) \prod_{t \in T} (X - t) - \sum_k \nu^k \bigl(f_k(X) - v_k\bigr) \prod_{t \in T,\ t \ne x_k} (X - t).$$

$Q$, all $f_k$, all $v_k$ and $\nu$ are fixed before $z$, and
$\deg P \le D + 2d$, so $P \equiv 0$ except with probability $(D + 2d)\lambda$.
Evaluating $P \equiv 0$ at $t \in T$ gives

$$\sum_{k\,:\,x_k = t} \nu^k \bigl(f_k(t) - v_k\bigr) = 0.$$

The powers $\nu^k$ are distinct and at most 55, and the $f_k$, $v_k$ are fixed
before $\nu$, so each term is zero except with probability $55\lambda$.
$\blacksquare$

The claims so established are

$$\Bigl(F + \tfrac{1}{r} G\Bigr)(r) = a_0^{+}, \qquad \Bigl(F - \tfrac{1}{r} G\Bigr)(-r) = a_0, \qquad A_l\bigl(r^{2^l}\bigr) = a_l^{+}, \quad A_l\bigl(-r^{2^l}\bigr) = a_l \quad (1 \le l < d),$$

where the $a_l$ are the prover's values and the $a_l^{+}$ are the values the
verifier computed by the fold reconstruction from $v$.

**Lemma 3 (Gemini).** Given those claims, except with probability
$d(2D + 2)\lambda + (40 + 40d + 1)\lambda$: every entity polynomial has degree
below $n$; every to-be-shifted polynomial vanishes at 0;
$v_i = \mathrm{MLE}_{f_i}(u)$ for the 35 unshifted entities; and the 5 shifted
evaluations equal the MLE of the shifted coefficient vector
$(g_1, \dots, g_{n-1}, 0)$.

*Proof.* Put $B = X F + G$, so $a_0^{+} = B(r)/r$ and $a_0 = -B(-r)/r$. The
verifier's reconstruction formula is the fold relation solved for the positive
evaluation, so the claims say that the following polynomials vanish at $X = r$:

$$I_0(X) = 2X^2 A_1(X^2) - \bigl(X(1 - u_0) + u_0\bigr) B(X) + \bigl(X(1 - u_0) - u_0\bigr) B(-X),$$

$$I_l(X) = 2X A_{l+1}(X^2) - \bigl(X(1 - u_l) + u_l\bigr) A_l(X) - \bigl(X(1 - u_l) - u_l\bigr) A_l(-X), \qquad 1 \le l < d, \quad A_d := v.$$

All polynomials here are fixed before $r$ and have degree at most $2D + 2$, so
all $I_l \equiv 0$ except with probability $d(2D + 2)\lambda$. The constant
coefficient of $I_0$ is $-2u_0\,B(0)$, so $G(0) = 0$ unless $u_0 = 0$
(probability $\lambda$). Then $A_0 = B/X = F + G/X$ is a polynomial and each
$A_{l+1}$ is the fold of $A_l$.

Write $A_0 = \sum_j X^{jn}\, C_j(X)$ with $\deg C_j < n$. Folding $d$ times
gives $\sum_j Y^j\, \mathrm{MLE}_{C_j}(u)$, which must equal the constant $v$.
So

$$\mathrm{MLE}_{C_0}(u) = v, \qquad \mathrm{MLE}_{C_j}(u) = 0 \quad (j \ge 1).$$

$A_0$, $G(0)$ and $v$ are polynomials in $\rho$ of degree at most 39 whose
coefficients (the $f_i$, $g_j$, $v_i$, $u$) are fixed before $\rho$. So except
with probability $40\lambda$ the statements hold per entity: $g_j(0) = 0$, the
MLE of the low chunk of $f_i$ equals $v_i$, and every high chunk of every
entity has MLE zero at $u$. The entity polynomials are fixed before $u$, so if
some entity had a non-zero high chunk, that chunk's MLE would be a non-zero
multilinear polynomial vanishing at the random point $u$: probability at most
$d\lambda$ per entity. Hence all entities have degree below $n$, which also
makes the shifted vector end in 0. $\blacksquare$

**Lemma 4 (sumcheck).** Let

$$P(x) = \mathrm{pow}_\beta(x) \Bigl( R_0(x) + \sum_{k \ge 1,\ k \ne 5} \alpha_{k-1} R_k(x) \Bigr) + \alpha_4\, R_5(x)$$

with the multilinear polynomials from Lemma 3. If the round checks and the
final check pass with evaluations that are the true values at $u$, then
$\sum_{x \in \lbrace 0,1 \rbrace^d} P(x) = 0$, except with probability
$7\lambda$ per round.

*Proof.* Standard. $P$ has degree at most 7 in each variable. If the claimed
sum is false, then in some round the prover's $S_i$ differs from the true
partial-sum polynomial; two distinct degree-7 polynomials agree at the random
$u_i$ with probability at most $7\lambda$, and a wrong claim carried to the end
fails the final check. $\blacksquare$

**Lemma 5 (batching).** If $\sum_x P(x) = 0$ then statements 1–2 of Theorem 1
hold, except with probability $(25 + d)\lambda$.

*Proof.* $\sum_x P(x)$ is a polynomial in the 25 challenges $\alpha_k$ and the
$d$ gate challenges, of degree 1 in each, whose coefficients depend only on
data fixed before those challenges. For $k \ne 5$ the monomial
$\alpha_{k-1} \prod_i \beta_i^{x_i}$ (with no $\alpha$ factor for $k = 0$) has
coefficient $R_k(x)$, and $\alpha_4$ alone has coefficient $\sum_x R_5(x)$. No
two of these monomials coincide: the $k = 5$ term carries no gate challenge and
$P$ has no other $\alpha_4$ term. A non-zero polynomial of this shape vanishes
at a random point with probability at most $(25 + d)\lambda$. $\blacksquare$

**Fiat–Shamir.** Each lemma bounds the probability that one fresh challenge
turns a false intermediate claim into a true one, so the interactive protocol
is round-by-round sound with error $\varepsilon$. For such protocols the
Fiat–Shamir transform in the ROM loses a factor $Q + 1$. The transcript chains
challenges as $c_i = H(c_{i-1} \parallel m_i)$ with $c_{i-1}$ reduced mod $r$,
which binds the whole prefix except for chain collisions (at most
$Q^2 / 2^{253}$). Padding rounds beyond $d$ are absorbed but never checked;
they only feed later challenges. $\blacksquare$

### 6.3 Remarks on the bound

- Challenges are 128-bit (or about 126-bit), not field-sized. Every term above
  is therefore $\text{degree} \times 2^{-125}$ or better, not
  $\text{degree} \times 2^{-254}$. This is a Barretenberg design choice.
- Canonical-encoding checks on scalars and public inputs are not needed for
  Theorem 1 but make the accepted encoding unique, which callers that key
  storage on raw public-input bytes (nullifiers) rely on.

## 7. The ZK flavor is not sound

> [!WARNING]
> **In short.** The v0.87.0 consistency identity leaves $A(1)$ unconstrained
> (7.1). That makes `libra_evaluation` a free value, which the prover can solve
> for so that the sumcheck final check passes for arbitrary evaluations (7.2).
> Both halves were reproduced against the Rust code (7.3). The fix needs a
> change to the proof format, not only to the verifier (7.4).

### 7.1 Where the proof breaks

The ZK sumcheck proves

$$\sum_{x \in \lbrace 0,1 \rbrace^d} \bigl[ R'(x) + \rho_L\, G(x) \bigr] = \rho_L\, \sigma,$$

where $R'$ is the row-disabled relation polynomial, $G$ is the committed Libra
masking polynomial and $\sigma$ = `libra_sum`. Since $G$, $\sigma$ and all
witness commitments are fixed before $\rho_L$, this would give
$\sum_x R'(x) = 0$ with error $\lambda$ **if** the final check used the true
value $G(u)$.

The final check uses $s$ = `libra_evaluation`, a number the prover sends after
seeing $u$. Its only link to $G$ is the SmallSubgroupIPA identity, which is
meant to prove $s = \langle F, G \rangle$ over $H$:

$$L_1(X)\,A(X) + (X - g^{-1})\bigl(A(gX) - A(X) - F(X)\,G(X)\bigr) + L_{\mathrm{last}}(X)\bigl(A(X) - s\bigr) = Z_H(X)\,Q_L(X).$$

This is intended to enforce three things: $A(1) = 0$, the running-sum step on
$H$, and $A(g^{-1}) = s$. But the three terms are added without separating
challenges. On $H$ the identity gives:

- at $X = g^i$, $1 \le i \le 254$: the step
  $A(g^{i+1}) = A(g^i) + F(g^i)\,G(g^i)$;
- at $X = g^{-1}$: $A(g^{-1}) = s$;
- at $X = 1$: **one** equation for the two intended constraints $A(1) = 0$ and
  $A(g) = A(1) + F(1)\,G(1)$:

$$A(1) + (1 - g^{-1})\bigl(A(g) - A(1) - F(1)\,G(1)\bigr) = 0.$$

So $A(1) = a$ is a free parameter. Taking

$$A(g) = a + F(1)\,G(1) - \frac{a}{1 - g^{-1}}$$

and the honest step elsewhere gives

$$s = \langle F, G \rangle - \frac{a}{g - 1},$$

and since $g \ne 1$, **every** value of $s$ is reachable. The left side still
vanishes on all of $H$, so $Q_L$ is a genuine polynomial and all four openings
$G(r), A(gr), A(r), Q_L(r)$ are true evaluations of committed polynomials.

### 7.2 From a free $s$ to a forged proof

A prover that wants to "prove" a false statement proceeds as follows.

1. Commit to arbitrary wire, lookup and $z_{\mathrm{perm}}$ polynomials of
   degree below $n$, and an arbitrary $G$. Send any $\sigma$.
2. In each sumcheck round send any $S_i$ with $S_i(0) + S_i(1) = T_i$.
3. After the last $u_i$, compute the true evaluations of all 40 entities at
   $u$ (the precomputed ones are public circuit data) and solve the final check
   for $s$:

$$s = \frac{T_d - R(\mathrm{evals})\cdot\bigl(1 - \prod_{i \ge 2} u_i\bigr)}{\rho_L}.$$

4. Build $A$ with $A(1) = -(s - \langle F, G \rangle)(g - 1)$ as in 7.1,
   compute $Q_L$, commit to both.
5. Run Gemini, Shplonk and KZG honestly. Every opening claim is true.

Nothing in steps 1–5 depends on the witness satisfying the circuit or on the
public inputs being the right ones. Cost: one prover run.

### 7.3 Reproduction

Both halves were run against the real Rust functions on the
`simple_circuit` ZK fixture (temporary tests, since removed):

| Probe | Result |
|---|---|
| `check_libra_evaluations_consistency`, honest fixture | `Ok` |
| same function, openings of a forged $A, Q_L$ with $s$ = `0xdeadbeef` while the true $\langle F, G \rangle$ is a different 254-bit value | `Ok` |
| same forged openings with the **true** inner product as $s$ | `Err` |
| `verify_zk_sumcheck`, all 40 evaluations replaced by $7, 8, 9, \dots$ | `Err` |
| same garbage evaluations with `libra_evaluation` solved as in step 3 | `Ok` |

For the forged case the quotient was checked to be an exact polynomial
(remainder zero on division by $X^{256} - 1$) before any challenge $r$ was
chosen. A self-contained script is in Appendix A.

### 7.4 Upstream status and fix

The current upstream `small_subgroup_ipa.hpp` states that this identity
"alone is **not** sufficient for soundness", that it "has a one-dimensional
kernel at X = 1", and that soundness "additionally requires the boundary
opening A(1) = 0", which upstream now enforces as a fifth opening on $[A]$
inside the Shplonk batch. v0.87.0 has four openings and no such check.

The verifier cannot add that opening on its own: the prover's Shplonk quotient
must include the extra claim, so v0.87.0 proofs would stop verifying.

Options, in order of preference:

1. **Stop accepting `UltraKeccakZK` proofs** until the stack moves to a
   Barretenberg release that includes the boundary opening, then port that
   proof format. For the contracts this means non-ZK proofs only, which gives
   up witness privacy in the mixer and identity examples; that trade-off is
   the owner's call.
2. At minimum, make the generic verifier contract pin its flavor at
   construction instead of selecting by proof length, so non-ZK deployments
   are not exposed to the ZK path.

### 7.5 What holds once the boundary is enforced

**Theorem 2 (conditional).** If the verifier additionally obtained a sound
opening $A(1) = 0$, then Theorem 1 holds for the ZK flavor with the
row-disabled relations (constraints on the last four rows are not enforced, by
design) and $\varepsilon$ enlarged by

$$\max\bigl(\, \lambda,\;\; 8\lambda,\;\; 8(28 - d)\lambda,\;\; (D + 600)\lambda,\;\; 61\lambda \,\bigr).$$

*Sketch.* With $A(1) = 0$ the three constraints of 7.1 separate, so the
identity as a polynomial identity (error $(D + 600)\lambda$ over $r$) gives

$$s = \sum_{i=0}^{254} F(g^i)\,G(g^i) = \langle F, G \rangle,$$

the index-255 entry of $F$ being zero. $\langle F, G \rangle$ is the evaluation
at $u$ of the polynomial

$$G(X_0, \dots, X_{27}) = c + \sum_{i=0}^{27} g_i(X_i)$$

read off the values of the committed $G$ on $H$, with each $g_i$ of degree at
most 8. Sumcheck on $R' + \rho_L G$ then has degree at most 8 per round
($8\lambda$), and $\rho_L$ separates $\sum_x R'(x) = 0$ from
$\sum_x G(x) = \sigma$ ($\lambda$). The masking polynomial $M$ is one more
batched claim at $\rho^0$, and the Libra openings are four more Shplonk claims
at distinct powers ($61\lambda$).

One subtlety, present in the reference as well: $F$ includes powers of all 28
challenges, but only $d$ rounds are checked. The terms $g_i(u_i)$ for
$i \ge d$ are an additive constant that depends on challenges derived from
prover-chosen padding **after** the real rounds. An honest prover has
$g_i = 0$ there. A cheating prover would need that constant to hit a specific
field element; each attempt succeeds with probability at most
$8(28 - d)\lambda$, which is the third term above. This is not exploitable but
should be kept in mind if the format changes.

## 8. Other observations

| # | Severity | Observation |
|---|---|---|
| 1 | Low | `load_vk_from_bytes` accepts `log_circuit_size` 1 and 2. For those sizes the ZK row-disabling factor $1 - \prod_{i \ge 2} u_i$ is identically 0 and the relation term disappears from the final check (`zk_sumcheck.rs:132-142`). Barretenberg does not emit such VKs; rejecting $d < 3$ costs nothing. |
| 2 | Info | Soundness is per-VK (A4): v0.87 does not hash the VK commitments into the transcript. Safe for a VK fixed in contract storage. |
| 3 | Info | The 16 pairing-point words are bound by the transcript and the permutation argument but never aggregated. Sound only for non-recursive circuits, as `VERIFIER_PROVENANCE.md` states. |
| 4 | Info | The ZK path does not enforce constraints on the last four rows. v0.87 reserves those rows in both flavors (`decider_proving_key.cpp`), and the fixture VKs are byte-identical across flavors, so this is safe for bb-generated VKs. |
| 5 | Info | Effective challenge size is 128 or about 126 bits; see the remark after Theorem 1. |
| 6 | Doc | `ec.rs:28` describes `LHS_G2_BYTES` as the negated generator; it is $\tau\cdot G_2$. `relations.rs` and `ec.rs` cite v0.82.2 while the crate targets v0.87.0. |

## 9. References

Cited from memory; ePrint numbers should be checked before quoting.

- Lund, Fortnow, Karloff, Nisan. *Algebraic methods for interactive proof systems* (sumcheck). 1992.
- Chen, Bünz, Boneh, Zhang. *HyperPlonk*. ePrint 2022/1355.
- Xie, Zhang, Zhang, Papamanthou, Song. *Libra* (zero-knowledge sumcheck masking). ePrint 2019/317.
- Bootle, Chiesa, Hu, Orrù. *Gemini*. ePrint 2022/420.
- Boneh, Drake, Fisch, Gabizon. *Efficient polynomial commitment schemes for multiple points and polynomials* (Shplonk). ePrint 2020/081.
- Kate, Zaverucha, Goldberg. *Constant-size commitments to polynomials and their applications* (KZG). Asiacrypt 2010.
- Fuchsbauer, Kiltz, Loss. *The algebraic group model and its applications*. ePrint 2017/620.
- Gabizon, Williamson, Ciobotaru. *PLONK* (grand-product permutation argument). ePrint 2019/953.
- Haböck. *Multivariate lookups based on logarithmic derivatives* (logUp). ePrint 2022/1530.
- Ben-Sasson, Chiesa, Spooner. *Interactive oracle proofs* (Fiat–Shamir in the ROM). ePrint 2016/116.
- Canetti et al. *Fiat–Shamir: from practice to theory* (round-by-round soundness). STOC 2019.
- Barretenberg `v0.87.0`, commit `9081b0ed38c43c120afb7c80f8f6cd418ca5ad70`, and current upstream `small_subgroup_ipa.hpp`.

## Appendix A. Libra forgery script

Pure Python 3, no dependencies. It builds $A$ and $Q_L$ for an arbitrary claimed
$s$, checks that $Q_L$ is an exact polynomial, **then** samples $r$ and
evaluates the verifier's identity. Expected output:
`true <F,G> == claimed s ? False | verifier identity satisfied ? True`.

```python
import random

# BN254 scalar field modulus and the generator g of the order-256 subgroup H.
P = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
GEN = 0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76
N = 256


def inv(a):
    return pow(a % P, P - 2, P)


GEN_INV = inv(GEN)
N_INV = inv(N)


def evaluate(coeffs, x):
    return sum(c * pow(x, i, P) for i, c in enumerate(coeffs)) % P


def interpolate(values):
    """Coefficients of the polynomial of degree < 256 with these values on H."""
    return [
        N_INV * sum(v * pow(GEN_INV, i * j, P) for i, v in enumerate(values)) % P
        for j in range(N)
    ]


def add(a, b):
    size = max(len(a), len(b))
    a = a + [0] * (size - len(a))
    b = b + [0] * (size - len(b))
    return [(x + y) % P for x, y in zip(a, b)]


def neg(a):
    return [-c % P for c in a]


def mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % P
    return out


# --- Prover: everything in this block is fixed before the challenge r ---

u = [random.randrange(2**128) for _ in range(28)]  # sumcheck challenges
# Challenge polynomial F and committed Libra polynomial G, as values on H.
F = [1] + [pow(u[i // 9], i % 9, P) for i in range(252)] + [0, 0, 0]
G = [random.randrange(P) for _ in range(N)]
true_s = sum(f * g for f, g in zip(F, G)) % P
s = 0xDEADBEEF  # the value the prover WANTS to claim

# Choose A(1) = a0 != 0, absorb it in the first step, then step honestly.
a0 = -(s - true_s) * (GEN - 1) % P
A = [a0, (a0 + F[0] * G[0] - a0 * inv(1 - GEN_INV)) % P]
for i in range(1, 255):
    A.append((A[-1] + F[i] * G[i]) % P)

F_c, G_c, A_c = interpolate(F), interpolate(G), interpolate(A)
L_first = [N_INV] * N                                   # L_1
L_last = [N_INV * pow(GEN, j, P) % P for j in range(N)]  # L_{g^255}
A_shifted = [c * pow(GEN, j, P) % P for j, c in enumerate(A_c)]  # A(gX)

# Left side of the consistency identity, as a polynomial in X.
step = add(add(A_shifted, neg(A_c)), neg(mul(F_c, G_c)))
lhs = add(
    add(mul(L_first, A_c), mul([-GEN_INV % P, 1], step)),
    mul(L_last, add(A_c, [-s % P])),
)

# Q_L = lhs / (X^256 - 1); the remainder must be zero.
Q_L = [0] * (len(lhs) - N)
for i in range(len(lhs) - 1, N - 1, -1):
    Q_L[i - N] = lhs[i]
    lhs[i - N] = (lhs[i - N] + lhs[i]) % P
    lhs[i] = 0
assert all(c == 0 for c in lhs), "quotient is not a polynomial"

# --- Verifier: r is sampled AFTER A and Q_L are fixed ---

r = random.randrange(2**128)  # Gemini challenge
Z_H = (pow(r, N, P) - 1) % P


def lagrange(i):
    return Z_H * N_INV * inv(r * pow(GEN_INV, i, P) - 1) % P


F_r = sum(F[i] * lagrange(i) for i in range(N)) % P
A_r, A_gr, G_r = evaluate(A_c, r), evaluate(A_c, GEN * r % P), evaluate(G_c, r)
diff = (
    lagrange(0) * A_r
    + (r - GEN_INV) * (A_gr - A_r - F_r * G_r)
    + lagrange(255) * (A_r - s)
    - Z_H * evaluate(Q_L, r)
)
print(
    "true <F,G> == claimed s ?", true_s == s,
    "| verifier identity satisfied ?", diff % P == 0,
)
```

## Appendix B. The full forgery flow

An attacker who wants verify to accept a false statement (say, a mixer withdrawal with a nullifier they have no note for) would do this:

1. Pick the false public inputs and start the transcript with them.
2. Commit to arbitrary witness polynomials (wires, lookup polynomials, `z_perm`). They need not satisfy the circuit.
3. Commit to any Libra polynomial $G$ and send any `libra_sum`.
4. Sumcheck rounds: in each round send any univariate whose values at 0 and 1 add up to the current target. This is the only per-round check, so it is trivial to satisfy.
5. Send the true evaluations of all 40 polynomials at the sumcheck point u. They must be true, because Gemini/Shplonk/KZG will check them against the commitments.
6. Solve for `libra_evaluation`: the final sumcheck check is one linear equation in this value, so pick whatever makes it hold.
7. Forge the Libra argument: build the grand-sum polynomial $A$ with the non-zero $A(1)$ that makes the identity hold for the value from step 6, compute the quotient, commit to both.
8. Finish honestly: Gemini folds, Shplonk quotient, KZG opening. Every opening claim is a true evaluation of a committed polynomial, so the pairing check passes.

Steps 4, 6 and 7 are where the cheating happens, and those are the two things I tested. Steps 5 and 8 are ordinary honest proving.

### Why I did not build it

Steps 2, 5, 7 and 8 need three things I did not have:

- The SRS G1 points. Committing to a polynomial means a multi-scalar multiplication over the Aztec SRS. The verifier only holds one G2 point. The points are public but were not on this machine.
- The circuit's precomputed polynomials. Step 5 needs the true values of the 27 selector, permutation and table polynomials at u. The VK contains only their commitments. The polynomials come from Barretenberg's trace construction, which bb computes internally and does not export. nargo and bb are also not installed here.
- A complete prover. Every challenge is a hash of everything sent before it, so the whole proof has to be generated in one consistent run. That means a modified Barretenberg prover (a C++ build) or a from-scratch reimplementation of the UltraHonk ZK prover.

Editing an existing valid proof is not a shortcut. Changing a public input or any early message changes the first challenge, and with it every later challenge, so every opening must be recomputed from the witness polynomials.

### What this leaves open

The claim "a full forgery exists" rests on the argument that steps 5 and 8 are honest openings the verifier must accept. I am confident in that, and upstream's own note that the identity "alone is not sufficient for soundness" supports it. But until an end-to-end forged proof is produced, I have not ruled out by test that some other check I overlooked would block it.

The realistic way to close that gap is to install bb `0.87.0`, patch its ZK prover to do steps 4, 6 and 7, and run the output through verify. It is a substantial piece of work; say if you want me to attempt it.