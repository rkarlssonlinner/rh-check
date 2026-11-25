# Stage 1A: Exploit Taxonomy and Coverage Matrix

Research date: 2026-11-24

## Categories

### C1 — Logic (the type theory itself)

No known inconsistency in Lean's Calculus of Inductive Constructions. The meta-theory (propext, function extensionality, proof irrelevance, quotient soundness) is believed consistent. No catalogue entry falls in this category. Record any future claims here.

### C2 — Kernel implementation

Code inside the kernel that checks declarations. The largest category — 10 of 16 catalogue entries.

Shared structural signatures:
- Inductive types with unusual nested structure, phantom parameters, or parameters applied to non-parameter terms
- Projection expressions where the structure name does not match the projected value's type
- Recursors whose declared types are inconsistent with their parent inductive
- Free variable references (fvar) in declaration values (especially opaque)
- Types that are Prop only after universe normalization or that get stuck during reduction

Entries: E01, E02, E03, E04, E06, E07, E08, E11, E12, E13

### C3 — Runtime

Memory management and libraries underneath the kernel.

Shared structural signatures:
- Reference counter overflow (E09): leaves NO trace in the export; purely runtime
- GMP arithmetic bugs (E10): triggered by very large Nat literals combined with kernel-accelerated arithmetic; the LITERALS are visible in the export, the wrong RESULTS are not

Entries: E09, E10

### C4 — Elaboration and metaprograms

Code running in the same process as the kernel. The module system fix (E05) is the only entry. It leaves no trace in the kernel export because the export contains only final declarations.

Entries: E05

### C5 — Statement (what the theorem says)

Attacks on the meaning of the theorem, not the proof. Notation shadowing (E14) redefines constants so the same string means something different.

Structural signature: the theorem's type expression references locally-defined constants instead of the expected Mathlib constants. D6 catches this by comparing against the Mathlib export at the pinned commit.

Entries: E14 (overlaps with C6)

### C6 — Grader and harness

Tools around Lean that judge whether a proof is acceptable. E14 also falls here (the grader failed to compare exported types). Reward-hacking papers (not catalogued as separate entries) describe RL provers exploiting benchmark evaluation loopholes.

Entries: E14 (overlaps with C5)

### C7 — Assumptions (axioms and escape hatches)

sorry, native_decide, implemented_by, @[extern], and custom axioms.

Structural signature: axiom declarations beyond propext / Classical.choice / Quot.sound in the dependency cone. Declarations with unsafe, partial, or @[extern] attributes. References to sorryAx, Lean.ofReduceBool, Lean.trustCompiler.

Entries: E15

### C8 — Packaging (decorative structure)

Patterns with no logical effect: predicates defined as True, fields closed by rfl, witnesses built by assignment.

Structural signature: D9 flags these. Never report as exploits unless a D1-D8 detector also fires on the same declaration.

Entries: E16

---

## Detector List (revised from seed D1-D9)

| ID | Target | Catches | Notes |
| --- | --- | --- | --- |
| D1 | Axioms in the dependency cone beyond propext, Classical.choice, Quot.sound | E15 | Standard axiom audit |
| D2 | Inductive types: nested, mutual, reflexive, phantom params, unusual universe levels, parameter applied to non-param terms | E02, E06, E07, E12 | Cross-check against Mathlib inductives at pinned commit |
| D3 | Projection expressions with structure/value type mismatch | E02, E13 | The direct signature of CVE-2026-72844 |
| D4 | Large Nat literals and kernel-accelerated arithmetic | E10, E11 | Flag literals > 1 MB; alert at > 100 MB |
| D5 | Reduction-heavy: decide, deep/large terms, stuck types | E07, E08 | Extended to include stuck types (E08) |
| D6 | Statement integrity: five main theorem types must reference only Mathlib constants at the pinned commit | E14 | The DeepMind notation-shadowing attack |
| D7 | unsafe, partial, opaque, implemented_by, @[extern], initialize; free variables in any declaration value | E01, E04, E15 | Extended from seed D7 to include fvar scanning (E01, E04) |
| D8 | Distinct expressions with identical structural hashes | E02 (hash-collision component) | Optional / advanced; low priority |
| D9 | Decorative patterns: predicates as True, fields as rfl | E16 | Report as packaging only |

### Proposed new detectors

| ID | Target | Catches | Rationale |
| --- | --- | --- | --- |
| D10 | Types that resolve to Prop only after universe normalization | E03 | No existing detector covers is_prop universe bugs. Scan for types with Sort parameters where the sort is 0 only after substituting universe assignments. |
| D11 | Recursor / inductive consistency: recursor type and computation rules must match the inductive's declared constructor types and parameter structure | E07, E12 | Catches the union-find caching exploit (E07) and validates the hardening from E12. Reconstruct expected recursor type from the inductive declaration and compare. |

---

## Coverage Matrix

| Exploit | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | D11 | Export visible? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E01 (cache poison/opaque fvar) | | | | | | | **X** | | | | | yes |
| E02 (nested proj mismatch) | | **X** | **X** | | | | | x | | | | yes |
| E03 (is_prop universe) | | | | | | | | | | **X** | | yes |
| E04 (fvar leakage) | | | | | | | **X** | | | | | yes |
| E05 (module system) | | | | | | | | | | | | **NO** |
| E06 (inductive param bypass) | | **X** | | | | | | | | | | yes |
| E07 (defeq union-find) | | **X** | | | **X** | | | | | | **X** | yes |
| E08 (is_prop stuck) | | | | | **X** | | | | | | | yes |
| E09 (refcount overflow) | | | | | | | | | | | | **NO** |
| E10 (GMP bug) | | | | **X** | | | | | | | | partial (literals visible; wrong result not) |
| E11 (Nat cap) | | | | **X** | | | | | | | | yes |
| E12 (recursor typecheck) | | **X** | | | | | | | | | **X** | yes |
| E13 (nanoda proj bug) | | | **X** | | | | | | | | | yes |
| E14 (notation shadow) | | | | | | **X** | | | | | | yes |
| E15 (sorry/native_decide/etc) | **X** | | | | | | **X** | | | | | yes |
| E16 (decorative patterns) | | | | | | | | | **X** | | | yes |

**X** = primary detector for this exploit. **x** = secondary/partial coverage.

---

## Exploits NOT detectable from the export

| Exploit | Why | Alternative check |
| --- | --- | --- |
| E05 (module system) | Module-level issue; export contains only final declarations | Re-check on patched kernel (v4.33.0+) |
| E09 (refcount overflow) | Runtime memory corruption; no structural trace | Re-check on patched kernel (v4.34.0+) with GMP 6.3.0+ |
| E10 (GMP bug) | The wrong arithmetic RESULT is not in the export; only the input literals are | Re-check on patched kernel built against GMP 6.3.0+; D4 flags the input literals as suspicious |

These three require re-checking the proof on a fully patched Lean (v4.36.0 or later, with GMP 6.3.0+) and in nanoda. The export scan cannot clear them.

---

## Checks performed

1. Every soundness fix in the Lean release notes from v4.30 through v4.34.1 appears in the catalogue: v4.32.1 (E01), v4.32.2 (E02), v4.33.0 (E03, E04, E05), v4.33.1 (E06), v4.34.0 (E07, E08, E09, E10, E11, E12).
2. Every catalogue entry with an export-level signature is covered by at least one detector.
3. Three entries with no export-level signature (E05, E09, E10-partial) are listed separately above with alternative checks.

---

## Sources

- [Lean v4.32.1 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.32.1/)
- [Lean v4.32.2 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.32.2/)
- [Lean v4.33.0 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.33.0/)
- [Lean v4.33.1 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.33.1/)
- [Lean v4.34.0 release notes](https://lean-lang.org/doc/reference/latest/releases/v4.34.0/)
- [CVE-2026-72844 on oss-security](https://www.openwall.com/lists/oss-security/2026/10/26/2)
- [CVE-2026-72844 PoC](https://github.com/endrazine/lean-cve-poc)
- [CVE-2026-72711 PoC](https://github.com/endrazine/lean-cve-poc-14484)
- [De Moura postmortem #14576](https://leodemoura.github.io/blog/2026-8-1-postmortem-for-kernel-soundness-bug-14576/)
- [De Moura postmortem bug hunt](https://leodemoura.github.io/blog/2026-8-24-postmortem-for-the-kernel-soundness-bug-hunt/)
- [Don't trust Lean4 alone (LessWrong)](https://www.lesswrong.com/posts/jgmmMa7AqJNausrqx/don-t-trust-lean4-alone)
- [DeepMind agent-swarm case study (arXiv 2609.04170)](https://arxiv.org/pdf/2609.04170v1)
- [nanoda_lib issue #47](https://github.com/ammkrn/nanoda_lib/issues/47)
- [Lean Kernel Arena](https://arena.lean-lang.org/)
- [Phrack 73: Owning the Truth](https://phrack.org/issues/73/owning-the-truth-undecidability-unsound-kernels-and-the-forging-of-proof_md)
- [Tao: What mathematicians should know about Lean](https://terrytao.wordpress.com/2026/10/09/what-mathematicians-should-know-about-the-lean-theorem-proverquestions-of-reliability-and-ai/)
- [De Moura: Lean now ships with verified kernels](https://leodemoura.github.io/blog/2026-10-15-lean-now-ships-with-verified-kernels/)
- Lean Zulip archives (SafeVerify, native_decide, implemented_by threads)
- [LongCat-Flash-Prover (arXiv 2603.21065)](https://arxiv.org/pdf/2603.21065)
- [Faults in Our Formal Benchmarking (arXiv 2606.29493)](https://arxiv.org/pdf/2606.29493)
