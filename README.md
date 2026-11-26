# rh-check

Read-only streaming scan of the Lean 4 kernel export of Alpöge's RH proof for known exploit families and vacuity claims. This is complementary check that never compiles Lean and never needs the full 62 GB on disk.

## What this does

Streams the NDJSON kernel export through two checks:

1. **Exploit scan.** Detectors for structural signatures of every known Lean soundness bug (v4.30 onward), statement-level cheating patterns, and escape hatches.
2. **Vacuity check.** Traces the expression graph to determine whether `anyGeometry` (a definition critics flagged as `fun _ _ _ => True`) appears in the statement or only the proof of the five main theorems.

The scanner works directly on the export data and does not require a Lean installation, compilation, or execution of proof code. It serves as an intermediate check between reading the vacuity claims and re-running the full Lean type checker. Limitations are discussed below.

The export was built with Lean 4.33.1, before some known soundness bugs were patched. Sutherland's re-check on a patched kernel (v4.36.0) already covers every known bug; this scan is an independent second look at the export itself. The detectors flag what a whole family of exploits needs (for example, any huge number for the GMP overflow family), so a variant of a known family would likely show up too. A new kind of bug would not: that needs a re-check with an independent kernel.

## Source

Andrew Sutherland's independent sandboxed rebuild at `math.mit.edu/~drew/grh/`. SHA-256 hashes match across three independent builds (Sutherland, Zeng, ours).

## Prerequisites

- At least 8 GB RAM for the exploit scan and vacuity check, and 16 GB for the reachability check (measured peak 11.7 GB). The cone mapper needs more than 16 GB on the full export (measured; it stops itself before the machine swaps, see below).
- Python 3.12+
- `zstd` (command-line tool — `brew install zstd` on macOS, `apt install zstd` on Linux)
- `curl`
- ~8 GB free disk space for the compressed export

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

orjson is optional but gives 3–10x faster JSON parsing. The scanner falls back to stdlib `json` if it's missing.

## Quick start

```sh
. .venv/bin/activate

# First run: grab 10K lines + small aux files (seconds)
./provenance/download-and-verify.sh --peek

# Progressive scan: download and scan in chunks
./provenance/download-and-verify.sh --chunk-next 250M
./provenance/download-and-verify.sh --chunk-next 250M   # adds 250 MB more, re-scans
# repeat until 7.7 GB complete (SHA-256 verified automatically)

# Or download everything at once (~45 min, resume-capable, SHA-256 verified)
./provenance/download-and-verify.sh
```

The full download mode (`./provenance/download-and-verify.sh` without flags) downloads and verifies SHA-256 but does not scan. To scan separately:

```sh
zstd -d --long=30 -c data/sutherland/solution.ndjson.zst 2>/dev/null \
  | python3 -I scripts/detectors.py results/flags.csv
```

### Vacuity check

Checks whether `anyGeometry` (a definition flagged by external critics as `fun _ _ _ => True`) appears in the type (statement) or value (proof) of the five main theorems:

```sh
zstd -d --long=30 -c data/sutherland/solution.ndjson.zst 2>/dev/null \
  | python3 -I scripts/vacuity-check.py
```

### Reachability check (transitive, full export)

Checks whether any suspect name, or any axiom outside the permitted three, reaches the five main theorems through any chain of declarations, and prints one witness chain per hit (theorem ← lemma ← … ← source):

```sh
mkdir -p results/reach
zstd -d --long=30 -c data/sutherland/solution.ndjson.zst 2>/dev/null \
  | REACH_CONFIG=scripts/reach-config-narrow.json \
    python3 -I scripts/reach.py -o results/reach/reach-report.json 2>&1 | tee results/reach/run.log
```

`REACH_CONFIG` selects the suspect list. The narrow config leaves out the two widely used `shaLen` definitions (`Formalism.GaloisCohomology.shaLen`, `Formalism.BasicNotions.Rows.Data.shaLen`): each reaches about 70,000 declarations, and with them the run passed 14 GB at line 220 million and stopped. Without `REACH_CONFIG` the script reads `data/sutherland/comparator.json`.

It makes one pass and stores only the declarations and expressions that a suspect or a non-permitted axiom reaches. It relies on the export listing each declaration after the constants it uses; it counts any exceptions (`forward_refs` in the report), and a non-zero count means the result may miss paths. On the 10K-line sample and on planted cases it agrees exactly with the cone mapper's full cones.

### Cone mapper (transitive dependency analysis)

Computes the full transitive dependency cone of each main theorem (members, sizes, overlap). It answers the same reach questions as the reachability check, but on the full export it needs more than 16 GB of RAM (see below); use it on smaller inputs:

```sh
rm -f results/cone/milestones.jsonl
CONE_GC_DISABLE=1 python3 -I scripts/cone_mapper.py data/sutherland/solution.ndjson.zst
```

Pass the file path as shown. Piping into the script through stdin runs the old single-pass mode, which holds every expression in memory and does not fit the full export.

Environment variables:

- `CONE_GC_DISABLE=1` disables Python's cyclic GC. Recommended: in three logged runs the GC freed 0 objects and took about a quarter of the run time.
- `CONE_MEM_CEILING=80` sets the memory ceiling as a percentage of physical RAM (default 80%). It measures the process's physical footprint (the number Activity Monitor shows), which includes compressed memory. Plain RSS does not, and stops growing once macOS starts compressing.
- `CONE_SWAP_GROWTH_GB=2` stops the run if system swap grows by more than 2 GB after start (default 2). This catches memory pressure from other apps too.

At either limit the script writes `results/cone/cone-partial.json` (summary and suspect hits) and `results/cone/cone-partial-deps.jsonl` (one declaration per line, capped at 5 GB), then exits with code 3.

Pass 1 caches its counts in `results/cone/pass1-cache.bin` (about 2 GB). A later run on the same input skips pass 1. The mapper follows `mdata` wrappers and reports how many it had to skip (`mdata_skipped` in `cone-report.json`); a non-zero count means some constants are missing from the cones.

## What the scan covers

16 known exploits (E01–E16) across 8 categories, detected by 11 detectors (D1–D11). See [results/stage1a/taxonomy.md](results/stage1a/taxonomy.md) for the full catalogue and coverage matrix.

Three exploits leave no trace in the export and require kernel re-checking (Sutherland already did this on v4.36.0).

## What happens when you run it

The download script fetches the compressed kernel export (7.7 GB) from Sutherland's MIT page via HTTPS GET requests only. No data is uploaded. The SHA-256 hash is verified automatically when the download completes.

The scanner decompresses the export through a pipe (`zstd` into Python) and processes it line by line. The decompressed data (~62 GB) never lands on disk — it streams through memory. Only the compressed file is stored.

**Resource usage:**

| | Disk | RAM | CPU | Time |
|---|---|---|---|---|
| Download | 7.7 GB | minimal | minimal | ~45 min (depends on connection) |
| Exploit scan | no extra | 2–4 GB | 1 core | ~20 min with orjson, ~60 min without |
| Vacuity check | no extra | 2–4 GB | 1 core | ~15 min with orjson |
| Reachability check | no extra | 11.7 GB peak with the narrow config (measured) | 1 core + zstd | ~17 min (measured) |
| Cone mapper | ~2 GB pass-1 cache (up to 5 GB more if stopped early) | over 16 GB on the full export (measured: stopped at the 13.1 GB ceiling, 28% in) | 1 core + zstd | pass 1 ~21 min; full run does not fit 16 GB |

The cone mapper runs in two passes over the compressed export. Pass 1 counts how many times each expression will be referenced later, storing the counts in a compact array (2 bytes per expression, ~2 GB). Pass 2 builds the dependency cones and deletes each expression's data the moment nothing else needs it. Expressions referenced 65,535 times or more stay in memory for the whole run. When one sub-expression's set of constants already contains the other's, pass 2 reuses that set instead of copying it. Measured on 2026-11-25: the live set still grew by about 43,000 entries per million lines (13.1 million entries at line 306 million of 1,081 million), and the run stopped at the 80% memory ceiling. These entries are not leaks: each expression is still needed further down the export. Holding a set of names per expression projects to roughly 30 GB, so the full export needs the reachability check instead.

Each inductive type, constructor and recursor counts as its own constant, so `total_declarations` in `cone-report.json` is higher than the 1,468,418 declaration lines. An inductive type depends on its constructors; recursor rules are not followed, matching Lean's own axiom collection.

All scans are single-threaded and stream-based. They can run in parallel if you have 8+ GB of free RAM, or sequentially on a machine with less. The `--chunk-next` mode lets you download and scan in smaller pieces (e.g., 250 MB at a time) if you want to inspect intermediate results, but each chunk re-decompresses from the start, so downloading everything at once is faster overall.

All network activity is `curl` GET requests to `math.mit.edu`. All processing is local. Nothing is installed system-wide — dependencies go into a Python venv.

## Limitations

**Exploit scan:**

- Detects known exploit families only. A novel, previously unknown soundness bug would not be caught.
- Three known exploits (E09, E13, E16) leave no trace in the kernel export and require re-checking the proof in a patched kernel. Sutherland already did this on v4.36.0.
- A clean scan means no known exploit signature was found. Not more.

**Vacuity check:**

- Traces direct constant references in the expression tree. If `anyGeometry` enters the proof through a chain of intermediate lemmas (A calls B calls C calls `anyGeometry`), this check reports NO for the main theorem even though the dependency exists indirectly.
- To catch indirect dependencies, a transitive analysis is needed. The reachability check (`scripts/reach.py`) does this on the full export; the cone mapper computes full cones on smaller inputs.
- This check answers "does the expression tree contain it?" — not "could the proof be restructured to avoid it?"

**General:**

- Does not prove or disprove the theorem.
- Does not check whether definitions mean what their names suggest.
- Does not replace verification in an independent foundation (Rocq, Isabelle/HOL, Metamath).
- Does not replace a human-readable proof.

## Findings (2026-11-25)

Full scan of all 1,468,418 declarations in the export. Results below use a green/red convention: green supports the proof's soundness, red supports criticism.

**Exploit scan:**

- Green: zero `suspicious` flags across the entire export. Re-run 2026-11-25 with the fixed parser (numbers read from their text form, projections followed); it skipped no subtrees and failed to read no literals.
- Green: zero unsafe or partial declarations — the proof is entirely in safe Lean.
- Green: zero large nat literals (none above 10,000 bits), so no GMP exploit surface. Confirmed by the re-run; the first run's detector could not read the export's text-encoded numbers.
- Green: zero free variables in expression trees, including inside projections. The export contains no `mdata`.
- 11 `needs_recheck` flags, all reflexive inductive types. Nine are standard Mathlib or core types (`Acc`, `WType`, `TopologicalSpace.GenerateOpen`, etc.). The other two flags are one mutual block, `FunctorialResolution.EmbeddedResolution.PrincipalizationCertificate`, which is not in Mathlib as far as we know and is probably the proof's own code. Reflexive inductives are legitimate, but past kernel bugs went through unusual inductives; Sutherland's patched re-check and nanoda accept these.

**Vacuity check:**

Claims on Twitter allege that `anyGeometry`, defined as `fun _ _ _ => True`, renders the proof vacuous.

- Green: `anyGeometry` is absent from both the type (statement) and value (proof term) of all five main theorems at the expression level. Re-confirmed 2026-11-25 by the fixed check, which follows projections (an earlier version skipped them); the export contains no `mdata`.
- Green: Sutherland's auxiliary data shows the five statements are built from Mathlib definitions plus four statement definitions in a separate `Statements` module (`audit.log`), and the dependency cones of the Robin and Lagarias criterion statements (2,050 and 1,801 declarations) contain no `anyGeometry` and nothing from the proof's own code.
- Red: `anyGeometry` is defined as `fun _ _ _ => True` and reaches all five main theorems indirectly, through their proofs (see the reachability check below). The statements do not depend on it.

**Reachability check (transitive):**

Run 2026-11-25 with `scripts/reach.py` and `scripts/reach-config-narrow.json`: complete, all 1,080,769,508 lines, 0 forward references, 0 `mdata`.

- Red (structure, not soundness): every suspect declared in the export reaches all five main theorems. These are `anyGeometry`, `geoCl`, `GeoP`, `UnusedSlot72`, `GlobalTheory.Mem.RowsRest.shaLen`, and two `sha_eq` fields (`Formalism.BasicNotions.NData.sha_eq`, `GlobalTheory.TwInputs.Move.RestN.sha_eq`). All chains run through the main proof, `rhOfAll ← allChi ← UpperTheory.FinalTheorems.everyCharacter ← … ← UpperTheory.Lit.every_character_of_theta_integrals_local_matching`. Example: `riemannHypothesis ← rhOfAll ← allChi ← … ← UpperTheory.Lit.nonempty_hyps_definite_side_of_closed_bound ← GlobalTheory.Mem.Top.Bl.parametersOfDependence ← GlobalTheory.Mem.Top.Bl.anyGeometry`. Several chains pass through structures: a structure depends on a name when one of its fields mentions it (e.g. `Parameters ← Parameters.mk ← GeoP`), as in Lean's own axiom collection. This independently confirms that these names belong to the proof's dependency graph, as Vigslist's "carried" says. It does not test whether the proof uses their content ("spent"): the check does not separate a statement mention from a proof mention along the chain.
- Number of declarations each suspect reaches: `anyGeometry` 31, `geoCl` 35, `UnusedSlot72` 80, `RestN.sha_eq` 329, `GeoP` 446, `NData.sha_eq` 1,837, `RowsRest.shaLen` 8,432.
- Green: the export declares no axiom outside `propext`, `Quot.sound` and `Classical.choice`, so no other axiom reaches the theorems. This agrees with Sutherland's comparator. The axiom path of `reach.py` has no positive control on real Lean output yet (Stage 2).
- Not tested: the two widely used `shaLen` definitions (see the reachability check section). `geoOf` matches no declaration in the export.

## How this compares to other audits

Several independent audits of the same proof appeared in November 2026. They answer different questions and require different resources.

| | rh-check (this repo) | Sutherland (MIT) | Zeng | Vigslist |
|---|---|---|---|---|
| **What it checks** | Known exploit signatures + whether flagged definitions reach the main theorems | Full re-verification of the proof in a patched kernel | Declaration-level dependency graph of the full export | Source-level reading + dependency graph tracing of the proof's mathematical argument |
| **Requires Lean?** | No | Yes (patched v4.36.0, hours of compute) | No | No (reads source but does not compile) |
| **Hardware** | Laptop, 16 GB RAM | Server, 128+ GB RAM | Unclear | Laptop |
| **Input** | Compressed kernel export (7.7 GB download) | Full source + Mathlib | Kernel export | Source archive |
| **Can check a new suspect name** | Yes, one-line config change | Requires new compilation | Requires full re-run | Requires manual reading |
| **Can run on partial data** | Yes, streams and saves intermediate results | No | No | N/A |
| **Catches kernel bugs** | Known families only | All (by re-running the kernel) | No | No |
| **Catches vacuous definitions** | Yes (direct + transitive) | Indirectly (if the proof still compiles without them) | Yes (dependency graph) | Yes (by reading the code) |
| **Catches semantic weakness** | No | No | No | Yes (reads what the proof actually argues) |

Vigslist's audit (November 2026) is the deepest published analysis. It does not claim the formal derivation fails. It identifies eight points where the proof's names and packaging describe a different argument from what the code contains. Those are source-level observations this tool cannot make. See Vigslist, "An Audit of the Claimed Lean Proof of the Riemann Hypothesis: Eight Findings, with Addresses."

**How robust is this?**

This scan checks for known exploit families and direct expression-level references. It would not catch a novel kernel bug or a semantic weakness like those in Vigslist's findings. The strongest external evidence remains Sutherland's independent re-verification on a fully patched Lean kernel (v4.36.0), which covers both known and unknown kernel bugs. Our scan is a complementary structural check, not a substitute.

**How confident are we in the pipeline itself?**

This was the first full run. The parser and detectors were developed and tested on 10K-line and 310 MB partial exports before scaling to the full 7.7 GB. Known risks:

- The parser was tested against the export format but has no independent positive controls yet. Stage 2 (planned, requires a Lean installation) would generate synthetic Lean files with known exploit signatures, export them to NDJSON, and confirm the detectors catch them. The first run was deliberately designed to work without Lean.
- The D5 detector checks for declarations in modules that required extra computation budget during Sutherland's independent re-verification (unrelated to the vacuity question). It returned zero hits on the first full run due to a confirmed name-matching bug: the detector used `startswith` against bare module names (e.g. `Formalism.PeriodIntegrals...`), but the export uses fully qualified names with a `GlobalTheory.Mem.Top.Bl.` prefix. Fixed to substring match (`in`). The re-run (2026-11-25) still found zero, and the cause is structural: declaration names follow namespaces (e.g. `PI.UnitaryGroupMassFormula...`), not module paths, and the export does not record which module a declaration came from. D5 cannot work from the export. The question it was meant to raise is answered by Sutherland's `lean4lean-raised-fuel.log`: all five modules (18 declarations) passed lean4lean with raised fuel (`rc=0`).
- The vacuity check is deterministic: it parses every line, builds the expression DAG, and looks up whether specific name indices appear in specific expression subtrees. No heuristics. The result is cross-validated against Sutherland's independently produced dependency lists (`robin-deps.txt`, `lagarias-deps.txt`), which agree: zero `anyGeometry` in the theorem types' transitive dependency cones. The direct-reference result is solid. The reachability check answers the indirect path: `anyGeometry` reaches all five theorems through their proofs.
- Bug fixes during development (expression index handling, name resolution, memory, truncation) were each found during partial runs. The full run is the first time all fixes ran together end to end.
- Gaps found 2026-11-25 made some checks blind. The parser and the vacuity check read the projection field under the wrong name (`expr` instead of `struct`), no script followed `mdata` wrappers, and natVal (stored as text) was never measured. The cone mapper also merged all inductive types into one nameless entry and never registered constructors or recursors. Each fix was tested on a planted case that the old code missed and the new code catches. Findings that depended on these checks are marked unverified above.

We treat these results as a first pass, not a final verdict.

## Directory layout

```
provenance/     download script, SHA-256 verification
data/           downloaded exports (gitignored, up to 7.7 GB)
scripts/        Python scanner code
results/        flags, exploit catalogue, taxonomy
```

## Safety

All findings stay local. No outbound communication. The scanner reads the export as untrusted data and runs Python in isolated mode (`-I`).
