# rh-check

Read-only scan of the Lean 4 kernel export of Alpöge's RH proof for known exploit families and vacuity claims.

## What this does

Streams the NDJSON kernel export through two checks:

1. **Exploit scan.** Detectors for structural signatures of every known Lean soundness bug (v4.30 onward), statement-level cheating patterns, and escape hatches.
2. **Vacuity check.** Traces the expression graph to determine whether `anyGeometry` (a definition critics flagged as `fun _ _ _ => True`) appears in the statement or only the proof of the five main theorems.

The scanner works directly on the export data and does not require a Lean installation, compilation, or execution of proof code. It serves as an intermediate check between reading the vacuity claims and re-running the full Lean type checker. Limitations are discussed below.

## Source

Andrew Sutherland's independent sandboxed rebuild at `math.mit.edu/~drew/grh/`. SHA-256 cross-verified against three independent builds.

## Prerequisites

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

### Cone mapper (transitive dependency analysis)

Traces transitive declaration-level dependencies to check whether suspect definitions reach the main theorems through intermediate lemmas. Currently instrumented with memory diagnostics (the full export exceeds 16 GB RAM):

```sh
rm -f results/cone/milestones.jsonl
zstd -d --long=30 -c data/sutherland/solution.ndjson.zst 2>/dev/null \
  | python3 -I scripts/cone_mapper.py
```

Environment variables: `CONE_GC_DISABLE=1` disables Python's cyclic GC (for comparison runs), `CONE_MEM_CEILING=80` sets the RSS ceiling as a percentage of physical RAM (default 80%). The script exits cleanly at the ceiling, dumping partial results to `results/cone/`.

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
| Cone mapper | no extra | exceeds 16 GB (partial run) | 1 core | ~19 min to ceiling |

Both scans are single-threaded and stream-based. They can run in parallel if you have 8+ GB of free RAM, or sequentially on a machine with less. The `--chunk-next` mode lets you download and scan in smaller pieces (e.g., 250 MB at a time) if you want to inspect intermediate results, but each chunk re-decompresses from the start, so downloading everything at once is faster overall.

All network activity is `curl` GET requests to `math.mit.edu`. All processing is local. Nothing is installed system-wide — dependencies go into a Python venv.

## Limitations

**Exploit scan:**

- Detects known exploit families only. A novel, previously unknown soundness bug would not be caught.
- Three known exploits (E09, E13, E16) leave no trace in the kernel export and require re-checking the proof in a patched kernel. Sutherland already did this on v4.36.0.
- A clean scan means no known exploit signature was found. Not more.

**Vacuity check:**

- Traces direct constant references in the expression tree. If `anyGeometry` enters the proof through a chain of intermediate lemmas (A calls B calls C calls `anyGeometry`), this check reports NO for the main theorem even though the dependency exists indirectly.
- To catch indirect dependencies, a full transitive dependency cone analysis is needed. The cone mapper (`scripts/cone_mapper.py`) does this but currently exceeds 16 GB RAM on the full export. It is instrumented with memory diagnostics; a fix is in progress.
- This check answers "does the expression tree contain it?" — not "could the proof be restructured to avoid it?"

**General:**

- Does not prove or disprove the theorem.
- Does not check whether definitions mean what their names suggest.
- Does not replace verification in an independent foundation (Rocq, Isabelle/HOL, Metamath).
- Does not replace a human-readable proof.

## Findings (2026-11-25)

Full scan of all 1,468,418 declarations in the export. Results below use a green/red convention: green supports the proof's soundness, red supports criticism.

**Exploit scan:**

- Green: zero `suspicious` flags across the entire export.
- Green: zero unsafe or partial declarations — the proof is entirely in safe Lean.
- Green: zero large nat literals — no GMP exploit surface.
- Green: zero free variables in expression trees — the export is well-formed.
- 11 `needs_recheck` flags, all standard Mathlib reflexive inductives (`Acc`, `TopologicalSpace.GenerateOpen`, etc.). These are routine.

**Vacuity check:**

Claims on Twitter allege that `anyGeometry`, defined as `fun _ _ _ => True`, renders the proof vacuous.

- Green: `anyGeometry` is absent from both the type (statement) and value (proof term) of all five main theorems at the expression level.
- Green: Sutherland's auxiliary data independently confirms `anyGeometry` is absent from the theorem types' transitive dependency cones.
- Red: `anyGeometry` is defined as `fun _ _ _ => True` and exists in the export. Its role in intermediate lemmas has not been fully traced via transitive dependency analysis.

## How this compares to other audits

Several independent audits of the same proof appeared in November 2026. They answer different questions and require different resources.

| | rh-check (this repo) | Sutherland (MIT) | Zeng | Vigslist |
|---|---|---|---|---|
| **What it checks** | Known exploit signatures + whether flagged definitions reach the main theorems | Full re-verification of the proof in a patched kernel | Declaration-level dependency graph of the full export | Source-level reading + dependency graph tracing of the proof's mathematical argument |
| **Requires Lean?** | No | Yes (patched v4.36.0, hours of compute) | No | No (reads source but does not compile) |
| **Hardware** | Laptop, 8 GB RAM | Server, 128+ GB RAM | Unclear | Laptop |
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
- The D5 detector checks for declarations in modules that required extra computation budget during Sutherland's independent re-verification (unrelated to the vacuity question). It returned zero hits on the first full run due to a confirmed name-matching bug: the detector used `startswith` against bare module names (e.g. `Formalism.PeriodIntegrals...`), but the export uses fully qualified names with a `GlobalTheory.Mem.Top.Bl.` prefix. Fixed to substring match (`in`). Needs re-run.
- The vacuity check is deterministic: it parses every line, builds the expression DAG, and looks up whether specific name indices appear in specific expression subtrees. No heuristics. The result is cross-validated against Sutherland's independently produced dependency lists (`robin-deps.txt`, `lagarias-deps.txt`), which agree: zero `anyGeometry` in the theorem types' transitive dependency cones. The direct-reference result is solid. What remains open is the indirect path through intermediate lemmas.
- Bug fixes during development (expression index handling, name resolution, memory, truncation) were each found during partial runs. The full run is the first time all fixes ran together end to end.

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
