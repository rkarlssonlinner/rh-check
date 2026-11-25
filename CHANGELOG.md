# Changelog

## 2026-11-25 — Two-pass memory optimization and intro banners

**Cone mapper two-pass ref counting** — `const_refs` grew linearly to ~1B entries on the full export (~8 GB pointer array). Two-pass mode (file path argument) fixes this: Pass 1 counts references in a compact `bytearray` (~1.1 GB), Pass 2 uses a dict and frees entries at ref_count 0. Projected RSS: ~12 GB → ~5.5 GB.

- New CLI: `python3 -I scripts/cone_mapper.py data/sutherland/solution.ndjson.zst` (two-pass, memory-optimized). Stdin pipe still works (single-pass, unchanged behavior).
- New helpers: `_expr_child_idxs()`, `_open_ndjson_stream()`, `_pass1_ref_counts()`.
- Pass 2 progress shows percentage of total lines.
- Verified: both modes produce byte-identical `cone-report.json` on the 10K test file. Zero stale ref counts.

**Intro banners** — all five scripts now print a title line and key parameters to stderr at startup: `cone_mapper.py`, `detectors.py`, `parse_export.py`, `vacuity-check.py`, `filter-targets.py`.

**README** — updated Vigslist comparison table cell.

**Files changed:** `scripts/cone_mapper.py` (two-pass rewrite), `scripts/detectors.py`, `scripts/parse_export.py`, `scripts/vacuity-check.py`, `scripts/filter-targets.py` (intro banners), `README.md` (one table cell).

## 2026-11-25 — Cone mapper memory diagnostics

The cone mapper (`scripts/cone_mapper.py`) OOM-killed twice on the full 1.08B-line export (16 GB Mac):

- Run 1 (list + intern_cache): reached 157M lines / 30M unique frozensets before kill.
- Run 2 (dict, no interning): reached 60M lines — strictly worse.

Reverted to the original list + intern_cache approach and added three diagnostic checks:

1. **GC profiling** — `gc.callbacks` timing per generation, toggleable via `CONE_GC_DISABLE=1`.
2. **Memory tracking** — two-tier milestones (light every 1M lines, heavy every 10M) with RSS, per-structure sizing, frozenset sampling, growth extrapolation, OOM prediction.
3. **Graceful exit** — 80% RAM ceiling (`CONE_MEM_CEILING` env var) dumps partial `deps` + diagnostics before OOM killer. SIGTERM handler does the same.

Output: `results/cone/milestones.jsonl` (crash-safe JSONL, 50 MB cap), `results/cone/cone-partial.json` (partial deps, 5 GB cap), `results/cone/diagnostics.json` (summary on clean exit).

**Files changed:** `scripts/cone_mapper.py` (~130 lines added, original logic unchanged).

**Next:** run baseline + GC-disabled comparison, then use diagnostics to design the memory fix.

## 2026-11-25 — Full scan and vacuity check

Downloaded the full 7.7 GB compressed export, SHA-256 verified. Ran both the exploit scan and vacuity check on all 1,468,418 declarations.

**Exploit scan:**

- 58,672 flags total. Zero `suspicious`. 11 `needs_recheck` (standard Mathlib reflexive inductives).
- Zero unsafe/partial declarations, zero large nat literals, zero free variables.
- 57,418 projection flags and 1,234 True-reference flags, all info-level.

**Vacuity check:**

- `anyGeometry`, `geoCl`, `GeoP` found in the export at `GlobalTheory.Mem.Top.Bl.*`.
- All five main theorems: suspect names absent from both type and value expression trees.

**Code changes:**

- `scripts/parse_export.py` — orjson support, `F_TRUE` bit flag, `track_const_refs` opt-in, stopped propagating `expr_proj_info` through children (memory fix).
- `scripts/detectors.py` — streaming CSV output, D3 simplified to flag-only, D5 fixed (`startswith` → substring match for fully qualified names), D9 uses `has_true` flag.
- `scripts/vacuity-check.py` — new, single-pass streaming check.
- `provenance/download-and-verify.sh` — `--chunk-next` mode, venv Python auto-detection.
- `README.md` — rewritten for outside users.

**Known gaps:**

- D5 needs re-run after the name-matching fix.
- Stage 2 positive controls not yet built (requires Lean).
- Transitive dependency cone analysis for `anyGeometry` not yet completed (cone mapper OOM-kills; memory diagnostics added, fix in progress).

## 2026-11-24 — Project setup and infrastructure

Set up the read-only audit infrastructure for scanning Alpöge's RH proof kernel export for known exploit families.

**Files created:**

- `provenance/download-and-verify.sh` — download script with `--peek` mode and SHA-256 verification
- `scripts/parse_export.py` — streaming NDJSON parser with compact bytearray flags
- `scripts/detectors.py` — exploit detectors (D2, D3, D4, D5, D7, D9)
- `scripts/cone_mapper.py` — dependency-cone mapper
- `scripts/filter-targets.py` — streaming NDJSON filter
- `results/stage1a/exploit-catalogue.csv` — 16 known exploits (E01–E16)
- `results/stage1a/taxonomy.md` — exploit categories, detector coverage matrix
