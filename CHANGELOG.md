# Changelog

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
- Transitive dependency cone analysis for `anyGeometry` not yet completed.

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
