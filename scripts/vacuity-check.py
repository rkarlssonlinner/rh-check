"""Vacuity check: is anyGeometry in the TYPE or VALUE of the main theorems?

Streams the full NDJSON kernel export in a single pass. Tracks expression-level
constant references bottom-up, then checks whether suspect names (anyGeometry,
geoCl, GeoP) appear in the type expression tree or value expression tree of each
of the five main RH theorems.

Why this matters:
  - In the TYPE  → the theorem's statement depends on a vacuous definition.
                   The theorem may not actually state RH. (D6-level finding.)
  - In the VALUE → the theorem states genuine RH, but the proof routes through
                   a trivially-true intermediate. Architecturally suspicious,
                   not mathematically vacuous.

Sutherland's comparator output (explicit-statements.out) already shows zero
references to anyGeometry in the statement types' transitive dependency cones.
This script confirms that directly from the NDJSON export.

Usage:
  source .venv/bin/activate
  zstd -d --long=30 -c data/sutherland/solution.ndjson.zst \\
    | python3 -I scripts/vacuity-check.py [-o results/vacuity-check.json]

  The venv provides orjson (3-5x faster parsing). Without it, falls back to
  stdlib json. Run from the repo root (not from data/ or scripts/).

Output:
  - Progress to stderr (every 100K declarations).
  - Structured results as JSON to stdout (or -o file).
  - Human-readable summary to stderr.
  - On incomplete/truncated runs, partial results are saved to
    results/vacuity-partial.json so progress is not lost.

Requires: full solution.ndjson.zst (7.7 GB compressed, ~61.6 GB uncompressed).
          Runs on partial data but may not find the target declarations.

Memory: O(unique_expressions) for the const-reference sets. Expect 2-4 GB on
        the full export. The sets are pruned to only track expressions that
        reference at least one constant.

Runtime: 15-30 minutes on the full export, depending on disk/CPU.
"""
import argparse
import json
import os
import sys
import time

try:
    import orjson
    loads = orjson.loads
except ImportError:
    loads = json.loads

TARGETS = {
    "riemannHypothesis",
    "riemannZeta_eq_zero_re",
    "LFunction_ne_zero_of_half_lt_re",
    "LFunction_eq_zero_re",
    "LFunction_eq_zero_re_of_isPrimitive",
}

SUSPECT_NAMES = {
    "anyGeometry",
    "geoCl",
    "GeoP",
}

EXPECTED_DECLS = 1_468_418  # from Zeng's audit

# ---------- state ----------

name_parts = {}       # name_idx -> (prefix_idx, component_str)
resolved = {0: ""}    # name_idx -> fully qualified name string
suspect_nidxs = {}    # name_idx -> bit flag (for suspect names only)
expr_suspect = {}     # expr_idx -> bitmask of suspect names reachable in subtree
found_suspects = {}   # fully_qualified_name -> name_idx
found_decls = {}      # fully_qualified_name -> {kind, line, type_expr, value_expr}
line_num = 0
decl_count = 0
mdata_seen = 0
mdata_skipped = 0     # mdata lines without an int "expr" child
proj_skipped = 0      # proj lines without a "struct" child

# ---------- helpers ----------


def resolve(idx):
    """Resolve a name index to its fully qualified string."""
    if idx in resolved:
        return resolved[idx]
    stack = []
    cur = idx
    while cur not in resolved:
        if cur == 0:
            resolved[0] = ""
            break
        if cur not in name_parts:
            resolved[cur] = f"<unresolved:{cur}>"
            return resolved[cur]
        stack.append(cur)
        cur = name_parts[cur][0]
    for i in reversed(stack):
        pre_idx, component = name_parts[i]
        prefix = resolved[pre_idx]
        resolved[i] = f"{prefix}.{component}" if prefix else component
    return resolved[idx]


def process_expr(idx, obj):
    """Propagate suspect-name bits through the expression tree.

    Instead of storing all const references per expression (which would use
    many GB on the full export), we only track a bitmask of which suspect
    names are reachable. Only expressions that actually reference a suspect
    get an entry in expr_suspect, keeping memory proportional to the number
    of tainted expressions rather than total expressions.
    """
    global mdata_seen, mdata_skipped, proj_skipped
    children = []
    bits = 0

    if "const" in obj:
        name_idx = obj["const"].get("name", 0)
        bits |= suspect_nidxs.get(name_idx, 0)
    elif "app" in obj:
        a = obj["app"]
        children = [a["fn"], a["arg"]]
    elif "lam" in obj:
        children = [obj["lam"]["type"], obj["lam"]["body"]]
    elif "forallE" in obj:
        children = [obj["forallE"]["type"], obj["forallE"]["body"]]
    elif "letE" in obj:
        le = obj["letE"]
        children = [le["type"], le["value"], le["body"]]
    elif "proj" in obj:
        # The export names the projected expression "struct" (checked on
        # the 10K-line sample); an earlier version read "expr" and so
        # dropped every proj subtree.
        p = obj["proj"]
        if "struct" in p:
            children = [p["struct"]]
        else:
            proj_skipped += 1
    elif "mdata" in obj:
        # Field name not yet seen in our sample; misses are counted.
        mdata_seen += 1
        md = obj["mdata"]
        e = md.get("expr") if isinstance(md, dict) else None
        if isinstance(e, int):
            children = [e]
        else:
            mdata_skipped += 1

    for child_idx in children:
        bits |= expr_suspect.get(child_idx, 0)

    if bits:
        expr_suspect[idx] = bits


def bits_to_names(bits):
    """Convert a suspect bitmask back to a set of name strings."""
    result = set()
    for name, nidx in found_suspects.items():
        if bits & suspect_nidxs.get(nidx, 0):
            result.add(name)
    return result


def check_expr_for_suspects(expr_idx):
    """Return set of suspect names referenced in an expression subtree."""
    bits = expr_suspect.get(expr_idx, 0)
    return bits_to_names(bits) if bits else set()


PARTIAL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "results", "vacuity-partial.json",
)

# ---------- main loop ----------

def log(msg):
    print(msg, file=sys.stderr)


def save_partial(reason):
    """Save whatever we found so far on incomplete runs."""
    partial = {
        "status": "incomplete",
        "reason": reason,
        "lines_scanned": line_num,
        "declarations_scanned": decl_count,
        "suspects_found": {n: {"name_idx": i} for n, i in found_suspects.items()},
        "targets_found": list(found_decls.keys()),
        "targets_missing": sorted(TARGETS - set(found_decls.keys())),
    }
    os.makedirs(os.path.dirname(PARTIAL_PATH), exist_ok=True)
    with open(PARTIAL_PATH, "w") as f:
        json.dump(partial, f, indent=2)
        f.write("\n")
    log(f"  partial results saved to {PARTIAL_PATH}")


ap = argparse.ArgumentParser(description="Vacuity check on RH export")
ap.add_argument("-o", "--output", default=None,
                help="Write JSON results to this file instead of stdout")
cli_args = ap.parse_args()

log("vacuity-check — suspect-name reachability for Lean 4 kernel exports")
log(f"  targets:  {', '.join(sorted(TARGETS))}")
log(f"  suspects: {', '.join(sorted(SUSPECT_NAMES))}")
if cli_args.output:
    log(f"  output:   {cli_args.output}")
log(f"  mode:     stdin")
log("")

start = time.time()

for raw_line in sys.stdin:
    line_num += 1
    raw_line = raw_line.strip()
    if not raw_line:
        continue

    try:
        obj = loads(raw_line)
    except ValueError:
        log(f"  [truncated stream at line {line_num:,}]")
        save_partial("truncated stream")
        break

    # --- name definitions ---
    if "in" in obj:
        idx = obj["in"]
        if "str" in obj:
            name_parts[idx] = (obj["str"]["pre"], obj["str"]["str"])
        elif "num" in obj:
            name_parts[idx] = (obj["num"]["pre"], str(obj["num"]["i"]))

        full = resolve(idx)
        for s in SUSPECT_NAMES:
            if full == s or full.endswith("." + s):
                bit = 1 << len(found_suspects)
                found_suspects[full] = idx
                suspect_nidxs[idx] = bit
                log(f"  SUSPECT NAME: {full} (name idx {idx}, bit {bit}, line {line_num:,})")

    # --- expression definitions ---
    elif "ie" in obj:
        process_expr(obj["ie"], obj)

    # --- declarations ---
    else:
        for decl_kind in ("def", "thm", "inductive", "quot", "axiom", "opaque"):
            if decl_kind not in obj:
                continue
            decl = obj[decl_kind]
            decl_count += 1

            if decl_kind == "inductive":
                name_idx = decl.get("types", [{}])[0].get("name", 0)
            else:
                name_idx = decl.get("name", 0)
            name = resolve(name_idx)

            # track target theorems
            if name in TARGETS:
                found_decls[name] = {
                    "kind": decl_kind,
                    "line": line_num,
                    "type_expr": decl.get("type"),
                    "value_expr": decl.get("value"),
                }
                log(f"  TARGET DECL: {name} ({decl_kind}, line {line_num:,})")

            # track suspect declarations
            if name in SUSPECT_NAMES or any(name.endswith("." + s) for s in SUSPECT_NAMES):
                log(f"  SUSPECT DECL: {name} ({decl_kind}, line {line_num:,})")

            # progress every 50K declarations
            if decl_count % 50_000 == 0:
                elapsed = time.time() - start
                rate = line_num / elapsed if elapsed > 0 else 0
                pct = 100 * decl_count / EXPECTED_DECLS
                print(f"\r  {decl_count:>10,} / {EXPECTED_DECLS:,} decls ({pct:4.1f}%)  "
                      f"{line_num:,} lines  "
                      f"{rate:,.0f} lines/s  "
                      f"[{elapsed:.0f}s | suspects: {len(found_suspects)} | "
                      f"targets: {len(found_decls)}/{len(TARGETS)}]",
                      end="", file=sys.stderr)
            break

# ---------- results ----------

elapsed = time.time() - start
has_suspects = bool(found_suspects)

results = {
    "scan": {
        "lines": line_num,
        "declarations": decl_count,
        "elapsed_seconds": round(elapsed, 1),
        "complete": decl_count >= 1_400_000,
        "mdata_seen": mdata_seen,
        "mdata_skipped": mdata_skipped,
        "proj_skipped": proj_skipped,
    },
    "suspects": {},
    "theorems": {},
}

log(f"\n{'='*60}")
log(f"VACUITY CHECK RESULTS")
log(f"{'='*60}")
log(f"  lines scanned:    {line_num:,}")
log(f"  declarations:     {decl_count:,}")
log(f"  time:             {elapsed:.1f}s")
log(f"  scan complete:    {'YES' if results['scan']['complete'] else 'NO (need full export)'}")
log(f"  mdata:            {mdata_seen:,} seen, {mdata_skipped:,} skipped")
log(f"  proj skipped:     {proj_skipped:,}")
if mdata_skipped or proj_skipped:
    log(f"  WARNING: skipped subtrees; a NO below may miss suspect names")

# suspect names
log(f"\n--- Suspect names ---")
if found_suspects:
    for name, idx in sorted(found_suspects.items()):
        log(f"  {name} (name idx {idx})")
        results["suspects"][name] = {"name_idx": idx}
else:
    log(f"  NONE found in scanned portion")

# target theorems
log(f"\n--- Main theorems ---")
for t in sorted(TARGETS):
    if t not in found_decls:
        log(f"\n  {t}: NOT FOUND")
        results["theorems"][t] = {"found": False}
        continue

    d = found_decls[t]
    log(f"\n  {t} ({d['kind']}, line {d['line']:,}):")
    log(f"    type expr idx:  {d['type_expr']}")
    log(f"    value expr idx: {d['value_expr']}")

    entry = {
        "found": True,
        "kind": d["kind"],
        "line": d["line"],
        "type_expr_idx": d["type_expr"],
        "value_expr_idx": d["value_expr"],
    }

    if has_suspects:
        type_hits = check_expr_for_suspects(d["type_expr"]) if d["type_expr"] else set()
        value_hits = check_expr_for_suspects(d["value_expr"]) if d["value_expr"] else set()

        in_type = "YES" if type_hits else "NO"
        in_value = "YES" if value_hits else "NO"

        log(f"    suspect in TYPE:  {in_type}{' — ' + ', '.join(sorted(type_hits)) if type_hits else ''}")
        log(f"    suspect in VALUE: {in_value}{' — ' + ', '.join(sorted(value_hits)) if value_hits else ''}")

        entry["suspect_in_type"] = sorted(type_hits) if type_hits else []
        entry["suspect_in_value"] = sorted(value_hits) if value_hits else []
    else:
        log(f"    (no suspect names found — cannot check)")
        entry["suspect_in_type"] = None
        entry["suspect_in_value"] = None

    results["theorems"][t] = entry

# summary verdict
log(f"\n--- Verdict ---")
missing_targets = TARGETS - set(found_decls.keys())
missing_suspects = not found_suspects

if missing_targets or missing_suspects:
    log(f"  INCOMPLETE — need full export")
    if missing_targets:
        log(f"    missing targets:  {', '.join(sorted(missing_targets))}")
    if missing_suspects:
        log(f"    missing suspects: anyGeometry/geoCl/GeoP not found yet")
    results["verdict"] = "incomplete"
else:
    any_in_type = any(
        results["theorems"][t].get("suspect_in_type")
        for t in TARGETS if results["theorems"][t]["found"]
    )
    any_in_value = any(
        results["theorems"][t].get("suspect_in_value")
        for t in TARGETS if results["theorems"][t]["found"]
    )

    if any_in_type:
        log(f"  FINDING: suspect name(s) in theorem TYPE — statement may be vacuous")
        results["verdict"] = "suspect_in_type"
    elif any_in_value:
        log(f"  CLEAR: suspect name(s) in VALUE only — theorems state genuine RH")
        log(f"         proof routes through vacuous intermediate (architectural, not logical)")
        results["verdict"] = "value_only"
    else:
        log(f"  CLEAR: suspect names not referenced by any main theorem")
        results["verdict"] = "not_referenced"

log(f"\n{'='*60}")

# structured output
out_fh = sys.stdout
if cli_args.output:
    os.makedirs(os.path.dirname(os.path.abspath(cli_args.output)), exist_ok=True)
    out_fh = open(cli_args.output, "w")

json.dump(results, out_fh, indent=2)
out_fh.write("\n")

if cli_args.output:
    out_fh.close()
    log(f"\nResults written to {cli_args.output}")

# save partial on incomplete runs even when not truncated
if results["verdict"] == "incomplete":
    save_partial("export not fully scanned")

# clean up partial file on complete runs
if results["verdict"] != "incomplete" and os.path.exists(PARTIAL_PATH):
    os.remove(PARTIAL_PATH)
    log(f"  removed stale {PARTIAL_PATH}")
