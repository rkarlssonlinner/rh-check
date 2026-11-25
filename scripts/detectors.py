"""Detectors D1–D9, D10, D11 for the RH export scan.

Each detector takes (kind, name, decl, line_num, features, parser) and returns
a list of flags. `features` is the merged expression feature dict from the parser,
giving access to const_refs, proj info, fvar, natVal etc. without storing full
expression trees.

A flag is a dict: {detector, declaration, line, reason, severity}
line = line number in the ORIGINAL export file (never renumbered)
severity: "suspicious", "needs_recheck", or "info"
"""
import json
import sys
import os
import collections
import csv
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_export import ExportParser, stream_parse

PERMITTED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}

FIVE_THEOREMS = [
    "riemannHypothesis",
    "riemannZeta_eq_zero_re",
    "LFunction_ne_zero_of_half_lt_re",
    "LFunction_eq_zero_re",
    "LFunction_eq_zero_re_of_isPrimitive",
]

HOT_MODULES = [
    "Formalism.PeriodIntegrals.UnitaryGroupMassFormula.ChebyshevPrimeBounds.SmallLoop",
    "Formalism.PeriodIntegrals.UnitaryGroupMassFormula.DyadicPrimeIntervals.Run1",
    "Formalism.PeriodIntegrals.UnitaryGroupMassFormula.DyadicPrimeIntervals.Run2",
    "Formalism.PeriodIntegrals.UnitaryGroupMassFormula.DyadicPrimeIntervals.Run3",
    "Formalism.PeriodIntegrals.UnitaryGroupMassFormula.DyadicPrimeIntervals.Run4",
]

LEAN_INTERNAL_AXIOMS = {
    "Lean.ofReduceBool", "Lean.ofReduceNat", "Lean.trustCompiler",
    "sorryAx", "lcProof", "lcVoid", "lcErased", "lcUnreachable",
    "lcCast", "lcAny", "isScalarObj", "Quot.lcInv",
}


def flag(detector, declaration, line, reason, severity="info"):
    return {
        "detector": detector,
        "declaration": declaration,
        "line": line,
        "reason": reason,
        "severity": severity,
    }


def d2_inductive_anomalies(kind, name, decl, line_num, features, parser):
    """D2: Inductive types with unusual structure."""
    if kind != "inductive":
        return []
    flags = []
    types = decl.get("types", [])
    recs = decl.get("recs", [])

    for t in types:
        if t.get("isReflexive", False):
            flags.append(flag("D2", name, line_num,
                "reflexive inductive type", "needs_recheck"))
        if t.get("numNested", 0) > 0:
            flags.append(flag("D2", name, line_num,
                f"nested inductive ({t['numNested']} nested)", "info"))
        if t.get("isUnsafe", False):
            flags.append(flag("D2", name, line_num,
                "unsafe inductive type", "suspicious"))

    for rec in recs:
        if rec.get("numMotives", 1) > 1:
            flags.append(flag("D2", name, line_num,
                f"mutual inductive: {rec['numMotives']} motives", "info"))

    ctors = decl.get("ctors", [])
    if len(ctors) == 0:
        flags.append(flag("D2", name, line_num,
            "inductive with zero constructors", "info"))

    for ctor in ctors:
        if ctor.get("isUnsafe", False):
            flags.append(flag("D7", name, line_num,
                f"unsafe constructor: {parser.resolve_name(ctor.get('name', 0))}",
                "suspicious"))

    return flags


def d3_projection_mismatch(kind, name, decl, line_num, features, parser):
    """D3: Projection expressions in declaration's expression tree."""
    if not features["has_proj"]:
        return []
    return [flag("D3", name, line_num, "has projection expression", "info")]


def d4_large_nat_literals(kind, name, decl, line_num, features, parser):
    """D4: Large Nat literals in the declaration's expression tree."""
    if not features["has_large_nat"]:
        return []
    bits = features["max_nat_bits"]
    if features["has_huge_nat"]:
        return [flag("D4", name, line_num,
            f"Nat literal with {bits:,} bits (>1M — GMP exploit range)",
            "suspicious")]
    return [flag("D4", name, line_num,
        f"Nat literal with {bits:,} bits (>10K)", "info")]


def d5_reduction_heavy(kind, name, decl, line_num, features, parser):
    """D5: Declarations from hot modules (raised lean4lean fuel)."""
    flags = []
    for mod in HOT_MODULES:
        if mod in name:
            flags.append(flag("D5", name, line_num,
                f"in hot module (raised lean4lean fuel): {mod}",
                "needs_recheck"))
            break
    return flags


def d7_unsafe_partial_fvar(kind, name, decl, line_num, features, parser):
    """D7: unsafe/partial safety, and fvar in expression trees."""
    flags = []
    safety = decl.get("safety", "safe")
    if safety == "unsafe":
        flags.append(flag("D7", name, line_num,
            "declaration marked unsafe", "suspicious"))
    elif safety == "partial":
        flags.append(flag("D7", name, line_num,
            "declaration marked partial", "suspicious"))

    if features["has_fvar"]:
        flags.append(flag("D7", name, line_num,
            "free variable reference (fvar) in expression tree",
            "suspicious"))

    return flags


def d9_decorative(kind, name, decl, line_num, features, parser):
    """D9: Predicates defined as True, fields closed by rfl."""
    if kind != "def":
        return []
    if features["has_true"]:
        return [flag("D9", name, line_num,
            "references True constant (possible decorative predicate)",
            "info")]
    return []


ALL_DETECTORS = [
    d2_inductive_anomalies,
    d3_projection_mismatch,
    d4_large_nat_literals,
    d5_reduction_heavy,
    d7_unsafe_partial_fvar,
    d9_decorative,
]


def run_detectors(input_file, output_csv, limit=None):
    all_flags = []
    decl_count = 0
    start = time.time()
    parser = None

    for result in stream_parse(input_file, limit=limit):
        if result[0] == "meta":
            print(f"Scanning export: {result[1]['lean']['version']}", file=sys.stderr)
        elif result[0] == "decl":
            _, kind, name, decl, line_num, features = result
            decl_count += 1
            if parser is None:
                # grab parser ref from the generator's internal state — not ideal
                # but stream_parse yields parser state via features
                pass
            for detector in ALL_DETECTORS:
                try:
                    det_flags = detector(kind, name, decl, line_num, features, _parser_ref[0])
                    all_flags.extend(det_flags)
                except Exception as e:
                    all_flags.append(flag("ERROR", name, line_num,
                        f"{detector.__name__}: {e}", "info"))

    elapsed = time.time() - start
    print(f"\n=== Detector Summary ===", file=sys.stderr)
    print(f"Declarations scanned: {decl_count:,}", file=sys.stderr)
    print(f"Flags raised: {len(all_flags):,}", file=sys.stderr)
    print(f"Time: {elapsed:.2f}s", file=sys.stderr)

    by_detector = collections.Counter(f["detector"] for f in all_flags)
    by_severity = collections.Counter(f["severity"] for f in all_flags)
    print(f"\nBy detector:", file=sys.stderr)
    for d, c in sorted(by_detector.items()):
        print(f"  {d}: {c}", file=sys.stderr)
    print(f"\nBy severity:", file=sys.stderr)
    for s, c in sorted(by_severity.items()):
        print(f"  {s}: {c}", file=sys.stderr)

    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f,
            fieldnames=["detector", "declaration", "line", "reason", "severity"])
        writer.writeheader()
        writer.writerows(all_flags)

    print(f"\nFlags written to {output_csv}", file=sys.stderr)
    return all_flags


# Ugly but necessary: stream_parse yields results, not the parser itself.
# We need the parser for name resolution in detectors.
_parser_ref = [None]
_orig_stream_parse = stream_parse

def _instrumented_stream_parse(input_file, limit=None):
    p = ExportParser()
    _parser_ref[0] = p
    for line in input_file:
        line = line.strip()
        if not line:
            continue
        result = p.parse_line(line)
        if result is not None:
            yield result
        if limit and p.line_num >= limit:
            break
    yield ("summary", p.counts, p.decl_count, p.line_num, p.meta)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("output", nargs="?", default="results/flags.csv")
    ap.add_argument("--checkpoint", default=None,
                    help="Path to checkpoint file (line number to resume from)")
    args = ap.parse_args()

    print("detectors — anomaly scanner for Lean 4 kernel exports (D1–D11)",
          file=sys.stderr)
    print(f"  output: {args.output}", file=sys.stderr)
    if args.checkpoint:
        print(f"  checkpoint: {args.checkpoint}", file=sys.stderr)
    print(f"  mode: stdin", file=sys.stderr)
    print("", file=sys.stderr)

    skip_to_line = 0
    prev_flags_file = None
    if args.checkpoint and os.path.exists(args.checkpoint):
        skip_to_line = int(open(args.checkpoint).read().strip())
        prev_flags_file = args.output
        print(f"Checkpoint: fast-forwarding past line {skip_to_line:,}", file=sys.stderr)

    decl_count = 0
    flag_count = 0
    skipped_decls = 0
    start = time.time()
    last_progress = 0
    by_detector = collections.Counter()
    by_severity = collections.Counter()

    write_header = not os.path.exists(args.output)
    csv_file = open(args.output, "a", newline="")
    writer = csv.DictWriter(csv_file,
        fieldnames=["detector", "declaration", "line", "reason", "severity"])
    if write_header:
        writer.writeheader()

    for result in _instrumented_stream_parse(sys.stdin):
        if result[0] == "truncated":
            print(f"\n  (truncated stream at line {result[1]} — end of downloaded data)",
                  file=sys.stderr)
            sys.stdin.close()
            break
        elif result[0] == "meta":
            print(f"Scanning export: {result[1]['lean']['version']}", file=sys.stderr)
        elif result[0] == "decl":
            _, kind, name, decl, line_num, features = result
            decl_count += 1
            if line_num <= skip_to_line:
                skipped_decls += 1
                if skipped_decls % 50000 == 0:
                    elapsed = time.time() - start
                    print(f"\r  fast-forward: {skipped_decls:>10,} declarations skipped  "
                          f"[{elapsed:.0f}s]", end="", file=sys.stderr)
                continue
            if decl_count - last_progress >= 10000:
                elapsed = time.time() - start
                print(f"\r  {decl_count:>10,} declarations  "
                      f"({skipped_decls:,} skipped, {flag_count} new flags)  "
                      f"[{elapsed:.0f}s]", end="", file=sys.stderr)
                last_progress = decl_count
            for detector in ALL_DETECTORS:
                try:
                    det_flags = detector(kind, name, decl, line_num, features, _parser_ref[0])
                    for f in det_flags:
                        writer.writerow(f)
                        flag_count += 1
                        by_detector[f["detector"]] += 1
                        by_severity[f["severity"]] += 1
                except Exception as e:
                    err = flag("ERROR", name, line_num,
                        f"{detector.__name__}: {e}", "info")
                    writer.writerow(err)
                    flag_count += 1
                    by_detector["ERROR"] += 1
                    by_severity["info"] += 1

    csv_file.close()

    elapsed = time.time() - start
    new_decls = decl_count - skipped_decls
    print(f"\n=== Detector Summary ===", file=sys.stderr)
    print(f"Declarations total:   {decl_count:,}", file=sys.stderr)
    if skipped_decls:
        print(f"  skipped (checkpoint): {skipped_decls:,}", file=sys.stderr)
        print(f"  newly scanned:       {new_decls:,}", file=sys.stderr)
    print(f"Flags raised: {flag_count:,}", file=sys.stderr)
    print(f"Time: {elapsed:.2f}s", file=sys.stderr)

    if flag_count:
        print(f"\nBy detector:", file=sys.stderr)
        for d, c in sorted(by_detector.items()):
            print(f"  {d}: {c}", file=sys.stderr)
        print(f"\nBy severity:", file=sys.stderr)
        for s, c in sorted(by_severity.items()):
            print(f"  {s}: {c}", file=sys.stderr)

    if args.checkpoint:
        final_line = _parser_ref[0].line_num if _parser_ref[0] else 0
        with open(args.checkpoint, "w") as f:
            f.write(str(final_line))
        print(f"Checkpoint updated: line {final_line:,}", file=sys.stderr)

    print(f"Flags written to {args.output}", file=sys.stderr)
