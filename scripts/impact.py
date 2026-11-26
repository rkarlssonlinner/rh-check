"""Impact analysis: type vs. value classification of suspect reachability chains.

For each hop in the reach report's witness chains, determines whether the
upstream constant enters through the type (statement) or value (proof/body)
of the downstream declaration, and what kind each declaration is.

This tells us whether suspects are "spent" (content matters) or "carried"
(structurally present but content-irrelevant):
  - TYPE entry: the suspect's name enters a declaration's statement.
    Its content may affect what downstream declarations state.
  - VALUE of a thm: proof-irrelevant in Lean (Prop). The suspect's
    content cannot affect the theorem's statement.
  - VALUE of a def: the def's body mentions the suspect. Whether the
    content matters depends on whether downstream code unfolds the def.

A chain where every hop is through the value of theorems means the
suspect is proof-irrelevant and cannot affect what any theorem states.

Limitation: the reach report gives one witness chain per (theorem, source)
pair. If the same source reaches a theorem through multiple paths, only
one is classified here. Combined with the vacuity check (suspects absent
from main theorem types directly), a value-only witness chain is strong
evidence that the suspect is proof-only for that theorem.

Usage:
  mkdir -p results/reach
  zstd -d --long=30 -c data/sutherland/solution.ndjson.zst 2>/dev/null \\
    | python3 -I scripts/impact.py \\
        -r results/reach/reach-report.json \\
        -o results/reach/impact-report.json \\
      2>&1 | tee results/reach/impact-run.log
"""
import argparse
import json
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
from cone_mapper import (
    _expr_child_idxs, resolve_name, loads,
    MEMORY_CEILING, _get_footprint, _GUARD_EXIT_CODE)

DECL_KINDS = ("def", "thm", "inductive", "quot", "axiom", "opaque")


def load_chains(path):
    """Read the reach report and extract chains, names, and hop pairs."""
    with open(path) as f:
        report = json.load(f)
    chains = []
    all_names = set()
    hop_pairs = set()
    for thm, data in report["theorems"].items():
        if not data.get("found"):
            continue
        for hit in data.get("reached_by", []):
            ch = hit["chain"]
            chains.append({"theorem": thm, "source": hit["source"],
                           "source_kind": hit["kind"], "chain": ch})
            all_names.update(ch)
            for i in range(len(ch) - 1):
                hop_pairs.add((ch[i], ch[i + 1]))
    return chains, all_names, hop_pairs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-r", "--reach-report",
                    default=os.path.join(PROJECT_DIR, "results", "reach",
                                         "reach-report.json"))
    ap.add_argument("-o", "--output",
                    default=os.path.join(PROJECT_DIR, "results", "reach",
                                         "impact-report.json"))
    args = ap.parse_args()

    def err(msg):
        print(msg, file=sys.stderr, flush=True)

    chains, all_names, hop_pairs = load_chains(args.reach_report)
    upstream_names = {up for _, up in hop_pairs}

    err(f"impact: {len(chains)} chains, {len(all_names)} names, "
        f"{len(hop_pairs)} hops, {len(upstream_names)} tracked in exprs")

    # One bit per upstream name we look for in expressions.
    name_to_bit = {n: 1 << i for i, n in enumerate(sorted(upstream_names))}

    # --- streaming state ---
    name_parts = {}
    name_cache = {}
    nidx_to_bit = {}   # name_idx -> bitmask (tracked upstream names only)
    expr_taint = {}     # expr_idx -> bitmask (which tracked names reachable)
    decl_info = {}      # full_name -> {kind, type_bits, value_bits}
    line_num = decl_lines = 0
    mdata_seen = mdata_skipped = 0
    t0 = time.monotonic()

    def full(idx):
        return resolve_name(idx, name_parts, name_cache)

    def expr_bits(eids):
        b = 0
        for e in dict.fromkeys(eids):
            b |= expr_taint.get(e, 0)
        return b

    err("Streaming...")
    for raw in sys.stdin.buffer:
        line_num += 1
        try:
            obj = loads(raw)
        except ValueError:
            err(f"  [unparsable line {line_num:,}]")
            break

        # --- name parts ---
        if "in" in obj:
            idx = obj["in"]
            if "str" in obj:
                name_parts[idx] = (obj["str"]["pre"],
                                   sys.intern(obj["str"]["str"]))
            elif "num" in obj:
                name_parts[idx] = (obj["num"]["pre"],
                                   sys.intern(str(obj["num"]["i"])))
            fname = full(idx)
            bit = name_to_bit.get(fname)
            if bit is not None:
                nidx_to_bit[idx] = bit
                err(f"  TRACK {fname} (nidx {idx}, line {line_num:,})")

        # --- expressions ---
        elif "ie" in obj:
            idx = obj["ie"]
            if "const" in obj:
                b = nidx_to_bit.get(obj["const"]["name"], 0)
                if b:
                    expr_taint[idx] = b
            else:
                children = _expr_child_idxs(obj)
                if "mdata" in obj:
                    mdata_seen += 1
                    if not children:
                        mdata_skipped += 1
                b = 0
                for c in dict.fromkeys(children):
                    b |= expr_taint.get(c, 0)
                if b:
                    expr_taint[idx] = b

        elif "meta" in obj or "il" in obj:
            pass

        # --- declarations ---
        else:
            for kind in DECL_KINDS:
                if kind not in obj:
                    continue
                decl = obj[kind]
                decl_lines += 1

                if kind == "inductive":
                    for t in decl.get("types", []):
                        fname = full(t.get("name", 0))
                        if fname in all_names:
                            tb = expr_bits(
                                [t["type"]] if "type" in t else [])
                            # Structural: an inductive type depends on its
                            # constructors through the JSON ctors field,
                            # not through expression references.
                            for ci in t.get("ctors", []):
                                tb |= nidx_to_bit.get(ci, 0)
                            decl_info[fname] = {
                                "kind": "inductive",
                                "type_bits": tb, "value_bits": 0}
                    for c in decl.get("ctors", []):
                        fname = full(c.get("name", 0))
                        if fname in all_names:
                            decl_info[fname] = {
                                "kind": "ctor",
                                "type_bits": expr_bits(
                                    [c["type"]] if "type" in c else []),
                                "value_bits": 0}
                    for r in decl.get("recs", []):
                        fname = full(r.get("name", 0))
                        if fname in all_names:
                            decl_info[fname] = {
                                "kind": "rec",
                                "type_bits": expr_bits(
                                    [r["type"]] if "type" in r else []),
                                "value_bits": 0}
                else:
                    fname = full(decl.get("name", 0))
                    if fname in all_names:
                        decl_info[fname] = {
                            "kind": kind,
                            "type_bits": expr_bits(
                                [decl["type"]] if "type" in decl
                                else []),
                            "value_bits": expr_bits(
                                [decl["value"]] if "value" in decl
                                else [])}
                break

        if line_num % 10_000_000 == 0:
            fp = _get_footprint()
            err(f"  {line_num/1e6:.0f}M lines, "
                f"{len(decl_info)}/{len(all_names)} found, "
                f"{len(expr_taint):,} tainted, "
                f"fp {fp/2**30:.2f} GB, {time.monotonic()-t0:.0f}s")
            if fp >= MEMORY_CEILING:
                err(f"STOP: {fp/2**30:.2f} GB >= ceiling")
                break

    elapsed = time.monotonic() - t0
    err(f"\n{line_num:,} lines in {elapsed:.0f}s, "
        f"{len(decl_info)}/{len(all_names)} chain decls found")
    missing = sorted(all_names - set(decl_info))
    if missing:
        err(f"  MISSING: {missing}")

    # --- classify each unique hop ---
    hop_class = {}
    for down, up in hop_pairs:
        info = decl_info.get(down)
        bit = name_to_bit.get(up, 0)
        if info is None or bit == 0:
            hop_class[(down, up)] = {
                "kind": None, "in_type": None, "in_value": None}
        else:
            hop_class[(down, up)] = {
                "kind": info["kind"],
                "in_type": bool(info["type_bits"] & bit),
                "in_value": bool(info["value_bits"] & bit)}

    # --- annotate chains ---
    annotated = []
    for ch in chains:
        hops = []
        for i in range(len(ch["chain"]) - 1):
            down, up = ch["chain"][i], ch["chain"][i + 1]
            hc = hop_class.get((down, up), {})
            hops.append({"decl": down, "kind": hc.get("kind"),
                         "references": up,
                         "in_type": hc.get("in_type"),
                         "in_value": hc.get("in_value")})

        classified = [h for h in hops if h["in_type"] is not None]
        any_type = any(h["in_type"] for h in classified)
        all_value = bool(classified) and all(
            h["in_value"] and not h["in_type"] for h in classified)
        # "thm-value" means proof-irrelevant: all value hops through thms.
        all_thm_value = all_value and all(
            h["kind"] == "thm" for h in classified)
        first_type = next(
            (i for i, h in enumerate(hops) if h["in_type"]), None)

        annotated.append({
            "theorem": ch["theorem"], "source": ch["source"],
            "source_kind": ch["source_kind"], "hops": hops,
            "any_type_entry": any_type,
            "first_type_hop": first_type,
            "all_value_only": all_value and not any_type,
            "all_thm_value": all_thm_value and not any_type})

    # --- per-source summary ---
    summary = {}
    for ch in annotated:
        s = summary.setdefault(ch["source"], {
            "theorems": [], "enters_any_type": False,
            "proof_irrelevant": True, "value_only": True,
            "kinds_on_path": set()})
        s["theorems"].append(ch["theorem"])
        if ch["any_type_entry"]:
            s["enters_any_type"] = True
        if not ch["all_thm_value"]:
            s["proof_irrelevant"] = False
        if not ch["all_value_only"]:
            s["value_only"] = False
        for h in ch["hops"]:
            if h["kind"]:
                s["kinds_on_path"].add(h["kind"])

    for s in summary.values():
        s["kinds_on_path"] = sorted(s["kinds_on_path"])
        if s["enters_any_type"]:
            s["assessment"] = "type-entry"
        elif s["proof_irrelevant"]:
            s["assessment"] = "proof-irrelevant"
        elif s["value_only"]:
            s["assessment"] = "value-only-via-defs"
        else:
            s["assessment"] = "mixed"

    # --- console summary ---
    err(f"\n{'='*60}")
    err("IMPACT ANALYSIS")
    err(f"{'='*60}")

    for src in sorted(summary):
        s = summary[src]
        err(f"\n  {src}: {s['assessment'].upper()}")
        err(f"    reaches {len(s['theorems'])} theorems, "
            f"kinds on path: {s['kinds_on_path']}")

    shown = set()
    for ch in annotated:
        if ch["source"] in shown:
            continue
        shown.add(ch["source"])
        err(f"\n  Example: {ch['theorem']} <- ... <- {ch['source']}")
        for h in ch["hops"]:
            t = "TYPE " if h["in_type"] else "     "
            v = "VALUE" if h["in_value"] else "     "
            k = (h["kind"] or "?")[:10]
            err(f"    {k:10s} {t} {v}  {h['decl']}")
            err(f"    {'':10s}              -> {h['references']}")

    # --- write report ---
    decl_kinds = {n: decl_info[n]["kind"] for n in sorted(decl_info)}
    report = {
        "status": "complete" if not missing else "incomplete",
        "lines": line_num, "decl_lines": decl_lines,
        "chain_decls_found": len(decl_info),
        "chain_decls_expected": len(all_names),
        "missing_decls": missing,
        "mdata_seen": mdata_seen, "mdata_skipped": mdata_skipped,
        "declarations": decl_kinds,
        "source_summary": summary,
        "chains": annotated,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    err(f"\nWrote {args.output}")


if __name__ == "__main__":
    main()
