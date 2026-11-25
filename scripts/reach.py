"""Reachability of suspect names and non-permitted axioms to the main theorems.

Answers, for each main theorem, two questions over the full transitive
dependency graph:
  1. Does any suspect name (config "suspect_names", matched by full name or
     "." suffix, as in vacuity-check.py) reach it through any chain of
     declarations?
  2. Does any axiom outside "permitted_axioms" reach it?
For every hit it prints one witness chain: theorem <- lemma <- ... <- source.

Method: one pass, forward propagation. Each source (a suspect declaration or
a non-permitted axiom) gets one bit. The export lists each declaration after
the constants it uses, so a declaration's bits are the union of the bits of
the constants its type and value mention. Only expressions and declarations
that carry a bit are stored, so memory stays small. The cone mapper
(cone_mapper.py) computes full cones instead and needs more than 16 GB on
the full export.

The method is only exact if no declaration uses a constant that is declared
later in a different line. The script counts such forward references and
reports them; a non-zero count means the result cannot be trusted.

Edges follow cone_mapper._decl_units: an inductive type, its constructors
and its recursors form one block; recursor rules are not followed.

Usage:
  zstd -d --long=30 -c data/sutherland/solution.ndjson.zst 2>/dev/null \\
    | python3 -I scripts/reach.py [-o results/reach/reach-report.json]

Env: REACH_CONFIG overrides the config path (default
data/sutherland/comparator.json). CONE_MEM_CEILING applies as in
cone_mapper.py; at the ceiling the script stops with exit code 3.
"""
import argparse
import json
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
from cone_mapper import (  # noqa: E402  (shared, tested helpers)
    _decl_units, _expr_child_idxs, _get_footprint, resolve_name, loads,
    MEMORY_CEILING, _GUARD_EXIT_CODE)

DECL_KINDS = ("def", "thm", "inductive", "quot", "axiom", "opaque")
MAX_CHAIN = 10_000


def load_config():
    path = (os.environ.get("REACH_CONFIG")
            or os.path.join(PROJECT_DIR, "data", "sutherland",
                            "comparator.json"))
    with open(path) as f:
        return json.load(f), path


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-o", "--output",
                    default=os.path.join(PROJECT_DIR, "results", "reach",
                                         "reach-report.json"))
    args = ap.parse_args()

    config, config_path = load_config()
    targets = set(config["theorem_names"])
    permitted = set(config["permitted_axioms"])
    suspects = sorted(config.get("suspect_names", []))

    def err(msg):
        print(msg, file=sys.stderr, flush=True)

    name_parts = {}
    name_cache = {}
    declared = set()          # name idx of every declared constant
    pending = set()           # const name idx used before being declared
    late = {}                 # expr idx -> ("c", name) or ("e", children) for
                              # expressions that mention a pending name; their
                              # marks are recomputed after the next decl line
    expr_taint = {}           # expr idx -> {bit: name idx of const it came via}
    decl_taint = {}           # name idx -> {bit: via name idx, None = source}
    sources = []              # bit -> {"name", "kind"}
    target_idx = {}           # target full name -> name idx
    forward_refs = 0
    forward_examples = []
    mdata_seen = mdata_skipped = 0
    line_num = decl_lines = 0
    complete = True
    t0 = time.monotonic()

    def full(idx):
        return resolve_name(idx, name_parts, name_cache)

    def source_kind(name, kind):
        if kind == "axiom" and name not in permitted:
            return "axiom"
        for s in suspects:
            if name == s or name.endswith("." + s):
                return "suspect"
        return None

    def merge_into(acc, m, via=None):
        """Add bits of m to acc. via=None keeps m's own via entries."""
        for b, c in m.items():
            if b not in acc:
                acc[b] = c if via is None else via

    def expr_map(eids):
        acc = {}
        for e in dict.fromkeys(eids):
            m = expr_taint.get(e)
            if m:
                merge_into(acc, m)
        return acc

    def set_const(idx, n):
        m = decl_taint.get(n)
        if m:
            expr_taint[idx] = {b: n for b in m}
        else:
            expr_taint.pop(idx, None)

    def set_compound(idx, children):
        m = expr_map(children)
        if m:
            expr_taint[idx] = m
        else:
            expr_taint.pop(idx, None)

    def redo_late(clear):
        """Expressions are shared and reused later. Those emitted before a
        name they mention was declared (an inductive's own constructor and
        recursor types, and recursor rules that mention the recursor) got
        marks too early; recompute them in order."""
        for idx, (tag, x) in late.items():
            if tag == "c":
                set_const(idx, x)
            else:
                set_compound(idx, x)
        if clear:
            late.clear()

    err(f"reach: config {config_path}")
    err(f"  targets:   {sorted(targets)}")
    err(f"  permitted: {sorted(permitted)}")
    err(f"  suspects:  {suspects}")

    stream = sys.stdin.buffer
    for raw in stream:
        line_num += 1
        try:
            obj = loads(raw)
        except ValueError:
            err(f"  [unparsable line {line_num:,}: truncated stream?]")
            complete = False
            break

        if "in" in obj:
            idx = obj["in"]
            if "str" in obj:
                name_parts[idx] = (obj["str"]["pre"],
                                   sys.intern(obj["str"]["str"]))
            elif "num" in obj:
                name_parts[idx] = (obj["num"]["pre"],
                                   sys.intern(str(obj["num"]["i"])))

        elif "ie" in obj:
            idx = obj["ie"]
            if "const" in obj:
                n = obj["const"]["name"]
                if n not in declared:
                    pending.add(n)
                    late[idx] = ("c", n)
                set_const(idx, n)
            else:
                children = _expr_child_idxs(obj)
                if "mdata" in obj:
                    mdata_seen += 1
                    if not children:
                        mdata_skipped += 1
                if late and any(c in late for c in children):
                    late[idx] = ("e", children)
                set_compound(idx, children)

        elif "meta" in obj or "il" in obj:
            pass

        else:
            for kind in DECL_KINDS:
                if kind not in obj:
                    continue
                decl_lines += 1
                units = _decl_units(kind, obj[kind])
                line_names = {u[0] for u in units}
                declared.update(line_names)
                pending.difference_update(line_names)
                if pending:
                    forward_refs += len(pending)
                    if len(forward_examples) < 20:
                        forward_examples.extend(
                            full(n) for n in list(pending)[:5])
                    pending.clear()

                def unit_map(name_idx, ukind, eids):
                    m = expr_map(eids)
                    name = full(name_idx)
                    sk = source_kind(name, ukind)
                    if sk:
                        b = len(sources)
                        sources.append({"name": name, "kind": sk})
                        m[b] = None
                        err(f"  SOURCE bit {b}: {name} ({sk}, line "
                            f"{line_num:,})")
                    if name in targets:
                        target_idx[name] = name_idx
                    return m

                # Types and constructors first. In an inductive block they
                # depend on each other (type -> constructors, constructor
                # type mentions the type), so each gets the block's bits,
                # via the unit that has them. Recursors depend on their
                # own type only, and nothing in the block depends on them.
                own = {u[0]: unit_map(u[0], u[1], u[2])
                       for u in units if u[1] != "rec"}
                if kind == "inductive":
                    block = {}
                    for name_idx, m in own.items():
                        for b in m:
                            block.setdefault(b, name_idx)
                    for name_idx, m in own.items():
                        for b, holder in block.items():
                            if b not in m:
                                m[b] = holder
                for name_idx, m in own.items():
                    if m:
                        decl_taint[name_idx] = m
                # Recompute early expressions twice: once so recursor types
                # see the block's bits, once more after the recursors have
                # their own bits (rules and later terms mention them).
                if late:
                    redo_late(clear=False)
                for name_idx, ukind, eids, _ in units:
                    if ukind == "rec":
                        m = unit_map(name_idx, ukind, eids)
                        if m:
                            decl_taint[name_idx] = m
                if late:
                    redo_late(clear=True)
                break

        if line_num % 10_000_000 == 0:
            fp = _get_footprint()
            err(f"  {line_num/1e6:.0f}M lines, {decl_lines:,} decl lines, "
                f"{len(expr_taint):,} marked exprs, {len(decl_taint):,} "
                f"marked decls, footprint {fp/2**30:.2f} GB, "
                f"{time.monotonic()-t0:.0f}s")
            if fp >= MEMORY_CEILING:
                err(f"STOP: footprint {fp/2**30:.2f} GB >= ceiling")
                complete = False
                write_report(args.output, locals(), stopped=True)
                sys.exit(_GUARD_EXIT_CODE)

    write_report(args.output, locals(), stopped=False)


def chain(start, bit, decl_taint, full):
    out = [full(start)]
    cur, seen = start, {start}
    while len(out) < MAX_CHAIN:
        via = decl_taint.get(cur, {}).get(bit)
        if via is None:
            break
        if via in seen:
            out.append(f"<cycle at {full(via)}>")
            break
        seen.add(via)
        out.append(full(via))
        cur = via
    return out


def write_report(path, v, stopped):
    err = v["err"]
    sources, decl_taint, full = v["sources"], v["decl_taint"], v["full"]
    used_by = [0] * len(sources)
    for m in decl_taint.values():
        for b in m:
            used_by[b] += 1

    theorems = {}
    for t in sorted(v["targets"]):
        if t not in v["target_idx"]:
            theorems[t] = {"found": False}
            continue
        idx = v["target_idx"][t]
        m = decl_taint.get(idx, {})
        hits = []
        for b in sorted(m):
            hits.append({"source": sources[b]["name"],
                         "kind": sources[b]["kind"],
                         "chain": chain(idx, b, decl_taint, full)})
        theorems[t] = {"found": True, "reached_by": hits}

    report = {
        "status": "stopped" if stopped else (
            "complete" if v["complete"] else "incomplete"),
        "config": v["config_path"],
        "lines": v["line_num"],
        "decl_lines": v["decl_lines"],
        "forward_refs": v["forward_refs"],
        "forward_ref_examples": v["forward_examples"],
        "mdata_seen": v["mdata_seen"],
        "mdata_skipped": v["mdata_skipped"],
        "marked_exprs": len(v["expr_taint"]),
        "marked_decls": len(decl_taint),
        "sources": [dict(s, marked_decls=used_by[b])
                    for b, s in enumerate(sources)],
        "theorems": theorems,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    err("")
    err("=" * 60)
    err(f"REACH RESULTS ({report['status']})")
    err(f"  lines {v['line_num']:,}, decl lines {v['decl_lines']:,}, "
        f"marked decls {len(decl_taint):,}")
    err(f"  forward references: {v['forward_refs']:,}")
    if v["forward_refs"]:
        err(f"  WARNING: forward references found; results may miss "
            f"paths. Examples: {v['forward_examples'][:5]}")
    err(f"  mdata: {v['mdata_seen']:,} seen, {v['mdata_skipped']:,} skipped")
    for s, n in zip(sources, used_by):
        err(f"  source {s['name']} ({s['kind']}): marks {n:,} declarations")
    for t, e in theorems.items():
        if not e["found"]:
            err(f"\n  {t}: NOT FOUND")
            continue
        if not e["reached_by"]:
            err(f"\n  {t}: reached by no source")
        for h in e["reached_by"]:
            err(f"\n  {t}: REACHED by {h['source']} ({h['kind']})")
            err("    " + " <- ".join(h["chain"]))
    err(f"\nWrote {path}")


if __name__ == "__main__":
    main()
