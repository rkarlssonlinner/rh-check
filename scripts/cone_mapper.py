"""
Build the dependency cone of the five main theorems.

Single streaming pass: parse all lines, bubble up const references per expression,
record declaration-to-declaration dependencies, then walk backward from theorem names.

Memory: ~1-2 GB on the full export (interned frozensets of int IDs, not full JSON).
No recursion.

Usage:
  cat data/sutherland/solution-first-10k.ndjson | .venv/bin/python3 -I scripts/cone_mapper.py
  zstd -d --long=30 -c data/sutherland/solution.ndjson.zst | .venv/bin/python3 -I scripts/cone_mapper.py
"""
import sys
import os
import json
import collections
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

try:
    import orjson
    loads = orjson.loads
except ImportError:
    loads = json.loads

EMPTY = frozenset()


def load_config():
    path = os.path.join(PROJECT_DIR, "data", "sutherland", "comparator.json")
    with open(path) as f:
        return json.load(f)


def resolve_name(idx, name_parts, cache):
    """Iterative name resolution."""
    if idx in cache:
        return cache[idx]
    chain = []
    cur = idx
    while cur not in cache:
        if cur == 0:
            cache[0] = ""
            break
        if cur not in name_parts:
            cache[cur] = f"<unresolved:{cur}>"
            break
        chain.append(cur)
        cur = name_parts[cur][0]
    for c in reversed(chain):
        pre_idx, component = name_parts[c]
        prefix = cache[pre_idx]
        cache[c] = f"{prefix}.{component}" if prefix else component
    return cache[idx]


def main():
    config = load_config()
    theorem_names = set(config["theorem_names"])
    permitted_axioms = set(config["permitted_axioms"])

    name_parts = {}
    name_cache = {}
    const_refs = []
    intern_cache = {EMPTY: EMPTY}
    decls = {}
    deps = {}
    line_num = 0
    t0 = time.monotonic()

    def err(msg):
        print(msg, file=sys.stderr, flush=True)

    def intern_set(s):
        fs = frozenset(s) if not isinstance(s, frozenset) else s
        cached = intern_cache.get(fs)
        if cached is not None:
            return cached
        intern_cache[fs] = fs
        return fs

    def get_refs(idx):
        if 0 <= idx < len(const_refs):
            r = const_refs[idx]
            if r is not None:
                return r
        return EMPTY

    def ensure_slot(idx):
        while len(const_refs) <= idx:
            const_refs.append(None)

    err(f"Theorem targets: {sorted(theorem_names)}")
    err(f"Permitted axioms: {sorted(permitted_axioms)}")
    err("Parsing...")

    for raw in sys.stdin:
        line_num += 1
        obj = loads(raw)

        if "in" in obj:
            idx = obj["in"]
            if "str" in obj:
                name_parts[idx] = (obj["str"]["pre"], obj["str"]["str"])
            elif "num" in obj:
                name_parts[idx] = (obj["num"]["pre"], str(obj["num"]["i"]))

        elif "ie" in obj:
            idx = obj["ie"]
            ensure_slot(idx)
            keys = obj.keys() if isinstance(obj, dict) else set()

            if "const" in obj:
                const_refs[idx] = intern_set(frozenset({obj["const"]["name"]}))
            elif "app" in obj:
                a = obj["app"]
                const_refs[idx] = intern_set(get_refs(a["fn"]) | get_refs(a["arg"]))
            elif "lam" in obj:
                la = obj["lam"]
                const_refs[idx] = intern_set(get_refs(la["type"]) | get_refs(la["body"]))
            elif "forallE" in obj:
                fa = obj["forallE"]
                const_refs[idx] = intern_set(get_refs(fa["type"]) | get_refs(fa["body"]))
            elif "letE" in obj:
                le = obj["letE"]
                const_refs[idx] = intern_set(
                    get_refs(le["type"]) | get_refs(le["value"]) | get_refs(le["body"])
                )
            elif "proj" in obj:
                const_refs[idx] = intern_set(get_refs(obj["proj"]["struct"]))
            else:
                const_refs[idx] = EMPTY

        elif "meta" in obj:
            pass

        elif "il" in obj:
            pass

        else:
            for kind in ("def", "thm", "inductive", "quot", "axiom", "opaque"):
                if kind in obj:
                    decl = obj[kind]
                    name_idx = decl.get("name", 0)
                    name = resolve_name(name_idx, name_parts, name_cache)

                    all_refs = set()
                    for eid in _decl_expr_ids(decl):
                        all_refs |= get_refs(eid)

                    ref_names = set()
                    for nidx in all_refs:
                        rname = resolve_name(nidx, name_parts, name_cache)
                        if rname and rname != name:
                            ref_names.add(rname)

                    decls[name] = {"kind": kind, "line": line_num}
                    deps[name] = ref_names
                    break

        if line_num % 1_000_000 == 0:
            elapsed = time.monotonic() - t0
            err(f"  {line_num/1e6:.0f}M lines, {len(decls):,} decls, "
                f"{len(const_refs):,} exprs, {len(intern_cache):,} unique ref sets, "
                f"{elapsed:.0f}s")

    elapsed = time.monotonic() - t0
    err(f"Parsed {line_num:,} lines in {elapsed:.1f}s: "
        f"{len(decls):,} declarations, {len(const_refs):,} expressions, "
        f"{len(name_parts):,} names, {len(intern_cache):,} unique ref sets")

    del const_refs
    del intern_cache

    err("Computing cones...")
    cones = {}
    for thm_name in sorted(theorem_names):
        if thm_name not in deps:
            err(f"  WARNING: {thm_name} not found in this export slice")
            continue
        cone = set()
        queue = collections.deque([thm_name])
        while queue:
            current = queue.popleft()
            if current in cone:
                continue
            cone.add(current)
            for dep in deps.get(current, set()):
                if dep not in cone:
                    queue.append(dep)
        cones[thm_name] = cone
        err(f"  {thm_name}: {len(cone):,} declarations in cone")

    all_in_cone = set()
    for c in cones.values():
        all_in_cone |= c

    axioms_in_cone = set()
    for name in all_in_cone:
        info = decls.get(name, {})
        if info.get("kind") == "axiom":
            axioms_in_cone.add(name)
    for name in all_in_cone:
        if name not in decls:
            axioms_in_cone.add(name)

    err(f"\nAll declarations in any cone: {len(all_in_cone):,} of {len(decls):,}")
    err(f"Axioms / unresolved names in cone: {sorted(axioms_in_cone)}")

    unexpected = axioms_in_cone - permitted_axioms - {""}
    known_lean_axioms = {
        "Lean.ofReduceBool", "Lean.ofReduceNat", "Lean.trustCompiler",
        "Quot.lcInv", "isScalarObj", "lcAny", "lcCast", "lcErased",
        "lcProof", "lcUnreachable", "lcVoid", "sorryAx"
    }
    suspicious_axioms = unexpected - known_lean_axioms
    if suspicious_axioms:
        err(f"\n*** D1 FLAG: unexpected axioms in cone: {sorted(suspicious_axioms)}")
    elif unexpected:
        err(f"\nKnown Lean axioms in cone (check if sorryAx is here): {sorted(unexpected)}")
    else:
        err(f"\nD1 clean on this slice: only permitted axioms in cone")

    out_dir = os.path.join(PROJECT_DIR, "results", "cone")
    os.makedirs(out_dir, exist_ok=True)

    result = {
        "theorems": config["theorem_names"],
        "permitted_axioms": config["permitted_axioms"],
        "total_declarations": len(decls),
        "total_in_cone": len(all_in_cone),
        "axioms_in_cone": sorted(axioms_in_cone),
        "unexpected_axioms": sorted(unexpected),
        "cones": {t: {"size": len(c), "members": sorted(c)} for t, c in cones.items()},
    }
    out_path = os.path.join(out_dir, "cone-report.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    err(f"\nWrote {out_path}")


def _decl_expr_ids(decl):
    """Extract all expression IDs referenced by a declaration."""
    ids = []
    if "type" in decl:
        ids.append(decl["type"])
    if "value" in decl:
        ids.append(decl["value"])
    if "ctors" in decl:
        for ctor in decl["ctors"]:
            if "type" in ctor:
                ids.append(ctor["type"])
    if "recs" in decl:
        for rec in decl["recs"]:
            if "type" in rec:
                ids.append(rec["type"])
            for rule in rec.get("rules", []):
                if "val" in rule:
                    ids.append(rule["val"])
    if "all" in decl:
        pass
    return ids


if __name__ == "__main__":
    main()
