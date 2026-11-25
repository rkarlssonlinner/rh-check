"""
Build the dependency cone of the five main theorems.

Single streaming pass: parse all lines, bubble up const references per expression,
record declaration-to-declaration dependencies, then walk backward from theorem names.

Memory: ~1-2 GB on the full export (interned frozensets of int IDs, not full JSON).
No recursion.

Usage:
  cat data/sutherland/solution-first-10k.ndjson | .venv/bin/python3 -I scripts/cone_mapper.py
  zstd -d --long=30 -c data/sutherland/solution.ndjson.zst | .venv/bin/python3 -I scripts/cone_mapper.py

Diagnostics (env vars):
  CONE_GC_DISABLE=1  — disable Python's cyclic GC (no cycles in this code)
  CONE_MEM_CEILING=80 — RSS ceiling as % of physical RAM (default: 80)
"""
import sys
import os
import json
import collections
import time
import gc
import resource
import signal
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

try:
    import orjson
    loads = orjson.loads
except ImportError:
    loads = json.loads

EMPTY = frozenset()

# --- Diagnostic configuration ---

_DIAG_GC_DISABLE = os.environ.get("CONE_GC_DISABLE", "") == "1"
_DIAG_CEILING_PCT = int(os.environ.get("CONE_MEM_CEILING", "80"))
_DIAG_HEAVY_INTERVAL = 10  # heavy milestone every N million lines


def _get_physical_ram():
    try:
        out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)
        return int(out.strip())
    except Exception:
        return 16 * 1024**3


PHYSICAL_RAM = _get_physical_ram()
MEMORY_CEILING = int(PHYSICAL_RAM * _DIAG_CEILING_PCT / 100)
_MILESTONE_CAP = 50 * 1024 * 1024   # 50 MB max milestone file
_PARTIAL_CAP = 5 * 1024**3          # 5 GB max partial dump
_MIN_WRITE_GAP = 1.0                # seconds between milestone writes

# --- GC callback ---

_gc_time = [0.0, 0.0, 0.0]
_gc_counts = [0, 0, 0]
_gc_collected = [0, 0, 0]
_gc_callback_start = 0.0


def _gc_callback(phase, info):
    global _gc_callback_start
    gen = info["generation"]
    if phase == "start":
        _gc_callback_start = time.monotonic()
    elif phase == "stop":
        _gc_time[gen] += time.monotonic() - _gc_callback_start
        _gc_counts[gen] += 1
        _gc_collected[gen] += info["collected"]


gc.callbacks.append(_gc_callback)


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
    suspect_names = set(config.get("suspect_names", []))

    name_parts = {}
    name_cache = {}
    const_refs = []
    intern_cache = {EMPTY: EMPTY}
    decls = {}
    deps = {}
    line_num = 0
    t0 = time.monotonic()

    # --- Diagnostic state ---
    diag_prev_rss = 0
    diag_prev_line = 0
    diag_milestone_bytes = 0
    diag_last_write_time = 0.0
    diag_checkpoints = []

    milestone_dir = os.path.join(PROJECT_DIR, "results", "cone")
    os.makedirs(milestone_dir, exist_ok=True)
    milestone_path = os.path.join(milestone_dir, "milestones.jsonl")
    milestone_fh = open(milestone_path, "a")

    def err(msg):
        print(msg, file=sys.stderr, flush=True)

    # --- GC toggle ---
    if _DIAG_GC_DISABLE:
        gc.disable()
        err("DIAGNOSTIC: GC disabled for this run")
    else:
        err(f"DIAGNOSTIC: GC enabled (thresholds: {gc.get_threshold()})")
    err(f"DIAGNOSTIC: physical RAM {PHYSICAL_RAM / (1024**3):.1f} GB, "
        f"ceiling {MEMORY_CEILING / (1024**3):.1f} GB ({_DIAG_CEILING_PCT}%)")

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

    # --- Diagnostic helpers ---

    def _gc_snapshot():
        return {
            "gen0": {"n": _gc_counts[0], "collected": _gc_collected[0],
                     "time_s": round(_gc_time[0], 4)},
            "gen1": {"n": _gc_counts[1], "collected": _gc_collected[1],
                     "time_s": round(_gc_time[1], 4)},
            "gen2": {"n": _gc_counts[2], "collected": _gc_collected[2],
                     "time_s": round(_gc_time[2], 4)},
            "total_gc_s": round(sum(_gc_time), 4),
            "enabled": gc.isenabled(),
        }

    def _write_milestone(record):
        nonlocal diag_milestone_bytes, diag_last_write_time
        if diag_milestone_bytes >= _MILESTONE_CAP:
            return
        now = time.monotonic()
        if now - diag_last_write_time < _MIN_WRITE_GAP:
            return
        line = json.dumps(record, separators=(",", ":")) + "\n"
        encoded = line.encode()
        if diag_milestone_bytes + len(encoded) > _MILESTONE_CAP:
            return
        try:
            milestone_fh.write(line)
            diag_milestone_bytes += len(encoded)
            diag_last_write_time = now
            if record.get("t") == "heavy":
                milestone_fh.flush()
                os.fsync(milestone_fh.fileno())
        except Exception:
            pass

    def diag_checkpoint(is_heavy):
        nonlocal diag_prev_rss, diag_prev_line

        ru = resource.getrusage(resource.RUSAGE_SELF)
        rss = ru.ru_maxrss  # bytes on macOS
        elapsed = time.monotonic() - t0

        record = {
            "t": "heavy" if is_heavy else "light",
            "line": line_num,
            "wall_s": round(elapsed, 2),
            "rss_bytes": rss,
            "rss_pct": round(100 * rss / PHYSICAL_RAM, 1),
            "ceil_pct": round(100 * rss / MEMORY_CEILING, 1),
            "const_refs_len": len(const_refs),
            "intern_len": len(intern_cache),
            "deps_len": len(deps),
            "names_len": len(name_parts),
            "decls_len": len(decls),
            "const_refs_sizeof": sys.getsizeof(const_refs),
            "intern_sizeof": sys.getsizeof(intern_cache),
            "gc": _gc_snapshot(),
        }

        if is_heavy and len(const_refs) > 0:
            non_none = sum(1 for x in const_refs if x is not None)
            record["const_refs_non_none"] = non_none

            n_samples = min(1000, len(const_refs))
            step = max(1, len(const_refs) // n_samples)
            fs_sizes = []
            for i in range(0, len(const_refs), step):
                v = const_refs[i]
                if v is not None:
                    fs_sizes.append(sys.getsizeof(v))
            if fs_sizes:
                avg_fs = sum(fs_sizes) / len(fs_sizes)
                record["avg_frozenset_bytes"] = round(avg_fs, 1)
                record["est_frozenset_total_bytes"] = int(avg_fs * non_none)

        if diag_prev_rss > 0 and diag_prev_line > 0:
            delta_rss = rss - diag_prev_rss
            delta_lines = line_num - diag_prev_line
            if delta_lines > 0:
                growth = delta_rss / delta_lines
                record["growth_mb_per_Mline"] = round(
                    growth * 1e6 / (1024**2), 1)
                headroom = MEMORY_CEILING - rss
                if growth > 0:
                    record["est_oom_at_line"] = line_num + int(
                        headroom / growth)

        diag_prev_rss = rss
        diag_prev_line = line_num
        diag_checkpoints.append(record)
        _write_milestone(record)

        oom_str = ""
        if "est_oom_at_line" in record:
            oom_str = f", est OOM at {record['est_oom_at_line']/1e6:.0f}M"
        err(f"  DIAG: RSS={rss/(1024**2):.0f}MB ({record['rss_pct']}% phys, "
            f"{record['ceil_pct']}% ceil){oom_str}, GC={sum(_gc_time):.1f}s")

        return rss

    def dump_partial(reason):
        out_dir = os.path.join(PROJECT_DIR, "results", "cone")
        os.makedirs(out_dir, exist_ok=True)
        partial_path = os.path.join(out_dir, "cone-partial.json")

        total_estimate = 1_080_000_000
        pct = round(100 * line_num / total_estimate, 1)

        est_bytes = len(deps) * 2000
        deps_to_write = deps
        if est_bytes > _PARTIAL_CAP:
            max_entries = int(_PARTIAL_CAP / 2000)
            keys = list(deps.keys())[-max_entries:]
            deps_to_write = {k: deps[k] for k in keys}
            err(f"  Truncating partial dump: {max_entries:,} of "
                f"{len(deps):,} entries")

        suspects_found = {}
        if suspect_names:
            for sname in sorted(suspect_names):
                referencing = [d for d, refs in deps.items()
                               if sname in refs]
                if referencing:
                    suspects_found[sname] = len(referencing)
            if suspects_found:
                err(f"  Suspects in partial deps: {suspects_found}")
            else:
                err(f"  No suspect names in partial deps so far")

        partial = {
            "status": "partial",
            "reason": reason,
            "lines_processed": line_num,
            "lines_total_estimate": total_estimate,
            "pct_processed": pct,
            "declarations_found": len(decls),
            "deps_entries": len(deps_to_write),
            "deps_total": len(deps),
            "elapsed_s": round(time.monotonic() - t0, 1),
            "rss_at_exit_bytes": resource.getrusage(
                resource.RUSAGE_SELF).ru_maxrss,
            "suspects_in_partial_deps": suspects_found,
            "deps": {name: sorted(refs)
                     for name, refs in deps_to_write.items()},
        }

        try:
            with open(partial_path, "w") as f:
                json.dump(partial, f, indent=2)
            err(f"Wrote partial results ({len(deps_to_write):,} decls, "
                f"{pct}%) to {partial_path}")
        except Exception as e:
            err(f"Failed to write partial results: {e}")

    def write_diagnostics(exit_reason):
        out_dir = os.path.join(PROJECT_DIR, "results", "cone")
        os.makedirs(out_dir, exist_ok=True)
        diag_path = os.path.join(out_dir, "diagnostics.json")

        diag = {
            "config": {
                "gc_disabled": _DIAG_GC_DISABLE,
                "gc_thresholds": list(gc.get_threshold()),
                "memory_ceiling_pct": _DIAG_CEILING_PCT,
                "physical_ram_bytes": PHYSICAL_RAM,
                "memory_ceiling_bytes": MEMORY_CEILING,
                "python_version": sys.version,
                "platform": sys.platform,
            },
            "exit_reason": exit_reason,
            "final_line": line_num,
            "final_decls": len(decls),
            "final_elapsed_s": round(time.monotonic() - t0, 1),
            "checkpoints": diag_checkpoints,
        }

        try:
            with open(diag_path, "w") as f:
                json.dump(diag, f, indent=2)
            err(f"Wrote diagnostics to {diag_path}")
        except Exception as e:
            err(f"Failed to write diagnostics: {e}")

    # --- SIGTERM handler ---
    def _sigterm_handler(signum, frame):
        err(f"\nSIGTERM received at line {line_num:,}")
        dump_partial("sigterm")
        write_diagnostics("sigterm")
        try:
            milestone_fh.close()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm_handler)

    # --- Main parsing loop ---

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

            if "const" in obj:
                const_refs[idx] = intern_set(frozenset({obj["const"]["name"]}))
            elif "app" in obj:
                a = obj["app"]
                const_refs[idx] = intern_set(
                    get_refs(a["fn"]) | get_refs(a["arg"]))
            elif "lam" in obj:
                la = obj["lam"]
                const_refs[idx] = intern_set(
                    get_refs(la["type"]) | get_refs(la["body"]))
            elif "forallE" in obj:
                fa = obj["forallE"]
                const_refs[idx] = intern_set(
                    get_refs(fa["type"]) | get_refs(fa["body"]))
            elif "letE" in obj:
                le = obj["letE"]
                const_refs[idx] = intern_set(
                    get_refs(le["type"]) | get_refs(le["value"])
                    | get_refs(le["body"]))
            elif "proj" in obj:
                const_refs[idx] = intern_set(
                    get_refs(obj["proj"]["struct"]))
            else:
                const_refs[idx] = EMPTY

        elif "meta" in obj:
            pass

        elif "il" in obj:
            pass

        else:
            for kind in ("def", "thm", "inductive", "quot", "axiom",
                         "opaque"):
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
                f"{len(const_refs):,} exprs, "
                f"{len(intern_cache):,} unique ref sets, {elapsed:.0f}s")

            is_heavy = (line_num
                        % (_DIAG_HEAVY_INTERVAL * 1_000_000) == 0)
            current_rss = diag_checkpoint(is_heavy)

            if current_rss >= MEMORY_CEILING:
                err(f"DIAGNOSTIC: RSS {current_rss/(1024**2):.0f}MB "
                    f">= ceiling "
                    f"{MEMORY_CEILING/(1024**2):.0f}MB "
                    f"({_DIAG_CEILING_PCT}%)")
                dump_partial("memory_ceiling")
                write_diagnostics("memory_ceiling")
                try:
                    milestone_fh.close()
                except Exception:
                    pass
                sys.exit(0)

    elapsed = time.monotonic() - t0
    err(f"Parsed {line_num:,} lines in {elapsed:.1f}s: "
        f"{len(decls):,} declarations, {len(const_refs):,} expressions, "
        f"{len(name_parts):,} names, "
        f"{len(intern_cache):,} unique ref sets")

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

    err(f"\nAll declarations in any cone: "
        f"{len(all_in_cone):,} of {len(decls):,}")
    err(f"Axioms / unresolved names in cone: {sorted(axioms_in_cone)}")

    unexpected = axioms_in_cone - permitted_axioms - {""}
    known_lean_axioms = {
        "Lean.ofReduceBool", "Lean.ofReduceNat", "Lean.trustCompiler",
        "Quot.lcInv", "isScalarObj", "lcAny", "lcCast", "lcErased",
        "lcProof", "lcUnreachable", "lcVoid", "sorryAx"
    }
    suspicious_axioms = unexpected - known_lean_axioms
    if suspicious_axioms:
        err(f"\n*** D1 FLAG: unexpected axioms in cone: "
            f"{sorted(suspicious_axioms)}")
    elif unexpected:
        err(f"\nKnown Lean axioms in cone (check if sorryAx is here): "
            f"{sorted(unexpected)}")
    else:
        err("\nD1 clean on this slice: only permitted axioms in cone")

    # --- Suspect-name check ---
    suspects_in_cone = {}
    suspects_in_deps = {}
    if suspect_names:
        for sname in sorted(suspect_names):
            in_cones = [t for t, c in cones.items() if sname in c]
            if in_cones:
                suspects_in_cone[sname] = in_cones
                err(f"  *** SUSPECT {sname} in cone of: "
                    f"{', '.join(in_cones)}")
            referencing = [d for d, refs in deps.items()
                           if sname in refs]
            if referencing:
                suspects_in_deps[sname] = referencing
        if not suspects_in_cone:
            err(f"\nSuspect names absent from all cones: "
                f"{sorted(suspect_names)}")
        err(f"Suspects directly referenced by {len(set().union(*suspects_in_deps.values()) if suspects_in_deps else [])} "
            f"declarations")

    # --- Cone overlap and inter-theorem dependencies ---
    cone_overlap = {}
    inter_deps = {}
    thm_list = sorted(cones.keys())
    for i, t1 in enumerate(thm_list):
        for t2 in thm_list[i + 1:]:
            shared = len(cones[t1] & cones[t2])
            cone_overlap[f"{t1} & {t2}"] = shared
        inter_deps[t1] = [t2 for t2 in thm_list
                          if t2 != t1 and t2 in cones[t1]]
    if cone_overlap:
        err(f"\nCone overlap: {cone_overlap}")
    if any(inter_deps.values()):
        err(f"Inter-theorem deps: {inter_deps}")

    out_dir = os.path.join(PROJECT_DIR, "results", "cone")
    os.makedirs(out_dir, exist_ok=True)

    result = {
        "theorems": config["theorem_names"],
        "permitted_axioms": config["permitted_axioms"],
        "suspect_names": config.get("suspect_names", []),
        "total_declarations": len(decls),
        "total_in_cone": len(all_in_cone),
        "axioms_in_cone": sorted(axioms_in_cone),
        "unexpected_axioms": sorted(unexpected),
        "suspects_in_cone": suspects_in_cone,
        "suspects_in_deps": {k: sorted(v)
                             for k, v in suspects_in_deps.items()},
        "cone_overlap": cone_overlap,
        "inter_theorem_deps": inter_deps,
        "cones": {t: {"size": len(c), "members": sorted(c)}
                  for t, c in cones.items()},
    }
    out_path = os.path.join(out_dir, "cone-report.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    err(f"\nWrote {out_path}")

    write_diagnostics("completed")
    try:
        milestone_fh.close()
    except Exception:
        pass


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
