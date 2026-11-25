"""
Build the dependency cone of the five main theorems.

Two-pass mode (recommended for the full export; full-run peak not yet measured):
  Pass 1 — lightweight scan to count per-expression references.
  Pass 2 — parse, compute deps, free each expression when its last reader is done.

Single-pass mode works exactly as before for stdin / small files.
No recursion.

Usage:
  # Two-pass (recommended for full export):
  .venv/bin/python3 -I scripts/cone_mapper.py data/sutherland/solution.ndjson.zst

  # Single-pass stdin:
  cat data/sutherland/solution-first-10k.ndjson | .venv/bin/python3 -I scripts/cone_mapper.py
  zstd -d --long=30 -c data/sutherland/solution.ndjson.zst | .venv/bin/python3 -I scripts/cone_mapper.py

Diagnostics (env vars):
  CONE_GC_DISABLE=1  — disable Python's cyclic GC (no cycles in this code)
  CONE_MEM_CEILING=80 — memory footprint ceiling as % of physical RAM (default: 80)
  CONE_SWAP_GROWTH_GB=2 — stop if system swap grows by more than this (default: 2)

Exit code 3 means the run stopped at a memory guard (partial results written).
"""
import sys
import os
import json
import collections
import ctypes
import itertools
import time
import gc
import resource
import signal
import subprocess
from array import array

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
_SWAP_GROWTH_LIMIT = int(
    float(os.environ.get("CONE_SWAP_GROWTH_GB", "2")) * 1024**3)
_DIAG_HEAVY_INTERVAL = 10  # heavy milestone every N million lines
_GUARD_EXIT_CODE = 3

# Reference counts: one uint16 per expression. A count that reaches _SAT
# stays at _SAT and that expression is never freed.
_SAT = 65535
_CACHE_FORMAT = 2  # bump when pass-1 counting changes


def _get_physical_ram():
    try:
        out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)
        return int(out.strip())
    except Exception:
        return 16 * 1024**3


def _get_current_rss():
    """Current RSS in bytes (not peak). Falls back to ru_maxrss."""
    try:
        out = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(os.getpid())],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        return int(out.strip()) * 1024
    except Exception:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


# macOS: RSS excludes compressed and swapped pages, so it stops growing
# when the system starts to compress. phys_footprint includes them.
# Layouts copied from <sys/resource.h> and <sys/sysctl.h>.
class _RusageInfoV2(ctypes.Structure):
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
        (n, ctypes.c_uint64) for n in (
            "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups",
            "ri_interrupt_wkups", "ri_pageins", "ri_wired_size",
            "ri_resident_size", "ri_phys_footprint",
            "ri_proc_start_abstime", "ri_proc_exit_abstime",
            "ri_child_user_time", "ri_child_system_time",
            "ri_child_pkg_idle_wkups", "ri_child_interrupt_wkups",
            "ri_child_pageins", "ri_child_elapsed_abstime",
            "ri_diskio_bytesread", "ri_diskio_byteswritten")]


class _XswUsage(ctypes.Structure):
    _fields_ = [("xsu_total", ctypes.c_uint64),
                ("xsu_avail", ctypes.c_uint64),
                ("xsu_used", ctypes.c_uint64),
                ("xsu_pagesize", ctypes.c_uint32),
                ("xsu_encrypted", ctypes.c_int32)]


_RUSAGE_INFO_V2 = 2

try:
    _libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    _libsystem.proc_pid_rusage.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _libsystem.proc_pid_rusage.restype = ctypes.c_int
    _libsystem.sysctlbyname.argtypes = [
        ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p, ctypes.c_size_t]
    _libsystem.sysctlbyname.restype = ctypes.c_int
except (OSError, AttributeError):
    _libsystem = None


def _get_footprint():
    """Physical footprint in bytes (what Activity Monitor shows).
    Falls back to RSS when libproc is unavailable."""
    if _libsystem is not None:
        ru = _RusageInfoV2()
        if _libsystem.proc_pid_rusage(
                os.getpid(), _RUSAGE_INFO_V2, ctypes.byref(ru)) == 0:
            return ru.ri_phys_footprint
    return _get_current_rss()


def _get_swap_used():
    """System-wide swap in use, in bytes. None if unavailable."""
    if _libsystem is None:
        return None
    xsw = _XswUsage()
    size = ctypes.c_size_t(ctypes.sizeof(xsw))
    if _libsystem.sysctlbyname(b"vm.swapusage", ctypes.byref(xsw),
                               ctypes.byref(size), None, 0) != 0:
        return None
    return xsw.xsu_used


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


# --- Two-pass helpers ---

def _expr_child_idxs(obj):
    """Sub-expression indices that an 'ie' object reads via get_refs."""
    if "app" in obj:
        a = obj["app"]
        return [a["fn"], a["arg"]]
    if "lam" in obj:
        la = obj["lam"]
        return [la["type"], la["body"]]
    if "forallE" in obj:
        fa = obj["forallE"]
        return [fa["type"], fa["body"]]
    if "letE" in obj:
        le = obj["letE"]
        return [le["type"], le["value"], le["body"]]
    if "proj" in obj:
        return [obj["proj"]["struct"]]
    if "mdata" in obj:
        # Field name not yet seen in our sample; main() counts misses.
        md = obj["mdata"]
        e = md.get("expr") if isinstance(md, dict) else None
        return [e] if isinstance(e, int) else []
    return []


def _open_ndjson_stream(path):
    """Open an NDJSON file (.zst or plain) for byte-level line iteration."""
    if path.endswith(".zst"):
        proc = subprocess.Popen(
            ["zstd", "-d", "--long=30", "-c", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return proc.stdout, proc
    else:
        return open(path, "rb"), None


def _pass1_ref_counts(path, err):
    """Pass 1: count how many times each expression index is referenced."""
    err(f"Pass 1: counting references in {path}")
    ref_counts = array("H")
    stream, proc = _open_ndjson_stream(path)
    line_num = 0
    t0 = time.monotonic()

    def _grow(needed_idx):
        gap = needed_idx + 1 - len(ref_counts)
        if gap > 0:
            ref_counts.frombytes(bytes(gap * ref_counts.itemsize))

    def _inc(idx):
        if ref_counts[idx] < _SAT:
            ref_counts[idx] += 1

    try:
        for raw in stream:
            line_num += 1
            obj = loads(raw)

            if "ie" in obj:
                idx = obj["ie"]
                _grow(idx)
                for si in dict.fromkeys(_expr_child_idxs(obj)):
                    _grow(si)
                    _inc(si)
            else:
                for kind in ("def", "thm", "inductive", "quot", "axiom",
                             "opaque"):
                    if kind in obj:
                        for eid in dict.fromkeys(
                                _decl_expr_ids(obj[kind])):
                            _grow(eid)
                            _inc(eid)
                        break

            if line_num % 10_000_000 == 0:
                elapsed = time.monotonic() - t0
                err(f"  Pass 1: {line_num/1e6:.0f}M lines, "
                    f"{len(ref_counts):,} slots, "
                    f"{_nbytes(ref_counts) / (1024**2):.0f} MB, "
                    f"{elapsed:.0f}s")
    finally:
        stream.close()
        if proc is not None:
            proc.wait()

    elapsed = time.monotonic() - t0
    err(f"Pass 1 complete: {line_num:,} lines, "
        f"{len(ref_counts):,} expression slots, "
        f"{elapsed:.1f}s")

    _save_pass1_cache(path, ref_counts, line_num, err)
    return ref_counts, line_num


def _nbytes(ref_counts):
    return len(ref_counts) * ref_counts.itemsize


def _pass1_cache_paths():
    cache_dir = os.path.join(PROJECT_DIR, "results", "cone")
    return (os.path.join(cache_dir, "pass1-cache.meta.json"),
            os.path.join(cache_dir, "pass1-cache.bin"))


def _save_pass1_cache(path, ref_counts, total_lines, err):
    meta_path, bin_path = _pass1_cache_paths()
    os.makedirs(os.path.dirname(meta_path), exist_ok=True)
    st = os.stat(path)
    meta = {
        "format": _CACHE_FORMAT,
        "saturation": _SAT,
        "itemsize": ref_counts.itemsize,
        "input_path": os.path.abspath(path),
        "input_size": st.st_size,
        "input_mtime": st.st_mtime,
        "total_lines": total_lines,
        "ref_counts_len": len(ref_counts),
    }
    try:
        with open(bin_path, "wb") as f:
            ref_counts.tofile(f)  # writes in blocks, no full copy
        with open(meta_path, "w") as f:
            json.dump(meta, f)
        err(f"Pass 1 cache saved ({_nbytes(ref_counts)/(1024**2):.0f} MB)")
    except Exception as e:
        err(f"WARNING: failed to save pass 1 cache: {e}")


def _load_pass1_cache(path, err):
    """Load cached ref_counts if the input file hasn't changed."""
    meta_path, bin_path = _pass1_cache_paths()
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        st = os.stat(path)
        if (meta.get("format") != _CACHE_FORMAT
                or meta.get("saturation") != _SAT
                or meta.get("itemsize") != array("H").itemsize):
            err("Pass 1 cache from an older format, re-running")
            return None
        if (meta["input_path"] != os.path.abspath(path)
                or meta["input_size"] != st.st_size
                or meta["input_mtime"] != st.st_mtime):
            err("Pass 1 cache stale (input changed), re-running")
            return None
        n = meta["ref_counts_len"]
        ref_counts = array("H", [0]) * n
        if os.path.getsize(bin_path) != _nbytes(ref_counts):
            err("Pass 1 cache corrupt (size mismatch), re-running")
            return None
        # Read straight into the array: no temporary bytes copy.
        mv = memoryview(ref_counts).cast("B")
        pos = 0
        with open(bin_path, "rb") as f:
            while pos < len(mv):
                got = f.readinto(mv[pos:pos + (1 << 26)])
                if not got:
                    break
                pos += got
        full = pos == len(mv)
        mv.release()
        if not full:
            err("Pass 1 cache corrupt (short read), re-running")
            return None
        err(f"Pass 1 loaded from cache: {meta['total_lines']:,} lines, "
            f"{len(ref_counts):,} slots "
            f"({_nbytes(ref_counts)/(1024**2):.0f} MB)")
        return ref_counts, meta["total_lines"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        return None


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


def main(input_path=None):
    config = load_config()
    theorem_names = set(config["theorem_names"])
    permitted_axioms = set(config["permitted_axioms"])
    suspect_names = set(config.get("suspect_names", []))

    two_pass = input_path is not None

    name_parts = {}
    name_cache = {}
    intern_cache = {} if two_pass else {EMPTY: EMPTY}
    decls = {}
    deps = {}
    line_num = 0
    mdata_seen = 0
    mdata_skipped = 0  # mdata lines without an int "expr" child
    swap_baseline = _get_swap_used()
    t0 = time.monotonic()

    if two_pass:
        _err = lambda m: print(m, file=sys.stderr, flush=True)
        cached = _load_pass1_cache(input_path, _err)
        if cached is not None:
            ref_counts, total_lines = cached
        else:
            ref_counts, total_lines = _pass1_ref_counts(input_path, _err)
        const_refs = {}
        diag_freed = 0
        diag_live_hwm = 0
    else:
        ref_counts = None
        const_refs = []
        diag_freed = 0
        diag_live_hwm = 0

    _stream = None
    _stream_proc = None

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

    err("cone_mapper — dependency-cone scanner for Lean 4 kernel exports")
    if two_pass:
        err(f"  input: {input_path} ({total_lines:,} lines)")
        err(f"  mode:  two-pass (memory-optimized)")
    else:
        err(f"  mode:  single-pass (stdin)")
    err("")

    # --- GC toggle ---
    if _DIAG_GC_DISABLE:
        gc.disable()
        err("DIAGNOSTIC: GC disabled for this run")
    else:
        err(f"DIAGNOSTIC: GC enabled (thresholds: {gc.get_threshold()})")
    err(f"DIAGNOSTIC: physical RAM {PHYSICAL_RAM / (1024**3):.1f} GB, "
        f"footprint ceiling {MEMORY_CEILING / (1024**3):.1f} GB "
        f"({_DIAG_CEILING_PCT}%)")
    if swap_baseline is None:
        err("DIAGNOSTIC: swap usage unavailable, swap guard OFF")
    else:
        err(f"DIAGNOSTIC: swap in use at start "
            f"{swap_baseline / (1024**3):.2f} GB, stop if it grows by "
            f"{_SWAP_GROWTH_LIMIT / (1024**3):.1f} GB")
    if two_pass:
        err(f"Pass 2: processing with {len(ref_counts):,} ref-count slots "
            f"({_nbytes(ref_counts) / (1024**2):.0f} MB), "
            f"{ref_counts.count(_SAT):,} saturated at {_SAT}")

    if two_pass:
        def intern_set(s):
            return frozenset(s) if not isinstance(s, frozenset) else s
    else:
        def intern_set(s):
            fs = frozenset(s) if not isinstance(s, frozenset) else s
            cached = intern_cache.get(fs)
            if cached is not None:
                return cached
            intern_cache[fs] = fs
            return fs

    if two_pass:
        def get_refs(idx):
            return const_refs.get(idx, EMPTY)

        def get_and_release(idx):
            nonlocal diag_freed
            val = const_refs.get(idx, EMPTY)
            if idx < len(ref_counts):
                c = ref_counts[idx]
                if 0 < c < _SAT:
                    c -= 1
                    ref_counts[idx] = c
                    if c == 0:
                        if const_refs.pop(idx, None) is not None:
                            diag_freed += 1
            return val

        def _decref(idx):
            nonlocal diag_freed
            if idx < len(ref_counts):
                c = ref_counts[idx]
                if 0 < c < _SAT:
                    c -= 1
                    ref_counts[idx] = c
                    if c == 0:
                        if const_refs.pop(idx, None) is not None:
                            diag_freed += 1

        def should_store(idx):
            return idx < len(ref_counts) and ref_counts[idx] > 0

    else:
        def get_refs(idx):
            if 0 <= idx < len(const_refs):
                r = const_refs[idx]
                if r is not None:
                    return r
            return EMPTY

        get_and_release = get_refs

        def _decref(idx):
            pass

        def should_store(idx):
            return True

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

        rss = _get_footprint()
        swap = _get_swap_used()
        elapsed = time.monotonic() - t0

        record = {
            "t": "heavy" if is_heavy else "light",
            "line": line_num,
            "wall_s": round(elapsed, 2),
            "footprint_bytes": rss,
            "footprint_pct": round(100 * rss / PHYSICAL_RAM, 1),
            "ceil_pct": round(100 * rss / MEMORY_CEILING, 1) if MEMORY_CEILING else None,
            "swap_used_bytes": swap,
            "const_refs_len": len(const_refs),
            "intern_len": len(intern_cache),
            "deps_len": len(deps),
            "names_len": len(name_parts),
            "decls_len": len(decls),
            "const_refs_sizeof": sys.getsizeof(const_refs),
            "intern_sizeof": sys.getsizeof(intern_cache),
            "gc": _gc_snapshot(),
        }

        if two_pass:
            record["const_refs_freed"] = diag_freed
            record["const_refs_live_hwm"] = diag_live_hwm
            record["ref_counts_len"] = len(ref_counts)

        if is_heavy and len(const_refs) > 0:
            if two_pass:
                non_none = len(const_refs)
                record["const_refs_non_none"] = non_none
                fs_sizes = [sys.getsizeof(v) for v in
                            itertools.islice(const_refs.values(), 1000)]
            else:
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
                record["est_frozenset_total_bytes"] = int(
                    avg_fs * non_none)

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
        swap_str = "" if swap is None else f", swap={swap/(1024**3):.2f}GB"
        err(f"  DIAG: footprint={rss/(1024**2):.0f}MB "
            f"({record['footprint_pct']}% phys, "
            f"{record['ceil_pct']}% ceil){oom_str}{swap_str}, "
            f"GC={sum(_gc_time):.1f}s")

        return rss, swap

    def dump_partial(reason):
        out_dir = os.path.join(PROJECT_DIR, "results", "cone")
        os.makedirs(out_dir, exist_ok=True)
        partial_path = os.path.join(out_dir, "cone-partial.json")
        deps_path = os.path.join(out_dir, "cone-partial-deps.jsonl")

        total_estimate = 1_080_000_000
        pct = round(100 * line_num / total_estimate, 1)

        # Stream one declaration per line; no in-memory copy of deps.
        # json.dumps output is ASCII, so len(line) is its size in bytes.
        deps_bytes = 0
        deps_written = 0
        deps_truncated = False
        try:
            with open(deps_path, "w") as f:
                for name, refs in deps.items():
                    line = json.dumps({"decl": name, "refs": sorted(refs)},
                                      separators=(",", ":")) + "\n"
                    if deps_bytes + len(line) > _PARTIAL_CAP:
                        deps_truncated = True
                        break
                    f.write(line)
                    deps_bytes += len(line)
                    deps_written += 1
        except Exception as e:
            err(f"Failed to write partial deps: {e}")
        if deps_truncated:
            err(f"  Partial deps stopped at the "
                f"{_PARTIAL_CAP / (1024**3):.0f} GB cap: {deps_written:,} of "
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
            "deps_file": os.path.basename(deps_path),
            "deps_entries": deps_written,
            "deps_total": len(deps),
            "deps_truncated": deps_truncated,
            "mdata_seen": mdata_seen,
            "mdata_skipped": mdata_skipped,
            "elapsed_s": round(time.monotonic() - t0, 1),
            "footprint_at_exit_bytes": _get_footprint(),
            "suspects_in_partial_deps": suspects_found,
        }

        try:
            with open(partial_path, "w") as f:
                json.dump(partial, f, indent=2)
            err(f"Wrote partial results ({deps_written:,} decls, "
                f"{pct}%) to {partial_path} and {deps_path}")
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
            "mdata_seen": mdata_seen,
            "mdata_skipped": mdata_skipped,
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
            if _stream_proc is not None:
                _stream.close()
                _stream_proc.terminate()
        except Exception:
            pass
        try:
            milestone_fh.close()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm_handler)

    # --- Open input stream ---

    if two_pass:
        _stream, _stream_proc = _open_ndjson_stream(input_path)
    else:
        _stream = sys.stdin

    # --- Main parsing loop ---

    err(f"Theorem targets: {sorted(theorem_names)}")
    err(f"Permitted axioms: {sorted(permitted_axioms)}")
    err("Parsing...")

    for raw in _stream:
        line_num += 1
        obj = loads(raw)

        if "in" in obj:
            idx = obj["in"]
            # sys.intern: components like "GlobalTheory" repeat millions
            # of times; keep one copy of each string.
            if "str" in obj:
                name_parts[idx] = (obj["str"]["pre"],
                                   sys.intern(obj["str"]["str"]))
            elif "num" in obj:
                name_parts[idx] = (obj["num"]["pre"],
                                   sys.intern(str(obj["num"]["i"])))

        elif "ie" in obj:
            idx = obj["ie"]

            if two_pass:
                if "const" in obj:
                    if should_store(idx):
                        const_refs[idx] = intern_set(
                            frozenset({obj["const"]["name"]}))
                else:
                    children = list(dict.fromkeys(
                        _expr_child_idxs(obj)))
                    if "mdata" in obj:
                        mdata_seen += 1
                        if not children:
                            mdata_skipped += 1
                    if should_store(idx) and children:
                        # `a | b` always allocates a new frozenset. When
                        # one side already contains the other, share it.
                        merged = EMPTY
                        for ci in children:
                            r = get_and_release(ci)
                            if not r or r is merged:
                                continue
                            if not merged or merged <= r:
                                merged = r
                            elif not r <= merged:
                                merged = merged | r
                        if merged:
                            const_refs[idx] = merged
                    elif children:
                        for ci in children:
                            _decref(ci)
            else:
                ensure_slot(idx)

                if "const" in obj:
                    const_refs[idx] = intern_set(
                        frozenset({obj["const"]["name"]}))
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
                elif "mdata" in obj:
                    mdata_seen += 1
                    kids = _expr_child_idxs(obj)
                    if kids:
                        const_refs[idx] = intern_set(get_refs(kids[0]))
                    else:
                        mdata_skipped += 1
                        const_refs[idx] = EMPTY
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
                    for eid in dict.fromkeys(_decl_expr_ids(decl)):
                        all_refs |= get_and_release(eid)

                    ref_names = set()
                    for nidx in all_refs:
                        rname = resolve_name(nidx, name_parts, name_cache)
                        if rname and rname != name:
                            ref_names.add(rname)

                    decls[name] = {"kind": kind, "line": line_num}
                    # tuple: ~8 B per name vs ~35 B in a set
                    deps[name] = tuple(ref_names)
                    break

        if line_num % 1_000_000 == 0:
            elapsed = time.monotonic() - t0
            if two_pass:
                pct = 100 * line_num / total_lines
                err(f"  {line_num/1e6:.0f}M lines ({pct:.1f}%), "
                    f"{len(decls):,} decls, "
                    f"{len(const_refs):,} live / {diag_freed:,} freed, "
                    f"{elapsed:.0f}s")
            else:
                err(f"  {line_num/1e6:.0f}M lines, {len(decls):,} decls, "
                    f"{len(const_refs):,} exprs, "
                    f"{len(intern_cache):,} unique ref sets, {elapsed:.0f}s")

            is_heavy = (line_num
                        % (_DIAG_HEAVY_INTERVAL * 1_000_000) == 0)
            current_rss, current_swap = diag_checkpoint(is_heavy)

            stop_reason = None
            if current_rss >= MEMORY_CEILING:
                err(f"DIAGNOSTIC: footprint {current_rss/(1024**2):.0f}MB "
                    f">= ceiling "
                    f"{MEMORY_CEILING/(1024**2):.0f}MB "
                    f"({_DIAG_CEILING_PCT}%)")
                stop_reason = "memory_ceiling"
            elif (swap_baseline is not None and current_swap is not None
                    and current_swap - swap_baseline > _SWAP_GROWTH_LIMIT):
                err(f"DIAGNOSTIC: swap grew "
                    f"{(current_swap - swap_baseline)/(1024**3):.2f} GB "
                    f"since start (limit "
                    f"{_SWAP_GROWTH_LIMIT/(1024**3):.1f} GB)")
                stop_reason = "swap_growth"
            if stop_reason:
                dump_partial(stop_reason)
                write_diagnostics(stop_reason)
                try:
                    if _stream_proc is not None:
                        _stream.close()
                        _stream_proc.terminate()
                except Exception:
                    pass
                try:
                    milestone_fh.close()
                except Exception:
                    pass
                sys.exit(_GUARD_EXIT_CODE)

    # --- Close input stream ---
    if _stream_proc is not None:
        _stream.close()
        _stream_proc.wait()

    elapsed = time.monotonic() - t0
    if two_pass:
        err(f"Parsed {line_num:,} lines in {elapsed:.1f}s: "
            f"{len(decls):,} declarations, "
            f"{diag_freed:,} freed / {len(const_refs):,} still live, "
            f"{len(name_parts):,} names, "
            f"{len(intern_cache):,} unique ref sets")
        saturated = ref_counts.count(_SAT)
        stale = len(ref_counts) - ref_counts.count(0) - saturated
        if stale:
            err(f"WARNING: {stale} expressions with non-zero ref counts "
                f"after parsing")
        err(f"{saturated:,} expressions saturated at {_SAT} (never freed)")
    else:
        err(f"Parsed {line_num:,} lines in {elapsed:.1f}s: "
            f"{len(decls):,} declarations, {len(const_refs):,} expressions, "
            f"{len(name_parts):,} names, "
            f"{len(intern_cache):,} unique ref sets")
    err(f"mdata expressions: {mdata_seen:,} seen, {mdata_skipped:,} "
        f"skipped (no int 'expr' child)")
    if mdata_skipped:
        err(f"WARNING: {mdata_skipped:,} mdata expressions skipped; "
            f"constants under them are missing from the cones")

    del const_refs
    del intern_cache
    if two_pass:
        del ref_counts

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
        "mdata_seen": mdata_seen,
        "mdata_skipped": mdata_skipped,
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
    if len(sys.argv) > 1:
        main(input_path=sys.argv[1])
    else:
        main()
