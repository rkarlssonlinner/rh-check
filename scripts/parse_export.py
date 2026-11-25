"""Streaming NDJSON parser for Lean 4 kernel exports (lean4export format 3.1.0).

Memory-efficient: instead of storing full expression dicts, computes compact
per-expression feature flags bottom-up and discards the raw JSON. Expressions
reference only lower-numbered expressions, so features propagate forward.

Designed for piped input: zstd -d --long=30 -c export.ndjson.zst | python3 -I parse_export.py
"""
import json
import sys
import collections
import time

try:
    import orjson
    _loads = orjson.loads
    _ParseError = orjson.JSONDecodeError
except ImportError:
    _loads = json.loads
    _ParseError = json.JSONDecodeError

# Per-expression feature bits (stored in a bytearray, 1 byte per expr)
F_PROJ      = 0x01  # subtree contains a proj expression
F_FVAR      = 0x02  # subtree contains a free variable reference
F_LARGE_NAT = 0x04  # subtree contains a natVal > 10K bits
F_HUGE_NAT  = 0x08  # subtree contains a natVal > 1M bits
F_TRUE      = 0x10  # subtree contains a const reference to True

_EXACT_DIGITS = 4000  # below CPython's default int/str limit of 4300 digits
_LOG2_10 = 3.321928094887362


def _nat_bits(val):
    """Bit length of a natVal, or None if malformed.

    The export stores natVal as a decimal string (checked on the 10K-line
    sample). Above _EXACT_DIGITS the length is estimated from the digit
    count, which is off by at most 4 bits and avoids a slow conversion of
    a giant literal.
    """
    if isinstance(val, int):
        return val.bit_length()
    if not (isinstance(val, str) and val.isascii() and val.isdigit()):
        return None
    s = val.lstrip("0")
    if len(s) <= _EXACT_DIGITS:
        return int(s or "0").bit_length()
    return int(len(s) * _LOG2_10) + 1


class ExportParser:
    def __init__(self, track_const_refs=False):
        self.names = {}        # index -> resolved full name string
        self.name_parts = {}   # index -> (prefix_idx, component)
        self.levels = {}       # index -> level dict (small, kept)
        self.track_const_refs = track_const_refs

        # Compact expression features: 1 byte per expression index
        self.expr_flags = bytearray()
        # Sparse storage for detector-specific data
        self.expr_const_refs = {}  # expr_idx -> set of name indices (cone mapping only)
        self.expr_proj_info = {}   # expr_idx -> list of (struct_name_idx,)
        self.expr_nat_bits = {}    # expr_idx -> max bit length of natVal in subtree
        self._true_name_idx = None # name index for "True", resolved on first encounter

        self.meta = None
        self.line_num = 0
        self.decl_count = 0
        self.counts = collections.Counter()

    def resolve_name(self, idx):
        if idx in self.names:
            return self.names[idx]
        if idx == 0:
            self.names[0] = ""
            return ""
        stack = []
        cur = idx
        while cur not in self.names:
            if cur == 0:
                self.names[0] = ""
                break
            stack.append(cur)
            cur = self.name_parts[cur][0]
        for i in reversed(stack):
            pre_idx, component = self.name_parts[i]
            prefix = self.names[pre_idx]
            self.names[i] = f"{prefix}.{component}" if prefix else component
        return self.names[idx]

    def _ensure_flags(self, idx):
        if idx >= len(self.expr_flags):
            self.expr_flags.extend(b'\x00' * (idx + 1 - len(self.expr_flags)))

    def _merge_child(self, parent_idx, child_idx):
        if child_idx < len(self.expr_flags):
            self.expr_flags[parent_idx] |= self.expr_flags[child_idx]
        if self.track_const_refs and child_idx in self.expr_const_refs:
            self.expr_const_refs.setdefault(parent_idx, set()).update(
                self.expr_const_refs[child_idx])
        # proj_info is NOT propagated — only stored on the direct proj expression.
        # The F_PROJ bit flag propagates via expr_flags and is enough for detectors.
        if child_idx in self.expr_nat_bits:
            cur = self.expr_nat_bits.get(parent_idx, 0)
            self.expr_nat_bits[parent_idx] = max(cur, self.expr_nat_bits[child_idx])

    def _process_expr(self, idx, obj):
        self._ensure_flags(idx)
        expr = {k: v for k, v in obj.items() if k != "ie"}
        children = []

        if "const" in expr:
            c = expr["const"]
            name_idx = c.get("name", 0)
            if self.track_const_refs:
                self.expr_const_refs.setdefault(idx, set()).add(name_idx)
            if self._true_name_idx is not None and name_idx == self._true_name_idx:
                self.expr_flags[idx] |= F_TRUE

        elif "app" in expr:
            a = expr["app"]
            children = [a["fn"], a["arg"]]

        elif "lam" in expr:
            children = [expr["lam"]["type"], expr["lam"]["body"]]

        elif "forallE" in expr:
            children = [expr["forallE"]["type"], expr["forallE"]["body"]]

        elif "letE" in expr:
            le = expr["letE"]
            children = [le["type"], le["value"], le["body"]]

        elif "proj" in expr:
            p = expr["proj"]
            self.expr_flags[idx] |= F_PROJ
            struct_name = p.get("typeName", p.get("struct", None))
            if struct_name is not None:
                self.expr_proj_info.setdefault(idx, []).append((struct_name,))
            # The export names the projected expression "struct"; an
            # earlier version read "expr" and dropped every proj subtree.
            if "struct" in p:
                children = [p["struct"]]
            else:
                self.counts["proj_skipped"] += 1

        elif "mdata" in expr:
            # Field name not yet seen in our sample; misses are counted.
            md = expr["mdata"]
            e = md.get("expr") if isinstance(md, dict) else None
            if isinstance(e, int):
                children = [e]
            else:
                self.counts["mdata_skipped"] += 1

        elif "natVal" in expr:
            bits = _nat_bits(expr["natVal"])
            if bits is None:
                self.counts["natVal_unparsed"] += 1
            else:
                self.expr_nat_bits[idx] = bits
                if bits > 10_000:
                    self.expr_flags[idx] |= F_LARGE_NAT
                if bits > 1_000_000:
                    self.expr_flags[idx] |= F_HUGE_NAT

        elif "fvar" in expr:
            self.expr_flags[idx] |= F_FVAR

        for child_idx in children:
            self._merge_child(idx, child_idx)

    def get_expr_features(self, expr_idx):
        """Get compact features for an expression index. Used by detectors."""
        flags = 0
        if expr_idx < len(self.expr_flags):
            flags = self.expr_flags[expr_idx]
        return {
            "flags": flags,
            "has_proj": bool(flags & F_PROJ),
            "has_fvar": bool(flags & F_FVAR),
            "has_large_nat": bool(flags & F_LARGE_NAT),
            "has_huge_nat": bool(flags & F_HUGE_NAT),
            "has_true": bool(flags & F_TRUE),
            "const_refs": self.expr_const_refs.get(expr_idx, set()),
            "proj_info": self.expr_proj_info.get(expr_idx, []),
            "max_nat_bits": self.expr_nat_bits.get(expr_idx, 0),
        }

    def get_decl_features(self, decl, kind):
        """Merge features from all expression indices referenced by a declaration."""
        expr_indices = []
        if kind in ("def", "thm", "opaque"):
            if "type" in decl:
                expr_indices.append(decl["type"])
            if "value" in decl:
                expr_indices.append(decl["value"])
        elif kind == "inductive":
            for t in decl.get("types", []):
                if "type" in t:
                    expr_indices.append(t["type"])
            for ctor in decl.get("ctors", []):
                if "type" in ctor:
                    expr_indices.append(ctor["type"])
            for rec in decl.get("recs", []):
                if "type" in rec:
                    expr_indices.append(rec["type"])
                for rule in rec.get("rules", []):
                    if "rhs" in rule:
                        expr_indices.append(rule["rhs"])
        elif kind == "quot":
            if "type" in decl:
                expr_indices.append(decl["type"])
        elif kind == "axiom":
            if "type" in decl:
                expr_indices.append(decl["type"])

        merged = {
            "flags": 0, "has_proj": False, "has_fvar": False,
            "has_large_nat": False, "has_huge_nat": False,
            "has_true": False,
            "const_refs": set(), "proj_info": [], "max_nat_bits": 0,
        }
        for eidx in expr_indices:
            f = self.get_expr_features(eidx)
            merged["flags"] |= f["flags"]
            merged["has_proj"] |= f["has_proj"]
            merged["has_fvar"] |= f["has_fvar"]
            merged["has_large_nat"] |= f["has_large_nat"]
            merged["has_huge_nat"] |= f["has_huge_nat"]
            merged["has_true"] |= f["has_true"]
            merged["const_refs"].update(f["const_refs"])
            merged["proj_info"].extend(f["proj_info"])
            merged["max_nat_bits"] = max(merged["max_nat_bits"], f["max_nat_bits"])
        return merged

    def parse_line(self, line):
        self.line_num += 1
        try:
            obj = _loads(line)
        except _ParseError:
            # Truncated zstd output ends mid-JSON-line. Treat as end of stream.
            self.counts["truncated"] += 1
            return ("truncated", self.line_num)

        if "meta" in obj:
            self.meta = obj["meta"]
            self.counts["meta"] += 1
            return ("meta", obj["meta"])

        if "in" in obj:
            idx = obj["in"]
            if "str" in obj:
                s = obj["str"]
                self.name_parts[idx] = (s["pre"], s["str"])
                self.counts["name_str"] += 1
                if s["str"] == "True" and s["pre"] == 0:
                    self._true_name_idx = idx
            elif "num" in obj:
                n = obj["num"]
                self.name_parts[idx] = (n["pre"], str(n["i"]))
                self.counts["name_num"] += 1
            return None

        if "il" in obj:
            idx = obj["il"]
            if "param" in obj:
                self.levels[idx] = {"kind": "param", "name": obj["param"]}
            elif "succ" in obj:
                self.levels[idx] = {"kind": "succ", "inner": obj["succ"]}
            elif "max" in obj:
                pair = obj["max"]
                self.levels[idx] = {"kind": "max", "lhs": pair[0], "rhs": pair[1]}
            elif "imax" in obj:
                pair = obj["imax"]
                self.levels[idx] = {"kind": "imax", "lhs": pair[0], "rhs": pair[1]}
            self.counts["level"] += 1
            return None

        if "ie" in obj:
            idx = obj["ie"]
            self._process_expr(idx, obj)
            expr_kind = next(k for k in obj if k != "ie")
            self.counts[f"expr_{expr_kind}"] += 1
            return None

        for decl_kind in ("def", "thm", "inductive", "quot", "axiom", "opaque"):
            if decl_kind in obj:
                self.decl_count += 1
                decl = obj[decl_kind]
                if decl_kind == "inductive":
                    name_idx = decl.get("types", [{}])[0].get("name", 0)
                else:
                    name_idx = decl.get("name", 0)
                name = self.resolve_name(name_idx)
                features = self.get_decl_features(decl, decl_kind)
                self.counts[f"decl_{decl_kind}"] += 1
                return ("decl", decl_kind, name, decl, self.line_num, features)

        self.counts["unknown"] += 1
        return ("unknown", obj, self.line_num)


def stream_parse(input_file, limit=None):
    parser = ExportParser()
    for line in input_file:
        line = line.strip()
        if not line:
            continue
        result = parser.parse_line(line)
        if result is not None:
            yield result
        if limit and parser.line_num >= limit:
            break
    yield ("summary", parser.counts, parser.decl_count, parser.line_num, parser.meta)


def main():
    limit = None
    if len(sys.argv) > 1:
        limit = int(sys.argv[1])

    print("parse_export — streaming NDJSON parser for Lean 4 kernel exports",
          file=sys.stderr)
    if limit:
        print(f"  limit: {limit:,} lines", file=sys.stderr)
    print(f"  mode: stdin", file=sys.stderr)
    print("", file=sys.stderr)

    start = time.time()
    decl_kinds = collections.Counter()
    errors = 0
    total_lines = 0
    total_decls = 0
    meta = None

    for result in stream_parse(sys.stdin, limit=limit):
        if result[0] == "meta":
            meta = result[1]
            print(f"Format: {meta['format']['version']}, "
                  f"Lean: {meta['lean']['version']} ({meta['lean']['githash'][:12]}), "
                  f"Exporter: {meta['exporter']['name']} {meta['exporter']['version']}",
                  file=sys.stderr)
        elif result[0] == "decl":
            _, kind, name, decl, line_num, features = result
            decl_kinds[kind] += 1
        elif result[0] == "unknown":
            errors += 1
            _, obj, line_num = result
            print(f"UNKNOWN line {line_num}: {json.dumps(obj)[:200]}", file=sys.stderr)
        elif result[0] == "summary":
            _, counts, total_decls, total_lines, meta = result

    elapsed = time.time() - start

    print(f"\n=== Parse Summary ===", file=sys.stderr)
    print(f"Lines:        {total_lines:>12,}", file=sys.stderr)
    print(f"Declarations: {total_decls:>12,}", file=sys.stderr)
    print(f"Errors:       {errors:>12,}", file=sys.stderr)
    print(f"Time:         {elapsed:>12.2f}s", file=sys.stderr)
    print(f"Lines/sec:    {total_lines/elapsed:>12,.0f}", file=sys.stderr)
    print(f"\nDeclarations by kind:", file=sys.stderr)
    for kind, count in sorted(decl_kinds.items(), key=lambda x: -x[1]):
        print(f"  {kind:<12} {count:>10,}", file=sys.stderr)

    print(f"\nLine types:", file=sys.stderr)
    for key, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {key:<16} {count:>10,}", file=sys.stderr)

    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
