"""
Stream the full NDJSON export and keep only lines the exploit detectors need.

Usage (from project root):
  zstd -d --long=30 -c data/sutherland/solution.ndjson.zst \
    | .venv/bin/python3 -I scripts/filter-targets.py \
    > data/sutherland/targets.ndjson

Filter B: keeps declarations, targeted expressions, names, and levels.
Drops bulk expressions (app, lam, forallE, bvar, letE) — ~75% of the file.

Covers detectors D1–D7 and D9. D8 (hash collisions) needs a separate full pass.
"""
import sys
import orjson

DECL_KEYS = frozenset({"def", "thm", "inductive", "quot", "meta"})
TARGET_EXPR = frozenset({"proj", "natVal", "sort", "const"})



print("filter-targets — keep only detector-relevant lines from Lean 4 kernel exports",
      file=sys.stderr)
print(f"  mode: stdin → stdout", file=sys.stderr)
print("", file=sys.stderr)

kept = 0
dropped = 0
errors = 0
stdout = sys.stdout.buffer

for raw in sys.stdin.buffer:
    try:
        obj = orjson.loads(raw)
    except orjson.JSONDecodeError:
        errors += 1
        print(f"PARSE ERROR line {kept+dropped+errors}: {raw[:100]}", file=sys.stderr)
        continue

    keys = obj.keys()
    if keys & DECL_KEYS or keys & TARGET_EXPR:
        stdout.write(raw)
        kept += 1
    elif "in" in keys or "il" in keys:
        stdout.write(raw)
        kept += 1
    else:
        dropped += 1

print(f"\n=== Filter summary ===", file=sys.stderr)
print(f"Kept:    {kept:>12,}", file=sys.stderr)
print(f"Dropped: {dropped:>12,}", file=sys.stderr)
print(f"Errors:  {errors:>12,}", file=sys.stderr)
print(f"Ratio:   {100*kept/(kept+dropped+errors):.1f}% kept", file=sys.stderr)
