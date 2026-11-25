#!/usr/bin/env bash
# Download and verify the RH kernel export from Sutherland's MIT page.
# Run this script manually — never via an agent.
set -euo pipefail

BASEDIR="$(cd "$(dirname "$0")/.." && pwd)"
DATADIR="$BASEDIR/data/sutherland"
LOGFILE="$BASEDIR/provenance/download-verify.log"
BASEURL="https://math.mit.edu/~drew/grh"

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "$LOGFILE"; }

mkdir -p "$DATADIR"
: > "$LOGFILE"

log "=== RH Export Download and Verification ==="
log "Target directory: $DATADIR"

# Always download small auxiliary files (tiny, always useful)
SMALL_FILES=(
    "comparator.json"
    "audit.log"
    "explicit-statements.out"
    "lean4lean-raised-fuel.log"
    "robin-deps.txt"
    "lagarias-deps.txt"
)
for f in "${SMALL_FILES[@]}"; do
    if [ -f "$DATADIR/$f" ]; then
        log "SKIP $f (already exists)"
    else
        log "Downloading $f..."
        curl -fSL "$BASEURL/$f" -o "$DATADIR/$f"
        log "Downloaded $f ($(wc -c < "$DATADIR/$f") bytes)"
    fi
done

# --peek mode: stream the first 10K lines without full download or SHA check.
if [ "${1:-}" = "--peek" ]; then
    log "PEEK MODE: streaming first 10,000 lines (no SHA verification)"
    set +o pipefail
    curl -fSL "$BASEURL/solution.ndjson.zst" \
        | zstd -d --long=30 -c \
        | head -n 10000 > "$DATADIR/solution-first-10k.ndjson"
    set -o pipefail
    log "Saved $(wc -l < "$DATADIR/solution-first-10k.ndjson") lines to $DATADIR/solution-first-10k.ndjson"
    log "Done (peek only — run without --peek for full download with SHA verification)."
    exit 0
fi

# --chunk SIZE mode: download SIZE more bytes, then decompress and scan what we have.
# Re-run to get the next chunk. zstd exits 1 on truncated input but outputs all
# complete blocks — verified: 1 MB of the real export yields 140K valid lines.
FULL_SIZE=7699933588
EXPORT_FILE="$DATADIR/solution.ndjson.zst"

if [ "${1:-}" = "--chunk-next" ]; then
    CHUNK_RAW="${2:?Usage: --chunk-next SIZE (e.g. 500M, 1G)}"
    # Parse human size to bytes
    parse_size() {
        local s="$1"
        case "$s" in
            *G|*g) echo $(( ${s%[Gg]} * 1073741824 )) ;;
            *M|*m) echo $(( ${s%[Mm]} * 1048576 )) ;;
            *K|*k) echo $(( ${s%[Kk]} * 1024 )) ;;
            *)     echo "$s" ;;
        esac
    }
    CHUNK_BYTES=$(parse_size "$CHUNK_RAW")

    CURRENT_SIZE=0
    if [ -f "$EXPORT_FILE" ]; then
        CURRENT_SIZE=$(wc -c < "$EXPORT_FILE" | tr -d ' ')
    fi

    if [ "$CURRENT_SIZE" -ge "$FULL_SIZE" ]; then
        log "File already complete ($CURRENT_SIZE bytes). Skipping download."
    else
        END_BYTE=$(( CURRENT_SIZE + CHUNK_BYTES - 1 ))
        if [ "$END_BYTE" -ge "$FULL_SIZE" ]; then
            END_BYTE=$(( FULL_SIZE - 1 ))
        fi
        log "CHUNK: downloading bytes ${CURRENT_SIZE}-${END_BYTE} of $FULL_SIZE"
        curl -fSL --progress-bar --retry 3 --retry-delay 10 \
            --range "$CURRENT_SIZE-$END_BYTE" \
            "$BASEURL/solution.ndjson.zst" >> "$EXPORT_FILE"
        NEW_SIZE=$(wc -c < "$EXPORT_FILE" | tr -d ' ')
        log "File size: $NEW_SIZE / $FULL_SIZE bytes ($(( NEW_SIZE * 100 / FULL_SIZE ))%)"
    fi

    # Verify SHA-256 if complete
    CURRENT_SIZE=$(wc -c < "$EXPORT_FILE" | tr -d ' ')
    if [ "$CURRENT_SIZE" -ge "$FULL_SIZE" ]; then
        log "Download complete. Verifying SHA-256..."
        ACTUAL=$(shasum -a 256 "$EXPORT_FILE" | awk '{print $1}')
        EXPECTED="61a8938ad5f5e57397c1c0e3b954916af546d9004ade01c3555744a681b05381"
        if [ "$ACTUAL" = "$EXPECTED" ]; then
            log "SHA-256 PASS"
        else
            log "SHA-256 FAIL (expected $EXPECTED, got $ACTUAL)"
            exit 1
        fi
    fi

    # Scan what we have. zstd outputs valid complete blocks, then exits 1 on the
    # truncated tail. This is expected and tested.
    log "Decompressing and scanning (progress every 10K declarations)..."
    mkdir -p "$BASEDIR/results"
    set +o pipefail
    PYTHON="${BASEDIR}/.venv/bin/python3"
    [ -x "$PYTHON" ] || PYTHON=python3
    zstd -d --long=30 -c "$EXPORT_FILE" 2>/dev/null \
        | "$PYTHON" -I "$BASEDIR/scripts/detectors.py" \
            --checkpoint "$BASEDIR/results/checkpoint.txt" \
            "$BASEDIR/results/chunk-flags.csv"
    set -o pipefail

    log "Done (chunk mode — re-run with --chunk-next to download and scan more)."
    exit 0
fi

# Full mode: download SHA256SUMS and large export files
log "Downloading SHA256SUMS..."
curl -fSL "$BASEURL/SHA256SUMS" -o "$BASEDIR/provenance/SHA256SUMS"
log "SHA256SUMS saved to provenance/SHA256SUMS"

LARGE_FILES=(
    "solution.ndjson.zst"
    "challenge.ndjson.zst"
)

for f in "${LARGE_FILES[@]}"; do
    log "Downloading $f (resume-capable)..."
    for attempt in 1 2 3; do
        if curl -fSL -C - --progress-bar --retry 3 --retry-delay 10 \
                "$BASEURL/$f" -o "$DATADIR/$f"; then
            log "Downloaded $f ($(wc -c < "$DATADIR/$f") bytes)"
            break
        else
            log "Attempt $attempt failed for $f — retrying in 30s..."
            sleep 30
        fi
        if [ "$attempt" -eq 3 ]; then
            log "FAIL: could not download $f after 3 attempts"
            exit 1
        fi
    done
done

# Verify SHA-256 of compressed files against known hashes
log "=== Verifying SHA-256 hashes ==="

verify() {
    local file="$1" expected="$2"
    local actual
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    if [ "$actual" = "$expected" ]; then
        log "PASS $file"
        log "  expected: $expected"
        log "  actual:   $actual"
    else
        log "FAIL $file"
        log "  expected: $expected"
        log "  actual:   $actual"
        exit 1
    fi
}

verify "$DATADIR/solution.ndjson.zst" \
    "61a8938ad5f5e57397c1c0e3b954916af546d9004ade01c3555744a681b05381"

log "=== All compressed-file hashes verified ==="
log ""
log "To extract the first 10,000 lines for quick testing:"
log "  zstd -d --long=30 -c $DATADIR/solution.ndjson.zst | head -n 10000 > $DATADIR/solution-first-10k.ndjson"
log ""
log "To verify the unpacked solution export (after full decompression):"
log "  Expected SHA-256: 5ea74b912147c5c93cc2b6d70cc727cf908df2f62ac6a20480a3fa02f6be244e"
log ""
log "Done."
