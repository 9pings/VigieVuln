#!/usr/bin/env bash
# Regenerate docs/assets/demo.gif — the animated terminal demo.
#
# Pipeline:  script(1) in a real PTY  ->  asciicast v2  ->  agg  ->  GIF
#   (VHS was the previous route; its bundled headless Chrome captures zero frames
#    under WSL, exiting 0 with an empty temp dir. This path has no browser.)
#
# Requires: util-linux `script`, `agg` (https://github.com/asciinema/agg),
#           JetBrains Mono installed, and a warm ~/.vigie-vuln cache.
# Set DEMO_CACHE_DIR to reuse a specific local snapshot without changing settings.
#
# The run is --offline on purpose: deterministic (no network timing in the
# recording) and it is the headline capability — a full audit, zero packets.
# The fixture is the one carrying unresolvable/private coordinates, so the
# "Maven POM analysis" block shows the dependencies VigieVuln could NOT reach — the
# failure mode that otherwise reads as a clean scan.
#
# Geometry: 120x54 at font 13 / line-height 1.185 stays below the previous
# 952x940 asset. Steps share a row; the final findings remain readable.
# Pass --warm to refresh the cache online before recording; otherwise use it as-is.
set -euo pipefail
cd "$(dirname "$0")/.."

FIXTURE=test/fixtures/private-lib-detection
OUT=docs/assets/demo.gif
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
CACHE_ARGS=()
if [[ -n "${DEMO_CACHE_DIR:-}" ]]; then
  export VIGIEVULN_DEMO_CACHE_MODULE="$PWD/lib/cache-directory.js"
  printf '%s\n' 'require(process.env.VIGIEVULN_DEMO_CACHE_MODULE).setActiveCacheDir(process.env.DEMO_CACHE_DIR);' > "$TMP/cache.cjs"
  CACHE_ARGS=(--require "$TMP/cache.cjs")
fi

# 0. optionally warm the cache online before recording
if [[ "${1:-}" == "--warm" ]]; then
  node "${CACHE_ARGS[@]}" vigievuln.js -s "$FIXTURE" --no-report >/dev/null
fi

# 1. capture real CLI output in a PTY, preserving ANSI colour
printf -v RUN '%q ' node --disable-warning=ExperimentalWarning "${CACHE_ARGS[@]}" vigievuln.js -s "$FIXTURE" --offline --no-report
TERM=xterm-256color script -q -e \
  --log-out "$TMP/raw" \
  -c "stty cols 120 rows 54; $RUN" >/dev/null

# 2. -> asciicast v2 (adds the typed prompt line and the Tokyo Night palette)
node scripts/asciicast-from-script.js "$TMP/raw" "$TMP/demo.cast" 120 54

# 3. -> GIF
"${AGG:-agg}" --font-size 13 --line-height 1.185 --fps-cap 8 \
    --last-frame-duration 5 --idle-time-limit 1 "$TMP/demo.cast" "$OUT"

echo "wrote $OUT ($(identify -format '%wx%h' "$OUT[0]" 2>/dev/null || echo '?'), $(( $(stat -c%s "$OUT") / 1024 )) KB)"

# The still screenshot is the actual final terminal frame of this recording.
if command -v convert >/dev/null; then
  convert "$OUT" -coalesce -delete 0--2 docs/assets/cli.png
fi
