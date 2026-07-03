#!/usr/bin/env bash
# copy-file.sh — Copy files from a remote/source directory to local output/ folder.
#
# USAGE:
#   1. Set ROOT to the source directory containing files to copy.
#   2. Add relative paths (from ROOT) to the heredoc list below, one per line.
#   3. Run: bash copy-file.sh
#
# NOTE: This file must NOT contain real server paths, IP addresses, or internal
#       directory structures. Add actual paths only in a local (non-committed) copy.

set -euo pipefail

# Source root directory — change this to your actual source path
ROOT="."

# Destination directory
OUT="output"

# Clean destination before copying
rm -rf "$OUT"
mkdir -p "$OUT"

# ---------------------------------------------------------------------------
# Add the relative file paths you want to copy below (one per line).
# Example:
#   source/path/to/file.php
# ---------------------------------------------------------------------------
cat <<'EOF' | while IFS= read -r relpath; do
# <add relative paths here — one per line>
EOF
    [[ -z "$relpath" || "$relpath" == \#* ]] && continue
    src="$ROOT/$relpath"
    dst="$OUT/$(basename "$relpath")"
    if [[ -f "$src" ]]; then
        cp "$src" "$dst"
        echo "Copied: $relpath -> $dst"
    else
        echo "WARNING: Not found: $src"
    fi
done

echo "Done. Files copied to: $OUT/"
