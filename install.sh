#!/usr/bin/env bash
# Install pretest to ~/.local/bin (or $1). Needs curl and python3.
set -euo pipefail

dest="${1:-$HOME/.local/bin}"
base="https://github.com/alexwest1981/pretest/releases/latest/download"
mkdir -p "$dest"

curl -fsSL "$base/pretest.py" -o "$dest/pretest"
curl -fsSL "$base/pretest.py.sha256" -o /tmp/pretest.sha256 2>/dev/null || true
if [ -s /tmp/pretest.sha256 ]; then
  ( cd "$dest" && sha256sum -c /tmp/pretest.sha256 ) || { echo "checksum mismatch, aborting" >&2; exit 1; }
fi
chmod +x "$dest/pretest"
echo "installed: $dest/pretest"

command -v python3 >/dev/null || { echo "warning: python3 (3.10+) is required" >&2; exit 1; }
case ":$PATH:" in *":$dest:"*) ;; *) echo "note: add $dest to PATH" ;; esac
