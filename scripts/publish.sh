#!/usr/bin/env bash
# Stage a Sopdet release for either the public (assessment) or private (fleet) tier.
#
# Usage:
#   scripts/publish.sh public  [signed-dir]   # all platforms (unsigned) + any public-trust-signed Windows builds
#   scripts/publish.sh private <signed-dir>   # private-trust-signed Windows builds only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tier="${1:-}"
signed_dir="${2:-}"
dest="$ROOT/dist/$tier"

if [ "$tier" != "public" ] && [ "$tier" != "private" ]; then
  echo "usage: $0 public [signed-dir] | private <signed-dir>" >&2
  exit 2
fi

rm -rf "$dest"
mkdir -p "$dest"

if [ "$tier" = "public" ]; then
  shopt -s nullglob
  for f in "$ROOT"/bin/sopdet "$ROOT"/bin/sopdet-linux-* "$ROOT"/bin/sopdet-darwin-* "$ROOT"/bin/sopdet-windows-*.exe; do
    [ -f "$f" ] && cp "$f" "$dest/"
  done
  if [ -n "$signed_dir" ] && [ -d "$signed_dir" ]; then
    for f in "$signed_dir"/*.exe; do [ -f "$f" ] && cp "$f" "$dest/"; done
  fi
else
  if [ -z "$signed_dir" ] || [ ! -d "$signed_dir" ]; then
    echo "private publish requires a signed directory (Private Trust builds)" >&2
    exit 2
  fi
  shopt -s nullglob
  found=0
  for f in "$signed_dir"/*.exe; do [ -f "$f" ] && cp "$f" "$dest/" && found=1; done
  if [ "$found" -eq 0 ]; then
    echo "no signed Windows binaries in $signed_dir" >&2
    exit 2
  fi
fi

cp "$ROOT/schema/inventory.schema.json" "$dest/"
for doc in WHAT-IT-COLLECTS.md README.md; do
  [ -f "$ROOT/$doc" ] && cp "$ROOT/$doc" "$dest/"
done

( cd "$dest" && find . -maxdepth 1 -type f ! -name MANIFEST.sha256 -printf '%P\n' | sort | while read -r name; do
    printf '%s  %s\n' "$(sha256sum "$name" | cut -d' ' -f1)" "$name"
  done > MANIFEST.sha256 )

echo "Staged $dest:"
ls -1 "$dest"
echo
echo "Public tier is safe to publish to a public release URL."
echo "Private tier must go to an authenticated destination (SAS/Entra blob, Intune/SCCM)."
