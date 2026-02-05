#!/usr/bin/env bash
set -euo pipefail

CONFIGURATION="${CONFIGURATION:-Release}"
RID="${RID:-linux-x64}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT_DIR/PE-Inspector/PE-Inspector.csproj"
OUT_DIR="$ROOT_DIR/artifacts/pe-inspector/$RID"

dotnet publish "$PROJECT" \
  -c "$CONFIGURATION" \
  -r "$RID" \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeAllContentForSelfExtract=true \
  -p:PublishTrimmed=false \
  -o "$OUT_DIR"

if [[ -f "$OUT_DIR/PE-Inspector" && ! -f "$OUT_DIR/PE-Inspector.exe" ]]; then
  mv "$OUT_DIR/PE-Inspector" "$OUT_DIR/PE-Inspector.exe"
fi

echo "Output: $OUT_DIR"
