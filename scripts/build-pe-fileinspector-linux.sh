#!/usr/bin/env bash
set -euo pipefail

CONFIGURATION="${CONFIGURATION:-Release}"
RID="${RID:-linux-x64}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT_DIR/PE-FileInspector/PE-FileInspector.csproj"
OUT_DIR="$ROOT_DIR/artifacts/pe-fileinspector/$RID"

dotnet publish "$PROJECT" \
  -c "$CONFIGURATION" \
  -r "$RID" \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeAllContentForSelfExtract=true \
  -p:PublishTrimmed=false \
  -o "$OUT_DIR"

if [[ -f "$OUT_DIR/PE-FileInspector" && ! -f "$OUT_DIR/PE-FileInspector.exe" ]]; then
  mv "$OUT_DIR/PE-FileInspector" "$OUT_DIR/PE-FileInspector.exe"
fi

echo "Output: $OUT_DIR"
