#!/usr/bin/env bash
# Copies the generated PiRectory Connect clients into internal/directory/gen.
#
# PiRectory's protos are not published to the Buf Schema Registry and the
# module path go.pilab.hu/cloud/pirectory does not resolve over the network,
# so the adapter carries its generated clients in-tree. The protos stay
# single-sourced in the PiRectory repository; this script only mirrors the
# output of `make generate` there.
#
# The rewrite is limited to the import block. The same path also appears
# inside each file's serialized descriptor (the file's go_package option),
# and rewriting it there would change the byte length without fixing the
# length prefix in front of it — which corrupts the descriptor and panics
# the protobuf runtime on init.
#
# Usage: hack/gen-directory-protos.sh [path-to-pirectory]
#   PIRECTORY_ROOT overrides the location when it is not ../../pirectory.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${1:-${PIRECTORY_ROOT:-$root/../../pirectory}}"
src="$(cd "$src" && pwd)"

pkg="github.com/pilab-dev/shadow-sso/internal/directory/gen"
from="go.pilab.hu/cloud/pirectory/gen"

files=(
  pirectory/accounts/v1/accounts.pb.go
  pirectory/accounts/v1/schema.pb.go
  pirectory/accounts/v1/watch.pb.go
  pirectory/accounts/v1/accountsv1connect/accounts.connect.go
  pirectory/credentials/v1/credentials.pb.go
  pirectory/credentials/v1/credentialsv1connect/credentials.connect.go
  pirectory/common/v1/common.pb.go
  pirectory/options/v1/options.pb.go
)

# strip_imports prints everything but the import block.
strip_imports() {
  awk 'BEGIN { inimp = 0 }
       /^import \($/ { inimp = 1; next }
       inimp && /^\)$/ { inimp = 0; next }
       !inimp { print }' "$1"
}

# import_block prints the import block, or nothing when the file has none.
import_block() {
  awk 'BEGIN { inimp = 0 }
       /^import \($/ { inimp = 1 }
       inimp { print }
       inimp && /^\)$/ { exit }' "$1"
}

rewrite_imports() { # <from> <to> <input> <output>
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys

src, dst, inp, out = sys.argv[1:5]
inside = False
with open(inp, "r", encoding="utf-8") as fh, open(out, "w", encoding="utf-8") as dst_fh:
    for line in fh:
        stripped = line.rstrip("\n")
        if stripped == "import (":
            inside = True
        elif inside and stripped == ")":
            inside = False
        if inside:
            line = line.replace(src, dst)
        dst_fh.write(line)
PY
}

for f in "${files[@]}"; do
  in="$src/gen/$f"
  out="$root/internal/directory/gen/$f"
  if [[ ! -f "$in" ]]; then
    echo "missing $in (run 'make generate' in $src)" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$out")"
  rewrite_imports "$from" "$pkg" "$in" "$out"

  # Everything outside the import block must be byte-identical to the source,
  # or the descriptor this file ships is not the one PiRectory generated. And
  # no import may still point at the PiRectory module.
  if ! diff -q <(strip_imports "$in") <(strip_imports "$out") >/dev/null; then
    echo "$f: rewrite touched more than the import block" >&2
    rm -f "$out"
    exit 1
  fi
  if grep -q "$from" <(import_block "$out"); then
    echo "$f: an import still points at $from" >&2
    rm -f "$out"
    exit 1
  fi
  echo "wrote ${out#"$root/"}"
done
