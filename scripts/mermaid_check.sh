#!/bin/bash
# Refuses two Mermaid mistakes that GitHub and the docs site cannot draw.
# No build step parses Mermaid, so this is the only gate.
#
# - A ';' in the text of a sequenceDiagram. There ';' ends the statement
#   like a newline and cuts the message in two. An entity code such as
#   '#59;' is allowed.
# - A '(' in an unquoted flowchart node label, as in X{f(x)?}. Mermaid
#   reads it as the start of a shape. Quote the label: X{"f(x)?"}. A
#   shape such as A[(db)] is allowed.
#
# Each hit is named as file:line. No git, no network.
#
#   scripts/mermaid_check.sh            all .md files in the tree
#   scripts/mermaid_check.sh PATH...    only these files and directories
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ $# -eq 0 ]]; then
  cd "${root}"
  set -- .
fi

hits=0
while IFS= read -r -d '' f; do
  out="$(awk '
    /^[ \t]*```mermaid/ { m = 1; kind = ""; next }
    m && /^[ \t]*```/   { m = 0; next }
    m && kind == "" && NF { kind = $1 }
    m && kind == "sequenceDiagram" {
      line = $0
      gsub(/#[0-9A-Za-z]+;/, "", line)
      f = FILENAME; sub(/^\.\//, "", f)
      if (index(line, ";")) print f ":" FNR ": ; in a sequenceDiagram ends the statement; use , or #59;"
    }
    m && kind ~ /^(flowchart|graph)$/ {
      line = $0
      gsub(/"[^"]*"/, "", line)
      f = FILENAME; sub(/^\.\//, "", f)
      if (line ~ /[[{][^][{}()]+\(/) print f ":" FNR ": ( in an unquoted node label opens a shape; quote the label"
    }
  ' "${f}")"
  if [[ -n "${out}" ]]; then
    echo "${out}" >&2
    hits=1
  fi
done < <(find "$@" \( -name .git -o -name .vagrant -o -name build -o -name dist -o -name node_modules \) -prune -o -type f -name '*.md' -print0)

if [[ "${hits}" -ne 0 ]]; then
  echo "mermaid_check: fix the lines above" >&2
  exit 1
fi
echo "mermaid_check: clean"
