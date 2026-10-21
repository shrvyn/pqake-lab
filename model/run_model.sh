#!/bin/sh
# Symbolic verification of every model in this directory.
#
#   sh model/run_model.sh
#
# ProVerif 2.05 comes from vendor/proverif2.05/ (Inria binary package, see
# vendor/proverifbin2.05.tar.gz).  Full output per model lands in model/logs/.
set -e

here=$(dirname "$0")
root=$(cd "$here/.." && pwd)
PV="${PROVERIF:-}"
[ -n "$PV" ] || PV="$root/vendor/proverif2.05/proverif.exe"
[ -x "$PV" ] || PV="$root/vendor/proverif2.05/proverif"
[ -x "$PV" ] || { echo "proverif binary not found - set PROVERIF=/path/to/proverif, or unpack vendor/proverifbin2.05.tar.gz"; exit 1; }

mkdir -p "$here/logs"
for f in "$here"/*.pv; do
	name=$(basename "$f" .pv)
	if ! "$PV" "$f" > "$here/logs/$name.log" 2>&1; then
		echo "== $name : PARSE ERROR"
		tail -3 "$here/logs/$name.log"
		continue
	fi
	echo "== $name"
	sed -n 's/^Query \(.*\) is \(.*\)\.$/   \1  ->  \2/p' "$here/logs/$name.log"
done
