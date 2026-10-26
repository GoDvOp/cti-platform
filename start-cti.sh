#!/bin/sh
# Run from any directory; no host Python installation is needed.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export CTI_STOP_DESKTOP=1
if [ "$#" -eq 0 ]; then
  set -- up
fi
exec sh scripts/docker.sh "$@"
