#!/usr/bin/env bash
#
# Run the write filter ordering demo.
# Shows how composition order changes observable behavior.
# Run build.sh first.

set -euo pipefail

echo "============================================================"
echo "  Ordering A: strace ABOVE write-filter"
echo "  strace sees ALL writes, including denied ones"
echo "============================================================"
echo ""

lind-wasm grates/strace-grate.cwasm \
  grates/write-filter-grate.cwasm \
  write_filter_ordering_test.cwasm

echo ""
echo "============================================================"
echo "  Ordering B: write-filter ABOVE strace"
echo "  strace sees ONLY permitted writes"
echo "============================================================"
echo ""

lind-wasm grates/write-filter-grate.cwasm \
  grates/strace-grate.cwasm \
  write_filter_ordering_test.cwasm

echo ""
echo "============================================================"
echo "  Compare the strace output between orderings."
echo "  In A, write(data.db) appears in the trace (then denied)."
echo "  In B, write(data.db) never reaches strace."
echo "============================================================"
