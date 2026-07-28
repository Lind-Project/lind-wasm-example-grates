#!/usr/bin/env bash

set -euo pipefail

git diff --name-only --no-renames "${1:-origin/main}...${2:-HEAD}" |
    awk -F/ '$1 == "c-grates" && NF > 2 { print "c/" $2 }
             $1 == "rust-grates" && NF > 2 { print "rust/" $2 }' |
    sort -u
