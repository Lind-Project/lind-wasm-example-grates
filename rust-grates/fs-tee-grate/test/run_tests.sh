#!/bin/bash

set -eou pipefail

lind_compile -s test/exerciser.c

lind-wasm grates/fs-tee-grate.cwasm %{ grates/imfs-grate.cwasm %} exerciser.cwasm
