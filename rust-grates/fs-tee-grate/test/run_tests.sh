#!/bin/bash

set -ou pipefail

cargo lind_compile

lind_compile --compile-grate -s test/read-simple-grate.c
lind_compile --compile-grate -s test/read-alt-grate.c
lind_compile --compile-grate -s test/read-pass-grate.c

lind_compile -s test/test.c

check_grate() {
    local out="$1"
    local grate="$2"
    local expected="$3"

    if echo "$out" | grep -q "\[grate-${grate}|read_handler\]"; then
        if [ "$expected" = "yes" ]; then
            echo "PASS: grate-${grate} reached"
        else
            echo "FAIL: grate-${grate} reached unexpectedly"
        fi
    else
        if [ "$expected" = "yes" ]; then
            echo "FAIL: grate-${grate} did not reach"
        else
            echo "PASS: grate-${grate} did not reach"
        fi
    fi
}

run_test() {
    local expected="$1"
    shift

    local out
    out="$("$@" 2>&1)"
    echo "$out"

    for grate in simple alt pass; do
        if echo "$expected" | grep -qw "$grate"; then
            check_grate "$out" "$grate" yes
        else
            check_grate "$out" "$grate" no
        fi
    done
}

echo ""
echo "===== Running Tests ====="

echo ""
echo "==== Test 1: Single primary, secondary stacks ===="
run_test "simple alt" lind_run fs-tee-grate.cwasm %{ read-simple-grate.cwasm %} %{ read-alt-grate.cwasm %} test.cwasm
run_test "simple alt" lind_run fs-tee-grate.cwasm %{ read-alt-grate.cwasm %} %{ read-simple-grate.cwasm %} test.cwasm

echo ""
echo "==== Test 2: Single primary, secondary passthrough stacks ===="
run_test "simple pass" lind_run fs-tee-grate.cwasm %{ read-simple-grate.cwasm %} %{ read-pass-grate.cwasm %} test.cwasm
run_test "simple pass" lind_run fs-tee-grate.cwasm %{ read-pass-grate.cwasm %} %{ read-simple-grate.cwasm %} test.cwasm

echo ""
echo "==== Test 3: primary, secondary multi-grate stacks ===="
run_test "simple pass alt" lind_run fs-tee-grate.cwasm %{ read-simple-grate.cwasm read-pass-grate.cwasm %} %{ read-alt-grate.cwasm read-pass-grate.cwasm %} test.cwasm
