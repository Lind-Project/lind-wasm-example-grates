#!/usr/bin/env bash
#
# Grate test suite runner.
#
# Reads test/grates_test.toml, builds each grate, compiles each test,
# copies artifacts to lindfs, runs the grate with the test binary, and
# reports results.
#
# Usage:
#   ./test/run_tests.sh                   # run all
#   ./test/run_tests.sh geteuid-grate     # run only this grate
#   ./test/run_tests.sh --list            # list available grates
#
# Requirements:
#   - lind-clang, lind-wasm, lind-compile in PATH (or LIND_WASM_ROOT set)
#   - For Rust grates: the grate compile script at examples/<dir>/compile_grate.sh
#     or Cargo.toml
#
# Environment:
#   LIND_WASM_ROOT  - root of lind-wasm checkout (default: ~/lind-wasm)
#   LINDFS          - lindfs directory (default: $LIND_WASM_ROOT/lindfs)
#   TIMEOUT         - default timeout per test in seconds (default: 30)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG="$SCRIPT_DIR/grates_test.toml"

LIND_WASM_ROOT="${LIND_WASM_ROOT:-$HOME/lind-wasm}"
LINDFS="${LINDFS:-$LIND_WASM_ROOT/lindfs}"
DEFAULT_TIMEOUT="${TIMEOUT:-30}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FILTER="${1:-}"
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

# ── Helpers ──────────────────────────────────────────────────────────

log_pass() { echo -e "  ${GREEN}PASS${NC}: $1"; ((PASSED++)); ((TOTAL++)); }
log_fail() { echo -e "  ${RED}FAIL${NC}: $1"; ((FAILED++)); ((TOTAL++)); }
log_skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; ((SKIPPED++)); }
log_section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

die() { echo -e "${RED}ERROR${NC}: $1" >&2; exit 1; }

# Simple TOML parser — extracts values for the current grate block.
# This is intentionally minimal; it handles the flat structure of our config.

parse_config() {
    local config_file="$1"

    # Reset state
    GRATES=()
    local current_grate=""
    local current_test_idx=-1
    local in_grate=0
    local in_test=0

    # We'll build parallel arrays for grate-level and test-level fields.
    # This is ugly but avoids needing python/jq.
    declare -g -a G_NAMES=() G_DIRS=() G_TYPES=() G_SKIPS=()
    declare -g -a T_GRATE_IDX=() T_SRC=() T_ARGS=() T_FILES=() T_TIMEOUT=() T_SKIPS=()

    local grate_idx=-1

    while IFS= read -r line; do
        # Strip comments and trim
        line="${line%%#*}"
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$line" ]] && continue

        if [[ "$line" == "[[grate]]" ]]; then
            ((grate_idx++))
            G_NAMES[$grate_idx]=""
            G_DIRS[$grate_idx]=""
            G_TYPES[$grate_idx]=""
            G_SKIPS[$grate_idx]="false"
            in_grate=1
            in_test=0
            continue
        fi

        if [[ "$line" == "[[grate.tests]]" ]]; then
            ((current_test_idx++))
            T_GRATE_IDX[$current_test_idx]=$grate_idx
            T_SRC[$current_test_idx]=""
            T_ARGS[$current_test_idx]=""
            T_FILES[$current_test_idx]=""
            T_TIMEOUT[$current_test_idx]="$DEFAULT_TIMEOUT"
            T_SKIPS[$current_test_idx]="false"
            in_test=1
            continue
        fi

        # Parse key = value
        if [[ "$line" =~ ^([a-z_]+)[[:space:]]*=[[:space:]]*(.*) ]]; then
            local key="${BASH_REMATCH[1]}"
            local val="${BASH_REMATCH[2]}"
            # Strip quotes
            val="${val#\"}"
            val="${val%\"}"

            if [[ $in_test -eq 1 ]]; then
                case "$key" in
                    test_src) T_SRC[$current_test_idx]="$val" ;;
                    grate_args) T_ARGS[$current_test_idx]="$val" ;;
                    files) T_FILES[$current_test_idx]="$val" ;;
                    timeout) T_TIMEOUT[$current_test_idx]="$val" ;;
                    skip) T_SKIPS[$current_test_idx]="$val" ;;
                esac
            elif [[ $in_grate -eq 1 ]]; then
                case "$key" in
                    name) G_NAMES[$grate_idx]="$val" ;;
                    dir) G_DIRS[$grate_idx]="$val" ;;
                    type) G_TYPES[$grate_idx]="$val" ;;
                    skip) G_SKIPS[$grate_idx]="$val" ;;
                esac
            fi
        fi
    done < "$config_file"
}

# Parse TOML array values like ["a", "b"] into a bash array
parse_toml_array() {
    local raw="$1"
    raw="${raw#\[}"
    raw="${raw%\]}"
    # Split on comma, strip quotes and whitespace
    echo "$raw" | tr ',' '\n' | sed 's/^[[:space:]]*"//;s/"[[:space:]]*$//'
}

# ── Build functions ──────────────────────────────────────────────────

build_c_grate() {
    local dir="$1"
    local grate_dir="$REPO_ROOT/examples/$dir"

    if [[ -f "$grate_dir/compile_grate.sh" ]]; then
        echo "  Building C grate: $dir"
        (cd "$grate_dir" && bash compile_grate.sh) 2>&1 | sed 's/^/    /'
    else
        die "No compile_grate.sh found in $grate_dir"
    fi
}

build_rust_grate() {
    local dir="$1"
    local grate_dir="$REPO_ROOT/examples/$dir"

    if [[ -f "$grate_dir/compile_grate.sh" ]]; then
        echo "  Building Rust grate: $dir"
        (cd "$grate_dir" && bash compile_grate.sh) 2>&1 | sed 's/^/    /'
    elif [[ -f "$grate_dir/Cargo.toml" ]]; then
        echo "  Building Rust grate: $dir (cargo)"
        (cd "$grate_dir" && cargo build --target wasm32-wasip1) 2>&1 | sed 's/^/    /'
    else
        die "No compile_grate.sh or Cargo.toml in $grate_dir"
    fi
}

compile_test() {
    local test_src="$1"
    echo "  Compiling test: $(basename "$test_src")"
    lind-clang "$test_src" 2>&1 | sed 's/^/    /'
}

# Find the .cwasm for a grate
find_grate_cwasm() {
    local dir="$1"
    local name="$2"
    local grate_dir="$REPO_ROOT/examples/$dir"

    # Check common locations
    for candidate in \
        "$LINDFS/$name.cwasm" \
        "$grate_dir/output/$name.cwasm" \
        "$grate_dir/target/wasm32-wasip1/debug/$name.cwasm" \
        "$grate_dir/target/wasm32-wasip1/release/$name.cwasm"; do
        if [[ -f "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    # Search lindfs for anything matching
    find "$LINDFS" -name "*.cwasm" -name "*${dir}*" 2>/dev/null | head -1
}

# ── Run a single test ────────────────────────────────────────────────

run_test() {
    local grate_name="$1"
    local grate_cwasm="$2"
    local test_cwasm="$3"
    local grate_args="$4"
    local timeout_sec="$5"
    local test_label="$6"

    local cmd="lind-wasm $(basename "$grate_cwasm")"
    if [[ -n "$grate_args" ]]; then
        cmd="$cmd $grate_args"
    fi
    cmd="$cmd $(basename "$test_cwasm")"

    echo "  Running: $cmd (timeout=${timeout_sec}s)"

    local exit_code=0
    timeout "$timeout_sec" lind-wasm "$(basename "$grate_cwasm")" \
        $grate_args \
        "$(basename "$test_cwasm")" \
        2>&1 | sed 's/^/    /' || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "$test_label"
    elif [[ $exit_code -eq 124 || $exit_code -eq 137 ]]; then
        log_fail "$test_label (TIMEOUT after ${timeout_sec}s)"
    else
        log_fail "$test_label (exit code $exit_code)"
    fi
}

# ── List mode ────────────────────────────────────────────────────────

if [[ "$FILTER" == "--list" ]]; then
    parse_config "$CONFIG"
    echo "Available grates:"
    for i in "${!G_NAMES[@]}"; do
        local skip=""
        [[ "${G_SKIPS[$i]}" == "true" ]] && skip=" (skip)"
        echo "  ${G_NAMES[$i]} [${G_TYPES[$i]}]${skip}"
    done
    exit 0
fi

# ── Main ─────────────────────────────────────────────────────────────

echo -e "${CYAN}=== Grate Test Suite ===${NC}"
echo "Config: $CONFIG"
echo "LindFS: $LINDFS"
echo ""

parse_config "$CONFIG"

for gi in "${!G_NAMES[@]}"; do
    gname="${G_NAMES[$gi]}"
    gdir="${G_DIRS[$gi]}"
    gtype="${G_TYPES[$gi]}"
    gskip="${G_SKIPS[$gi]}"

    # Filter
    if [[ -n "$FILTER" && "$FILTER" != "$gname" && "$FILTER" != "$gdir" ]]; then
        continue
    fi

    log_section "$gname ($gtype)"

    if [[ "$gskip" == "true" ]]; then
        log_skip "$gname (configured to skip)"
        continue
    fi

    # Check directory exists
    if [[ ! -d "$REPO_ROOT/examples/$gdir" ]]; then
        log_skip "$gname (directory examples/$gdir not found)"
        continue
    fi

    # Build grate
    case "$gtype" in
        c)    build_c_grate "$gdir" || { log_fail "$gname build"; continue; } ;;
        rust) build_rust_grate "$gdir" || { log_fail "$gname build"; continue; } ;;
        *)    log_skip "$gname (unknown type: $gtype)"; continue ;;
    esac

    # Find tests for this grate
    has_tests=0
    for ti in "${!T_GRATE_IDX[@]}"; do
        [[ "${T_GRATE_IDX[$ti]}" != "$gi" ]] && continue
        has_tests=1

        tsrc="${T_SRC[$ti]}"
        targs="${T_ARGS[$ti]}"
        tfiles="${T_FILES[$ti]}"
        ttimeout="${T_TIMEOUT[$ti]}"
        tskip="${T_SKIPS[$ti]}"

        test_label="$gname / $(basename "$tsrc")"

        if [[ "$tskip" == "true" ]]; then
            log_skip "$test_label"
            continue
        fi

        test_src_path="$REPO_ROOT/examples/$gdir/$tsrc"
        if [[ ! -f "$test_src_path" ]]; then
            log_fail "$test_label (source not found: $tsrc)"
            continue
        fi

        # Compile test
        compile_test "$test_src_path" || { log_fail "$test_label (compile)"; continue; }

        # Copy extra files to lindfs
        if [[ -n "$tfiles" ]]; then
            while IFS= read -r f; do
                [[ -z "$f" ]] && continue
                src="$REPO_ROOT/examples/$gdir/$f"
                if [[ -f "$src" ]]; then
                    cp "$src" "$LINDFS/"
                    echo "  Copied $f to lindfs"
                fi
            done <<< "$(parse_toml_array "$tfiles")"
        fi

        # Parse grate_args
        local run_args=""
        if [[ -n "$targs" ]]; then
            run_args="$(parse_toml_array "$targs" | tr '\n' ' ')"
        fi

        # Find grate cwasm
        grate_cwasm="$(find_grate_cwasm "$gdir" "$gname")"
        if [[ -z "$grate_cwasm" ]]; then
            log_fail "$test_label (grate .cwasm not found)"
            continue
        fi

        # Find test cwasm
        test_basename="$(basename "$tsrc" .c)"
        test_cwasm="$LINDFS/${test_basename}.cwasm"
        if [[ ! -f "$test_cwasm" ]]; then
            # Try finding it
            test_cwasm="$(find "$LINDFS" -name "${test_basename}.cwasm" 2>/dev/null | head -1)"
        fi
        if [[ -z "$test_cwasm" || ! -f "$test_cwasm" ]]; then
            log_fail "$test_label (test .cwasm not found)"
            continue
        fi

        run_test "$gname" "$grate_cwasm" "$test_cwasm" "$run_args" "$ttimeout" "$test_label"
    done

    if [[ $has_tests -eq 0 ]]; then
        log_skip "$gname (no tests configured)"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}=== Results ===${NC}"
echo -e "  Total:   $TOTAL"
echo -e "  ${GREEN}Passed:  $PASSED${NC}"
echo -e "  ${RED}Failed:  $FAILED${NC}"
echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"

[[ $FAILED -eq 0 ]] && exit 0 || exit 1
