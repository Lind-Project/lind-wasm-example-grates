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
# Environment:
#   LIND_WASM_ROOT  - root of lind-wasm checkout (default: ~/lind-wasm)
#   LINDFS          - lindfs directory (default: $LIND_WASM_ROOT/lindfs)
#   TIMEOUT         - default timeout per test in seconds (default: 30)

set -uo pipefail

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

log_pass()    { echo -e "  ${GREEN}PASS${NC}: $1"; PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); }
log_fail()    { echo -e "  ${RED}FAIL${NC}: $1"; FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); }
log_skip()    { echo -e "  ${YELLOW}SKIP${NC}: $1"; SKIPPED=$((SKIPPED+1)); }
log_section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

# ── TOML parser ──────────────────────────────────────────────────────
# Builds parallel arrays for grate-level and test-level fields.

G_NAMES=()
G_DIRS=()
G_TYPES=()
G_SKIPS=()

T_GRATE_IDX=()
T_SRC=()
T_ARGS=()
T_FILES=()
T_TIMEOUT=()
T_SKIPS=()

parse_config() {
    local config_file="$1"
    local grate_idx=-1
    local test_idx=-1
    local in_grate=0
    local in_test=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip comments (;  and #) and trim whitespace
        line="${line%%#*}"
        line="${line%%;;*}"
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$line" ]] && continue

        if [[ "$line" == "[[grate]]" ]]; then
            grate_idx=$((grate_idx + 1))
            G_NAMES+=("")
            G_DIRS+=("")
            G_TYPES+=("")
            G_SKIPS+=("false")
            in_grate=1
            in_test=0
            continue
        fi

        if [[ "$line" == "[[grate.tests]]" ]]; then
            test_idx=$((test_idx + 1))
            T_GRATE_IDX+=("$grate_idx")
            T_SRC+=("")
            T_ARGS+=("")
            T_FILES+=("")
            T_TIMEOUT+=("$DEFAULT_TIMEOUT")
            T_SKIPS+=("false")
            in_test=1
            continue
        fi

        # Parse key = value
        if [[ "$line" =~ ^([a-z_]+)[[:space:]]*=[[:space:]]*(.*) ]]; then
            local key="${BASH_REMATCH[1]}"
            local val="${BASH_REMATCH[2]}"
            # Strip surrounding quotes
            val="${val#\"}"
            val="${val%\"}"

            if [[ $in_test -eq 1 && $test_idx -ge 0 ]]; then
                case "$key" in
                    test_src)    T_SRC[$test_idx]="$val" ;;
                    grate_args)  T_ARGS[$test_idx]="$val" ;;
                    files)       T_FILES[$test_idx]="$val" ;;
                    timeout)     T_TIMEOUT[$test_idx]="$val" ;;
                    skip)        T_SKIPS[$test_idx]="$val" ;;
                esac
            elif [[ $in_grate -eq 1 && $grate_idx -ge 0 ]]; then
                case "$key" in
                    name) G_NAMES[$grate_idx]="$val" ;;
                    dir)  G_DIRS[$grate_idx]="$val" ;;
                    type) G_TYPES[$grate_idx]="$val" ;;
                    skip) G_SKIPS[$grate_idx]="$val" ;;
                esac
            fi
        fi
    done < "$config_file"
}

# Parse TOML array values like ["a", "b"] into lines
parse_toml_array() {
    local raw="$1"
    raw="${raw#\[}"
    raw="${raw%\]}"
    echo "$raw" | tr ',' '\n' | sed 's/^[[:space:]]*"//;s/"[[:space:]]*$//' | grep -v '^$'
}

# ── Build functions ──────────────────────────────────────────────────

build_c_grate() {
    local dir="$1"
    local grate_dir="$REPO_ROOT/examples/$dir"

    if [[ -f "$grate_dir/compile_grate.sh" ]]; then
        echo "  Building C grate: $dir"
        if ! (cd "$grate_dir" && bash compile_grate.sh) 2>&1 | sed 's/^/    /'; then
            return 1
        fi
    else
        echo "  ERROR: No compile_grate.sh found in $grate_dir"
        return 1
    fi
}

build_rust_grate() {
    local dir="$1"
    local grate_dir="$REPO_ROOT/examples/$dir"

    if [[ -f "$grate_dir/compile_grate.sh" ]]; then
        echo "  Building Rust grate: $dir"
        if ! (cd "$grate_dir" && bash compile_grate.sh) 2>&1 | sed 's/^/    /'; then
            return 1
        fi
    elif [[ -f "$grate_dir/Cargo.toml" ]]; then
        echo "  Building Rust grate: $dir (cargo lind_compile)"
        if ! (cd "$grate_dir" && cargo lind_compile) 2>&1 | sed 's/^/    /'; then
            return 1
        fi
    else
        echo "  ERROR: No compile_grate.sh or Cargo.toml in $grate_dir"
        return 1
    fi
}

compile_test() {
    local test_src="$1"
    echo "  Compiling test: $(basename "$test_src")"
    if ! lind-clang "$test_src" 2>&1 | sed 's/^/    /'; then
        return 1
    fi
}

# ── List mode ────────────────────────────────────────────────────────

if [[ "$FILTER" == "--list" ]]; then
    parse_config "$CONFIG"
    echo "Available grates:"
    for i in "${!G_NAMES[@]}"; do
        skip_note=""
        [[ "${G_SKIPS[$i]}" == "true" ]] && skip_note=" (skip)"
        echo "  ${G_NAMES[$i]} [${G_TYPES[$i]}]${skip_note}"
    done
    exit 0
fi

# ── Main ─────────────────────────────────────────────────────────────

echo -e "${CYAN}=== Grate Test Suite ===${NC}"
echo "Config: $CONFIG"
echo "LindFS: $LINDFS"

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
    build_ok=1
    case "$gtype" in
        c)    build_c_grate "$gdir" || build_ok=0 ;;
        rust) build_rust_grate "$gdir" || build_ok=0 ;;
        *)    log_skip "$gname (unknown type: $gtype)"; continue ;;
    esac

    if [[ $build_ok -eq 0 ]]; then
        log_fail "$gname (build failed)"
        continue
    fi

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
        if ! compile_test "$test_src_path"; then
            log_fail "$test_label (compile failed)"
            continue
        fi

        # Copy extra files to lindfs
        if [[ -n "$tfiles" ]]; then
            while IFS= read -r f; do
                [[ -z "$f" ]] && continue
                src="$REPO_ROOT/examples/$gdir/$f"
                if [[ -f "$src" ]]; then
                    cp "$src" "$LINDFS/"
                    echo "  Copied $(basename "$f") to lindfs"
                fi
            done <<< "$(parse_toml_array "$tfiles")"
        fi

        # Parse grate_args
        run_args=""
        if [[ -n "$targs" ]]; then
            run_args="$(parse_toml_array "$targs" | tr '\n' ' ')"
        fi

        # Find grate cwasm — check lindfs first, then search the grate dir
        grate_cwasm=""
        for candidate in \
            "$LINDFS/${gname}.cwasm" \
            "$LINDFS/"*"${gdir}"*.cwasm \
            $(find "$REPO_ROOT/examples/$gdir" -name "*.cwasm" 2>/dev/null); do
            if [[ -f "$candidate" ]]; then
                grate_cwasm="$candidate"
                break
            fi
        done

        if [[ -z "$grate_cwasm" || ! -f "$grate_cwasm" ]]; then
            log_fail "$test_label (grate .cwasm not found)"
            continue
        fi

        # Copy grate cwasm to lindfs if not already there
        if [[ "$(dirname "$grate_cwasm")" != "$LINDFS" ]]; then
            cp "$grate_cwasm" "$LINDFS/"
            grate_cwasm="$LINDFS/$(basename "$grate_cwasm")"
        fi

        # Find test cwasm — check lindfs, then search near the source
        test_basename="$(basename "$tsrc" .c)"
        test_cwasm=""
        for candidate in \
            "$LINDFS/${test_basename}.cwasm" \
            $(find "$(dirname "$test_src_path")" -name "${test_basename}.cwasm" 2>/dev/null); do
            if [[ -f "$candidate" ]]; then
                test_cwasm="$candidate"
                break
            fi
        done

        if [[ -z "$test_cwasm" || ! -f "$test_cwasm" ]]; then
            log_fail "$test_label (test .cwasm not found)"
            continue
        fi

        # Copy test cwasm to lindfs if not already there
        if [[ "$(dirname "$test_cwasm")" != "$LINDFS" ]]; then
            cp "$test_cwasm" "$LINDFS/"
            test_cwasm="$LINDFS/$(basename "$test_cwasm")"
        fi

        # Run
        cmd="lind-wasm $(basename "$grate_cwasm") ${run_args}$(basename "$test_cwasm")"
        echo "  Running: $cmd (timeout=${ttimeout}s)"

        exit_code=0
        timeout "$ttimeout" lind-wasm "$(basename "$grate_cwasm")" \
            $run_args \
            "$(basename "$test_cwasm")" \
            2>&1 | sed 's/^/    /' || exit_code=$?

        if [[ $exit_code -eq 0 ]]; then
            log_pass "$test_label"
        elif [[ $exit_code -eq 124 || $exit_code -eq 137 ]]; then
            log_fail "$test_label (TIMEOUT after ${ttimeout}s)"
        else
            log_fail "$test_label (exit code $exit_code)"
        fi
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
