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
DEFAULT_TIMEOUT="${TIMEOUT:-60}"

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
        if ! (cd "$grate_dir" && bash compile_grate.sh) > /dev/null 2>&1; then
            echo "    Build failed. Re-running with output:"
            (cd "$grate_dir" && bash compile_grate.sh) 2>&1 | sed 's/^/    /'
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
        if ! (cd "$grate_dir" && bash compile_grate.sh) > /dev/null 2>&1; then
            echo "    Build failed. Re-running with output:"
            (cd "$grate_dir" && bash compile_grate.sh) 2>&1 | sed 's/^/    /'
            return 1
        fi
    elif [[ -f "$grate_dir/Cargo.toml" ]]; then
        echo "  Building Rust grate: $dir (cargo lind_compile)"
        if ! (cd "$grate_dir" && cargo lind_compile) > /dev/null 2>&1; then
            echo "    Build failed. Re-running with output:"
            (cd "$grate_dir" && cargo lind_compile) 2>&1 | sed 's/^/    /'
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
    if ! lind-clang "$test_src" > /dev/null 2>&1; then
        echo "    Compile failed. Re-running with output:"
        lind-clang "$test_src" 2>&1 | sed 's/^/    /'
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

# Track which grates built successfully (by index)
BUILD_OK=()

# ── Phase 1: Build all grates and compile all tests ──────────────────

echo -e "\n${CYAN}── Phase 1: Build ──${NC}"

for gi in "${!G_NAMES[@]}"; do
    gname="${G_NAMES[$gi]}"
    gdir="${G_DIRS[$gi]}"
    gtype="${G_TYPES[$gi]}"
    gskip="${G_SKIPS[$gi]}"
    BUILD_OK[$gi]=0

    if [[ -n "$FILTER" && "$FILTER" != "$gname" && "$FILTER" != "$gdir" ]]; then
        continue
    fi

    if [[ "$gskip" == "true" ]]; then
        continue
    fi

    if [[ ! -d "$REPO_ROOT/examples/$gdir" ]]; then
        continue
    fi

    # Build grate
    case "$gtype" in
        c)    build_c_grate "$gdir" || { echo -e "  ${RED}FAILED${NC}"; continue; } ;;
        rust) build_rust_grate "$gdir" || { echo -e "  ${RED}FAILED${NC}"; continue; } ;;
        *)    continue ;;
    esac

    # Copy grate cwasm to lindfs
    grate_cwasm="$(find "$REPO_ROOT/examples/$gdir" -name "*.cwasm" 2>/dev/null | head -1)"
    if [[ -n "$grate_cwasm" && -f "$grate_cwasm" ]]; then
        cp "$grate_cwasm" "$LINDFS/"
    fi

    # Compile all tests for this grate
    test_build_ok=1
    for ti in "${!T_GRATE_IDX[@]}"; do
        [[ "${T_GRATE_IDX[$ti]}" != "$gi" ]] && continue
        [[ "${T_SKIPS[$ti]}" == "true" ]] && continue

        tsrc="${T_SRC[$ti]}"
        test_src_path="$REPO_ROOT/examples/$gdir/$tsrc"

        if [[ ! -f "$test_src_path" ]]; then
            echo -e "  ${RED}Test source not found: $tsrc${NC}"
            test_build_ok=0
            continue
        fi

        if ! compile_test "$test_src_path"; then
            test_build_ok=0
            continue
        fi

        # Copy test cwasm to lindfs
        test_basename="$(basename "$tsrc" .c)"
        test_cwasm="$(find "$(dirname "$test_src_path")" -name "${test_basename}.cwasm" 2>/dev/null | head -1)"
        if [[ -n "$test_cwasm" && -f "$test_cwasm" ]]; then
            cp "$test_cwasm" "$LINDFS/"
        fi

        # Copy extra files to lindfs
        tfiles="${T_FILES[$ti]}"
        if [[ -n "$tfiles" ]]; then
            while IFS= read -r f; do
                [[ -z "$f" ]] && continue
                src="$REPO_ROOT/examples/$gdir/$f"
                if [[ -f "$src" ]]; then
                    cp "$src" "$LINDFS/"
                fi
            done <<< "$(parse_toml_array "$tfiles")"
        fi
    done

    if [[ $test_build_ok -eq 1 ]]; then
        BUILD_OK[$gi]=1
    fi
done

# ── Phase 2: Run all tests ───────────────────────────────────────────

echo -e "\n${CYAN}── Phase 2: Run ──${NC}"

for gi in "${!G_NAMES[@]}"; do
    gname="${G_NAMES[$gi]}"
    gdir="${G_DIRS[$gi]}"
    gtype="${G_TYPES[$gi]}"
    gskip="${G_SKIPS[$gi]}"

    if [[ -n "$FILTER" && "$FILTER" != "$gname" && "$FILTER" != "$gdir" ]]; then
        continue
    fi

    log_section "$gname"

    if [[ "$gskip" == "true" ]]; then
        log_skip "$gname (configured to skip)"
        continue
    fi

    if [[ ! -d "$REPO_ROOT/examples/$gdir" ]]; then
        log_skip "$gname (directory not found)"
        continue
    fi

    if [[ "${BUILD_OK[$gi]}" != "1" ]]; then
        log_fail "$gname (build failed)"
        continue
    fi

    # Find grate cwasm in lindfs
    grate_cwasm=""
    for candidate in "$LINDFS/${gname}.cwasm" "$LINDFS/"*"${gdir}"*.cwasm; do
        if [[ -f "$candidate" ]]; then
            grate_cwasm="$candidate"
            break
        fi
    done

    if [[ -z "$grate_cwasm" || ! -f "$grate_cwasm" ]]; then
        log_fail "$gname (grate .cwasm not found in lindfs)"
        continue
    fi

    has_tests=0
    for ti in "${!T_GRATE_IDX[@]}"; do
        [[ "${T_GRATE_IDX[$ti]}" != "$gi" ]] && continue
        has_tests=1

        tsrc="${T_SRC[$ti]}"
        targs="${T_ARGS[$ti]}"
        ttimeout="${T_TIMEOUT[$ti]}"
        tskip="${T_SKIPS[$ti]}"

        test_label="$gname / $(basename "$tsrc")"

        if [[ "$tskip" == "true" ]]; then
            log_skip "$test_label"
            continue
        fi

        # Find test cwasm in lindfs
        test_basename="$(basename "$tsrc" .c)"
        test_cwasm="$LINDFS/${test_basename}.cwasm"
        if [[ ! -f "$test_cwasm" ]]; then
            log_fail "$test_label (test .cwasm not found in lindfs)"
            continue
        fi

        # Parse grate_args
        run_args=""
        if [[ -n "$targs" ]]; then
            run_args="$(parse_toml_array "$targs" | tr '\n' ' ')"
        fi

        # Run — pipe output through a monitor that kills the process on panic
        cmd="lind-wasm $(basename "$grate_cwasm") ${run_args}$(basename "$test_cwasm")"
        echo "  Running: $cmd (timeout=${ttimeout}s)"

        exit_code=0
        tmp_out=$(mktemp)

        timeout "$ttimeout" lind-wasm "$(basename "$grate_cwasm")" \
            $run_args \
            "$(basename "$test_cwasm")" \
            > "$tmp_out" 2>&1 &
        run_pid=$!

        # Monitor output for panics — kill immediately if detected
        panicked=0
        while kill -0 "$run_pid" 2>/dev/null; do
            if grep -q "panicked" "$tmp_out" 2>/dev/null; then
                kill "$run_pid" 2>/dev/null
                wait "$run_pid" 2>/dev/null || true
                panicked=1
                break
            fi
            sleep 0.1
        done

        if [[ $panicked -eq 0 ]]; then
            wait "$run_pid" 2>/dev/null || exit_code=$?
        fi

        # Show output (indented)
        sed 's/^/    /' < "$tmp_out"
        rm -f "$tmp_out"

        if [[ $panicked -eq 1 ]]; then
            log_fail "$test_label (PANIC detected)"
        elif [[ $exit_code -eq 0 ]]; then
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
