#!/bin/bash

# Configuration
BASE_DIR="$HOME/lind-wasm"
SCRIPTS_DIR="$BASE_DIR/scripts"
LINDFS_DIR="$BASE_DIR/lindfs"
TEST_ROOT_DIR="$BASE_DIR/tests/unit-tests"
LOG_FILE="$BASE_DIR/test_suite_$(date +%Y%m%d_%H%M%S).log"
TIMEOUT_VAL="5s" # Adjust if some tests are naturally slow

# Setup
mkdir -p "$LINDFS_DIR"
echo "--- Lind-Wasm Forceful Test Runner ---" > "$LOG_FILE"

find "$TEST_ROOT_DIR" -type f -name "*.c" | while read -r TEST_PATH; do
    TEST_DIR=$(dirname "$TEST_PATH")
    FILENAME=$(basename "$TEST_PATH")
    BASENAME="${FILENAME%.*}"
    CWASM_FILE="${TEST_DIR}/${BASENAME}.cwasm"
    
    echo "" | tee -a "$LOG_FILE"
    echo "------------------------------------------------" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    echo "Testing: $FILENAME" | tee -a "$LOG_FILE"

    # 1. Compile
    "$SCRIPTS_DIR/lind_compile" "$TEST_PATH" >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "RESULT: Compilation FAILED" | tee -a "$LOG_FILE"
        continue
    fi

    # 2. Copy
    cp "$CWASM_FILE" "$LINDFS_DIR/"

    # 3. Run with Hard Kill (SIGKILL)
    echo "Running ${BASENAME}.cwasm..." | tee -a "$LOG_FILE"

    # -k 2: Sends a SIGKILL (kill -9) 2 seconds after the initial signal if still alive
    # We removed --foreground to ensure the script doesn't hang on the sub-thread panic
    export RUST_BACKTRACE=1
    timeout -k 2 "$TIMEOUT_VAL" "$SCRIPTS_DIR/lind_run" strace_grate.cwasm "${BASENAME}.cwasm" >> "$LOG_FILE" 2>&1

    EXIT_STATUS=$?

    if [ $EXIT_STATUS -eq 124 ] || [ $EXIT_STATUS -eq 137 ]; then
        echo "RESULT: TIMEOUT/PANIC (KILLED)" | tee -a "$LOG_FILE"
        # Force kill any lingering lind_run processes just in case
        pkill -9 -f "lind_run" > /dev/null 2>&1
    elif [ $EXIT_STATUS -ne 0 ]; then
        echo "RESULT: FAILED (Exit Code: $EXIT_STATUS)" | tee -a "$LOG_FILE"
    else
        echo "RESULT: SUCCESS" | tee -a "$LOG_FILE"
    fi
    done

echo "------------------------------------------------" | tee -a "$LOG_FILE"

echo "Done."
