# syntax=docker/dockerfile:1.7
#
# Stage Definitions:
#   base      : Pre-built lind-wasm-dev toolchain
#   source    : Copies build context and records revision metadata
#   test      : Runs `make test` and parses results
#   dev       : Interactive debugging environment for reproducing failures (pushed to Docker Hub / Not yet)
#   artifacts : Minimal stage for extracting test outputs via `--output type=local`
#
# Usage Examples:
#   docker buildx build --target artifacts --output type=local,dest=./out .
#   docker buildx build --target dev -t <repo>:<tag> --push .
ARG BRANCH_NAME=main
ARG COMMIT_SHA=

# ── base ────────────────────────────────────────────────────────────────────
FROM securesystemslab/lind-wasm-dev:latest AS base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# ── source ──────────────────────────────────────────────────────────────────
FROM base AS source
ARG BRANCH_NAME
ARG COMMIT_SHA

COPY --chown=lind:lind . /home/lind/lind-wasm-example-grates
WORKDIR /home/lind/lind-wasm-example-grates

RUN mkdir -p /home/lind/e2e-artifacts && \
    printf 'branch=%s\ncommit=%s\nbuilt_at=%s\n' \
        "${BRANCH_NAME}" "${COMMIT_SHA:-<none>}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        > /home/lind/e2e-artifacts/revision.txt

# ── test ────────────────────────────────────────────────────────────────────
FROM source AS test
ENV LIND_WASM_ROOT=/home/lind/lind-wasm
WORKDIR /home/lind/lind-wasm-example-grates

RUN if { \
        if [[ -s .changed-grates ]]; then \
            while IFS= read -r grate; do \
                echo "Testing ${grate}"; \
                make test GRATE="${grate}" || exit $?; \
            done < .changed-grates; \
        else \
            make test; \
        fi; \
    } 2>&1 | tee /home/lind/e2e-artifacts/make-test.log; then \
        echo "E2E_STATUS=pass" > /home/lind/e2e_status; \
    else \
        status=$?; \
        echo "E2E_STATUS=fail" > /home/lind/e2e_status; \
        printf '\nmake test exited with status %s\n' "${status}" \
            >> /home/lind/e2e-artifacts/make-test.log; \
    fi; \
    sed -r 's/\x1b\[[0-9;]*m//g' /home/lind/e2e-artifacts/make-test.log \
        > /home/lind/e2e-artifacts/make-test.plain.log; \
    { \
        grep -E '^[[:space:]]+(Total|Passed|Failed|Skipped):' \
            /home/lind/e2e-artifacts/make-test.plain.log || true; \
        echo; \
        grep -oE '(FAIL|SKIP): [A-Za-z0-9_.-]+ / [A-Za-z0-9_.-]+ \([^)]*\)' \
            /home/lind/e2e-artifacts/make-test.plain.log || true; \
        grep -oE 'SKIP: [A-Za-z0-9_.-]+ \(configured[^)]*\)' \
            /home/lind/e2e-artifacts/make-test.plain.log || true; \
    } > /home/lind/e2e-artifacts/test-summary.txt; \
    echo "=== test summary ==="; \
    cat /home/lind/e2e-artifacts/test-summary.txt

# ── dev ─────────────────────────────────────────────────────────────────────
FROM test AS dev
ENV LIND_WASM_ROOT=/home/lind/lind-wasm
WORKDIR /home/lind/lind-wasm-example-grates

# ── artifacts ───────────────────────────────────────────────────────────────
FROM scratch AS artifacts
COPY --from=test /home/lind/e2e_status /e2e_status
COPY --from=test /home/lind/e2e-artifacts /test-artifacts
