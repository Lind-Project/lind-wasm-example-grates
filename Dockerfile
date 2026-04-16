# syntax=docker/dockerfile:1.7

ARG REPO_URL=https://github.com/Lind-Project/lind-wasm-example-grates.git
ARG BRANCH_NAME=main
ARG COMMIT_SHA=

FROM securesystemslab/lind-wasm-dev:latest AS base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

FROM base AS source
ARG REPO_URL
ARG BRANCH_NAME
ARG COMMIT_SHA
WORKDIR /home/lind

RUN mkdir -p /home/lind/e2e-artifacts && \
    requested_commit="${COMMIT_SHA}" && \
    if [[ -z "${requested_commit}" ]]; then requested_commit="<none>"; fi && \
    source_status=0 && \
    if git clone --branch "${BRANCH_NAME}" --single-branch "${REPO_URL}" /home/lind/lind-wasm-example-grates \
        2>&1 | tee /home/lind/e2e-artifacts/source.log; then \
        if [[ -n "${COMMIT_SHA}" ]]; then \
            if (cd /home/lind/lind-wasm-example-grates && \
                git fetch --depth 1 origin "${COMMIT_SHA}" && \
                git checkout --detach FETCH_HEAD) \
                2>&1 | tee -a /home/lind/e2e-artifacts/source.log; then \
                true; \
            else \
                source_status=$?; \
            fi; \
        fi; \
    else \
        source_status=$?; \
    fi && \
    checked_out_commit="<unavailable>" && \
    if [[ -d /home/lind/lind-wasm-example-grates/.git ]]; then \
        checked_out_commit="$(git -C /home/lind/lind-wasm-example-grates rev-parse HEAD)"; \
    fi && \
    printf 'repo_url=%s\nrequested_branch=%s\nrequested_commit=%s\nchecked_out_commit=%s\n' \
        "${REPO_URL}" "${BRANCH_NAME}" "${requested_commit}" "${checked_out_commit}" \
        > /home/lind/e2e-artifacts/revision.txt && \
    if [[ ${source_status} -eq 0 ]]; then \
        echo "SOURCE_STATUS=pass" > /home/lind/source_status; \
    else \
        echo "SOURCE_STATUS=fail" > /home/lind/source_status; \
        printf '\nsource setup exited with status %s\n' "${source_status}" >> /home/lind/e2e-artifacts/source.log; \
    fi

FROM source AS test
ENV LIND_WASM_ROOT=/home/lind/lind-wasm
WORKDIR /home/lind

RUN make clean && \
    make

RUN repo_dir=/home/lind/lind-wasm-example-grates && \
    if [[ -f /home/lind/source_status ]] && grep -q 'SOURCE_STATUS=pass' /home/lind/source_status && [[ -d "${repo_dir}/.git" ]]; then \
        cd "${repo_dir}" && \
        if make test 2>&1 | tee /home/lind/e2e-artifacts/make-test.log; then \
            echo "E2E_STATUS=pass" > /home/lind/e2e_status; \
        else \
            status=$?; \
            echo "E2E_STATUS=fail" > /home/lind/e2e_status; \
            printf '\nmake test exited with status %s\n' "${status}" >> /home/lind/e2e-artifacts/make-test.log; \
        fi && \
        if [[ -f report.html ]]; then cp report.html /home/lind/e2e-artifacts/report.html; fi && \
        if [[ -f results.json ]]; then cp results.json /home/lind/e2e-artifacts/results.json; fi && \
        if [[ -d reports ]]; then cp -a reports /home/lind/e2e-artifacts/reports; fi; \
    else \
        echo "E2E_STATUS=fail" > /home/lind/e2e_status; \
        if [[ -f /home/lind/e2e-artifacts/source.log ]]; then \
            cp /home/lind/e2e-artifacts/source.log /home/lind/e2e-artifacts/make-test.log; \
        else \
            printf 'source setup failed before make test could run\n' > /home/lind/e2e-artifacts/make-test.log; \
        fi && \
        printf '\nmake test was skipped because source checkout failed.\n' >> /home/lind/e2e-artifacts/make-test.log; \
    fi

FROM test AS release
ENV LIND_WASM_ROOT=/home/lind/lind-wasm
WORKDIR /home/lind/lind-wasm-example-grates

FROM scratch AS artifacts
COPY --from=test /home/lind/e2e_status /e2e_status
COPY --from=test /home/lind/e2e-artifacts /test-artifacts
