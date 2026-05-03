#!/usr/bin/env bash

set -euxo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DOCKER_UID_GID=""
DOCKER_MOUNT=()

step_configure_docker_user_mount_defaults() {
    DOCKER_UID_GID="$(id -u):$(id -g)"
    DOCKER_MOUNT=(
        -v "$PWD:$PWD"
        -w "$PWD"
        -e "HOME=$PWD"
        -u "$DOCKER_UID_GID"
    )
}

step_upload_coverage_to_codecov() {
    set +x
    local upload_sha="${GITHUB_SHA:-$(git rev-parse HEAD)}"
    echo "=== Codecov SHA debug ==="
    echo "GITHUB_EVENT_NAME: ${GITHUB_EVENT_NAME:-}"
    echo "GITHUB_SHA:        ${GITHUB_SHA:-}"
    echo "GITHUB_REF:        ${GITHUB_REF_NAME:-unset}"
    echo "HEAD:              $(git rev-parse HEAD)"
    echo "HEAD^1:            $(git rev-parse HEAD^1 2>/dev/null || echo 'N/A')"
    echo "HEAD^2:            $(git rev-parse HEAD^2 2>/dev/null || echo 'N/A (not a merge commit)')"
    if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; then
        upload_sha="$PR_HEAD_SHA"
        echo "Pull request event detected"
    elif git rev-parse HEAD^2 >/dev/null 2>&1; then
        echo "Merge commit detected"
    else
        echo "Not a merge commit"
    fi
    echo "Uploading coverage for $upload_sha"
    echo "========================="
    set -x

    curl -fsSLo codecov https://cli.codecov.io/v11.2.6/linux/codecov
    chmod +x codecov
    ./codecov --verbose upload-coverage \
        --fail-on-error \
        --dir kcov-merged/kcov-merged \
        --commit-sha "$upload_sha"
}

test_kcov_linux() {
    time zig build test \
        -Dno-run \
        -Dlong-tests \
        -Dtarget=x86_64-linux-gnu.2.36 \
        -Denable-tsan=false \
        -Dno-network-tests \
        --summary all
    step_configure_docker_user_mount_defaults
    time docker run \
        --security-opt seccomp=unconfined \
        "${DOCKER_MOUNT[@]}" \
        kcov/kcov \
        bash scripts/kcov_ci.sh
    step_upload_coverage_to_codecov
}

gossip_and_fuzz() {
    time command -v wget || (sudo apt-get update -y && sudo apt-get install wget -y)
    time ./scripts/proxy_workaround.sh zig
    time zig build sig fuzz \
            -Dno-run \
            -Denable-tsan=false \
            -Doptimize=ReleaseSafe \
            -p workspace/zig-out-release \
            --summary all
    time bash scripts/gossip_test.sh 120 workspace/zig-out-release/bin/sig
    time workspace/zig-out-release/bin/fuzz --seed 19 gossip-service 10000
    time workspace/zig-out-release/bin/fuzz --seed 19 gossip-table 100000
    time workspace/zig-out-release/bin/fuzz --seed 19 allocators 10000
    time workspace/zig-out-release/bin/fuzz --seed 19 ledger 10000
}

build_and_test_linux() {
    time command -v wget || (sudo apt-get update -y && sudo apt-get install wget -y)
    time ./scripts/proxy_workaround.sh zig
    time zig build \
        -Denable-tsan=true \
        -p workspace/zig-out \
        --summary all
    time zig build test \
        -Dno-run \
        -Dlong-tests \
        -Denable-tsan=true \
        -Dno-network-tests \
        --summary all
    time sh -c 'zig-out/bin/test 2>&1 | cat'
}

linux_misc_checks() {
    sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -yq update
    sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -yq install python3 python3-pip
    zig fmt --check src/ build.zig
    (
        cd conformance
        zig fmt --check src/ build.zig
    )
    python3 scripts/style.py --check src
    python3 scripts/style.py --check conformance/src
    python3 scripts/style.py --check v2/lib
    python3 scripts/style.py --check v2/services
    python3 scripts/style.py --check v2/init
    python3 docs/check.py ./
    sudo apt-get update -y
    sudo apt-get install wget -y
    ./scripts/proxy_workaround.sh zig
    (
        cd v2
        zig build ci --summary all
    )
    time \
        zig build test \
            -Dno-run \
            -Dlong-tests \
            -Denable-tsan=true \
            -Dledger=hashmap \
            -Dfilter=ledger \
            --summary all
    time sh -c 'zig-out/bin/test 2>&1 | cat'
    (
        cd src/rpc/webzockets
        time zig build test -Dcpu=x86_64_v3 --summary all
    )
}

solana_conformance() {
    cd conformance
    time zig build --summary all
    cd ..
    time step_clone_fixtures
    time conformance/scripts/ci-run.sh
}

case "${1:-all}" in
    all)
        mprocs \
            "bash ${BASH_SOURCE[0]} test_kcov_linux" \
            "bash ${BASH_SOURCE[0]} gossip_and_fuzz" \
            "bash ${BASH_SOURCE[0]} build_and_test_linux" \
            "bash ${BASH_SOURCE[0]} linux_misc_checks" \
            "bash ${BASH_SOURCE[0]} solana_conformance"
        ;;
    test_kcov_linux|gossip_and_fuzz|build_and_test_linux|linux_misc_checks|solana_conformance)
        "$1"
        ;;
    *)
        echo "usage: $0 [all|test_kcov_linux|gossip_and_fuzz|build_and_test_linux|linux_misc_checks|solana_conformance]" >&2
        exit 1
        ;;
esac
