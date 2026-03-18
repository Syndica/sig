#!/usr/bin/env bash
set -euo pipefail

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env="$conformance_dir/env"
. "$conformance_dir/commits.env"

get-repo-at-commit() { 
    local repo_url=$1
    local commit=$2
    local dir="$3"

    mkdir -p "$env"
    if [[ ! -d "$dir" ]]; then
        echo "Cloning $repo_url at $commit"
        if git clone --revision=$commit --depth=1 $repo_url "$dir"; then
            return 0
        else
            git clone $repo_url "$dir"
        fi
    fi
    echo "Resetting $dir to $commit"
    pushd "$dir"
    git fetch origin $commit
    git reset --hard $commit
    popd
}

get-repo-at-commit \
    https://github.com/firedancer-io/solfuzz-agave.git \
    $SOLFUZZ_AGAVE_COMMIT \
    "$env/solfuzz-agave"

get-repo-at-commit \
    https://github.com/firedancer-io/protosol.git \
    $AGAVE_PROTOSOL_COMMIT \
    "$env/solfuzz-agave/protosol"

# build vendored protoc and flatc
pushd "$env/solfuzz-agave/protosol"
git submodule update --init --recursive
./deps.sh
popd

export PROTOC_EXECUTABLE="$env/solfuzz-agave/protosol/opt/bin/protoc"
export FLATC_EXECUTABLE="$env/solfuzz-agave/protosol/opt/bin/flatc"

pushd "$env/solfuzz-agave"
cargo build --lib --release
popd
