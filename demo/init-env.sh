#!/usr/bin/env bash
set -euo pipefail

demo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $demo_dir
. commits.env

get-repo-at-commit() { 
    local repo_url=$1
    local commit=$2
    local dir=$3

    if [[ ! -d "$dir" ]]; then
        echo "Cloning $repo_url at $commit"
        git clone $repo_url $dir
    fi

    echo "Resetting $dir to $commit"
    pushd $dir
    git reset --hard $commit
    popd
}

# Clone and build agave
get-repo-at-commit \
    https://github.com/anza-xyz/agave.git \
    $AGAVE_COMMIT \
    env/agave

pushd env/agave
git apply ../../replay-agave.patch
cargo build --release
popd

# Clone and building sig
get-repo-at-commit \
    https://github.com/Syndica/sig.git \
    $SIG_COMMIT \
    env/sig

pushd env/sig
git apply ../../replay-sig.patch
zig build -Doptimize=ReleaseSafe
popd

# Create identity keypair
pushd env
./agave/target/release/solana-keygen new -o identity.json --no-passphrase --silent
popd