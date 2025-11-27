#!/usr/bin/env bash
set -euo pipefail

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir
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

mkdir -p env


echo Any local changes you have to solana-conformance, solfuzz-agave, or test-vectors will be deleted.
read -p "Do you want to continue? [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi


# get sources for all dependencies
get-repo-at-commit \
    https://github.com/firedancer-io/solana-conformance.git \
    $SOLANA_CONFORMANCE_COMMIT \
    env/solana-conformance

get-repo-at-commit \
    https://github.com/firedancer-io/solfuzz-agave.git \
    $SOLFUZZ_AGAVE_COMMIT \
    env/solfuzz-agave

get-repo-at-commit \
    https://github.com/firedancer-io/protosol.git \
    $AGAVE_PROTOSOL_COMMIT \
    env/solfuzz-agave/protosol

get-repo-at-commit \
    https://github.com/firedancer-io/test-vectors.git \
    $TEST_VECTORS_COMMIT \
    env/test-vectors


# build solfuzz agave
pushd env/solfuzz-agave
cargo build --lib --release
popd


# set up the python venv to run solana conformance
python3.11 -m venv env/pyvenv
source env/pyvenv/bin/activate

pushd env/solana-conformance
pip install -e ".[dev]"
pre-commit install
popd

cat <<EOF

Local environment created successfully. To activate it, run:

    source $conformance_dir/env/pyvenv/bin/activate

EOF
