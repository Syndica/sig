#!/usr/bin/env bash
set -euo pipefail

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir
. commits.env

get-repo-at-commit() { 
    local repo_url=$1
    local commit=$2
    local dir=$3

    mkdir -p env
    if [[ ! -d "$dir" ]]; then
        echo "Cloning $repo_url at $commit"
        if git clone --revision=$commit --depth=1 $repo_url $dir; then
            return 0
        else
            git clone $repo_url $dir
        fi
    fi
    echo "Resetting $dir to $commit"
    pushd $dir
    git reset --hard $commit
    popd
}

full-setup() {
    echo Any local changes you have to solana-conformance, solfuzz-agave, or test-vectors will be deleted.
    read -p "Do you want to continue? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi

    get-solfuzz-agave
    get-test-vectors
    get-solana-conformance
}

get-solfuzz-agave() {
    get-repo-at-commit \
        https://github.com/firedancer-io/solfuzz-agave.git \
        $SOLFUZZ_AGAVE_COMMIT \
        env/solfuzz-agave

    get-repo-at-commit \
        https://github.com/firedancer-io/protosol.git \
        $AGAVE_PROTOSOL_COMMIT \
        env/solfuzz-agave/protosol

    pushd env/solfuzz-agave
    cargo build --lib --release
    popd
}

get-test-vectors() {
    get-repo-at-commit \
        https://github.com/firedancer-io/test-vectors.git \
        $TEST_VECTORS_COMMIT \
        env/test-vectors
}

get-solana-conformance() {
    get-repo-at-commit \
        https://github.com/firedancer-io/solana-conformance.git \
        $SOLANA_CONFORMANCE_COMMIT \
        env/solana-conformance

    # set up the python venv to run solana conformance
    python3.11 -m venv env/pyvenv
    source env/pyvenv/bin/activate

    pushd env/solana-conformance
    pip install -e ".[dev]"
    pre-commit install
    popd

    cat <<-EOF

    Local environment created successfully. To activate it, run:

        source $conformance_dir/env/pyvenv/bin/activate

EOF
}

if [ $# -eq 0 ]; then
    full-setup
else
    "$@"
fi
