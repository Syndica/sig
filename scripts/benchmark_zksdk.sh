#!/bin/bash

ZIG=${ZIG:-zig}
cc=$CC
AGAVE_COMMIT=3e5af27241c78e56226546360f680e4081c87bda
FD_COMMIT=78ba75d32c5e38c050eb7c1086885998a951253d

agave() {
    echo "cloning agave to ./agave"
    git clone https://github.com/anza-xyz/agave --depth 1
    cd agave/
    git fetch origin $AGAVE_COMMIT --depth 1
    git checkout $AGAVE_COMMIT
    cd programs/zk-elgamal-proof/
    echo "Agave benchmarks:"
    cargo bench
    cd -
}

sig() {
    echo "building sig zksdk benchmarks, this can take a few minutes..."
    $ZIG build benchmark -Doptimize=ReleaseFast -Dno-run
    echo "running sig zksdk benchmarks..."
    echo "Sig benchmarks:"
    zig-out/bin/benchmark zksdk
    cd -
}

firedancer() {
    echo "building firedancer bencmarks, this can take a few minutes..."
    git clone https://github.com/Rexicon226/firedancer --depth 1 -b zksdk-benchmarks
    cd firedancer
    git fetch $FD_COMMIT --depth 1
    git checkout $FD_COMMIT
    ./deps.sh
    make -j test_zksdk
    echo "Firedancer benchmarks:"
    build/native/gcc/unit-test/test_zksdk
    cd -
}

agave
firedancer
sig
