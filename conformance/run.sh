CONF_DIR=/home/drew/mine/syndica/code/sig/conformance/

export LD_LIBRARY_PATH="$CONF_DIR/env/solfuzz/build-hfuzz"
export SOLFUZZ_TARGETS="$CONF_DIR/env/solfuzz-agave/target/release/libsolfuzz_agave.so,$CONF_DIR/zig-out/lib/libsolfuzz_sig.so"
export SOLFUZZ_ENGINE="cargo-hfuzz"
export ASAN_OPTIONS="verify_asan_link_order=0:detect_leaks=0"
# export CORPUS_DIR="/data0/cmoyes/octane/corpus/sol_elf_ctx"
export FUZZCORP_CORPUS_GROUP="sol_elf_ctx"
export FUZZCORP_LINEAGE_NAME="sol_elf_loader_diff"
# export HF_INPUT_DIR="/data0/cmoyes/octane/corpus/sol_elf_ctx"
export HF_WORKSPACE_DIR="/tmp/sig"
# HFUZZ_INPUT="/data0/cmoyes/octane/corpus/sol_elf_ctx" HFUZZ_WORKSPACE="/tmp/sig" HFUZZ_RUN_ARGS="--threads 32 -S --timeout 50 --rlimit_rss 9000 -F 10000000" ../bin/cargo-hfuzz hfuzz run-no-instr fuzz_elf

export HFUZZ_INPUT="$CONF_DIR/env/solfuzz/kunorpus/txn_corpus"
export HFUZZ_WORKSPACE="/tmp/sig" 
export HFUZZ_RUN_ARGS="--threads 16 -S --timeout 50 --rlimit_rss 9000 -F 10000000" 
    # ../bin/cargo-hfuzz hfuzz run-no-instr fuzz_txn

./hfuzz_target/x86_64-unknown-linux-gnu/release/fuzz_txn ../kunorpus/txn_corpus/txn_msg_00000000_a1b91a76662814c3.txnctx