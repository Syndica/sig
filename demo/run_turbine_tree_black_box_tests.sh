#!/bin/bash

# Remove old test results
if ls demo/turbine-tree-black-box-test-* 1> /dev/null 2>&1; then
    rm demo/turbine-tree-black-box-test-*
fi

# Run sig test
echo "Running sig turbine tree black box tests"
zig-out/bin/sig turbine-black-box

# Run agave test 
echo "Running agave turbine tree (cluster nodes) black box tests"
$1/target/release/solana-turbine

# Compare diffs
echo "diff demo/turbine-tree-black-box-test-0-sig.txt demo/turbine-tree-black-box-test-0-agave.txt"
diff demo/turbine-tree-black-box-test-0-sig.txt demo/turbine-tree-black-box-test-0-agave.txt

echo "diff demo/turbine-tree-black-box-test-1-sig.txt demo/turbine-tree-black-box-test-1-agave.txt"
diff demo/turbine-tree-black-box-test-1-sig.txt demo/turbine-tree-black-box-test-1-agave.txt