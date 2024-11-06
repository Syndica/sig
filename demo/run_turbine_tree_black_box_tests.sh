#!/bin/bash

# Remove old test results
if ls demo/turbine-tree-black-box-test-* 1> /dev/null 2>&1; then
    rm demo/turbine-tree-black-box-test-*
fi

# Run sig test
echo "Running sig turbine tree black box tests"
zig-out/bin/sig turbine-black-box

# Run agave test 
cd ../agave-fork/turbine
echo "Running agave turbine tree (cluster nodes) black box tests"
cargo test test_cluster_nodes_black_box > /dev/null 2>&1

# Move back to test directory
cd ../../sig1

# Compare diffs
echo "diff demo/turbine-tree-black-box-test-0-sig.txt demo/turbine-tree-black-box-test-0-agave.txt"
diff demo/turbine-tree-black-box-test-0-sig.txt demo/turbine-tree-black-box-test-0-agave.txt