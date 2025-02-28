#!/usr/bin/env bash
#
# to install kcov follow the instructions at:
#   https://github.com/SimonKagstrom/kcov/blob/master/INSTALL.md
# to build on mac the following should work:
#   ```
#   cd /path/to/kcov/
#   mkdir build
#   cd build
#   cmake ..
#   make
#   make install
#   export PATH=$PATH:/path/to/kcov/build/src
#   ```

set -exo pipefail

echo "=> Cleaning up" 
rm -rf kcov-output 
mkdir kcov-output 

if [ -z "$1" ]; then
    echo "=> Building Sig" 
    zig build test -Dno-run
    test_bin="./zig-out/bin/test"
else
    test_bin="$1"
fi

echo "=> Running kcov on tests" 
kcov \
    --include-pattern=src/ \
    --exclude-pattern=$HOME/.cache \
    kcov-output \
    $test_bin 