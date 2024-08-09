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

echo "=> Clearing kcov-output directory" 
rm -rf kcov-output 
mkdir kcov-output 

echo "=> Building Sig" 
zig build 

echo "=> Running kcov on gossip spy" 
kcov \
    --include-pattern=src/gossip/ \
    --exclude-pattern=$HOME/.cache \
    kcov-output/ \
    ./zig-out/bin/fuzz gossip_table 19 50_000

# open report
echo "=> Opening kcov-output/index.html" 
open kcov-output/index.html