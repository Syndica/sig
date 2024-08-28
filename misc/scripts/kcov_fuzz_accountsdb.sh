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

echo "=> Running kcov on accountsdb" 
kcov \
    --include-pattern=src/accountsdb/ \
    # not sure why this is necessary with --include-pattern but it is
    --exclude-pattern=$HOME/.cache \
    kcov-output/ \
    ./zig-out/bin/fuzz accountsdb

# open report
echo "=> Opening kcov-output/index.html" 
open kcov-output/index.html