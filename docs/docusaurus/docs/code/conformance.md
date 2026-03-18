Dependencies:
- python 3.11
- zig 0.15.2
- git

Optional dependencies, for building solfuzz-agave:
- cmake
- gcc
- cargo/rust

# Run tests

Just to run the conformance tests.

```bash
# install system dependencies
scripts/install-system-deps.sh solana-conformance

# set up the test environment
scripts/setup-env.sh
source env/pyvenv/bin/activate

# compile the sig binary to test
zig build -Doptimize=ReleaseSafe solfuzz_sig

# re-run conformance tests using test vectors
./run.py

# for more options
./run.py --help
```

# Debug Agave

If you want to debug solfuzz_agave or manually generate fixtures, you'll need to set up the `full` environment instead of just the basic default.

```bash
# install system dependencies
scripts/install-system-deps.sh solana-conformance solfuzz-agave

# set up the test environment, including solfuzz_agave
scripts/setup-env.sh full
source env/pyvenv/bin/activate

# compile the sig binary to test
zig build -Doptimize=ReleaseSafe solfuzz_sig

# create the fixtures from agave, and run the conformance tests 
./run.py --create

# re-run conformance tests using your created fixtures
./run.py --use-created

# for more options
./run.py --help
```
