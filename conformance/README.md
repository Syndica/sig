# Dependencies

- python 3.11
- zig 0.15.2 (not provided by the installation script or nix flake)
- git

Optional, for building solfuzz-agave:
- cmake
- gcc
- cargo/rust 1.93.0

## Installation

Use nix or the scripts.

### nix

```bash
nix develop           # if you only want to run the tests
nix develop .#full    # if you also want to debug solfuzz-agave
```

### scripts

Install the system dependencies:

```bash
scripts/install-system-deps.sh solana-conformance                # if you only want to run the tests
scripts/install-system-deps.sh solana-conformance solfuzz-agave  # if you also want to debug solfuzz-agave
```

Set up a test environment:

```bash
scripts/setup-env.sh         # if you only want to run the tests
scripts/setup-env.sh full    # if you also want to debug solfuzz-agave
```

# Build

To run the conformance tests, you'll need a build of solfuzz_sig. Either Debug or ReleaseSafe builds are fine.

```bash
zig build solfuzz_sig
```


# Run

**Run all the test vectors**

```bash
./run.py
```

For customization, try the `--help` option.

**Run the conformance CI job**

```bash
scripts/ci-run.sh
```

**Debug Agave**

If you want to debug solfuzz_agave or manually generate fixtures, you'll need to set up the `full` environment (described above in Dependencies). Then you can use some commands like these:

```bash
# create the fixtures from agave, and run the conformance tests
./run.py --create

# re-run conformance tests using your created fixtures
./run.py --use-created

# for more options
./run.py --help
```
