# Dependencies

Install [nix](https://nixos.org/download/) if you do not have it.

```bash
nix develop            # if you only want to run the tests
nix develop .#agave    # if you also want to run the test vectors against agave
```

# Build

To run the conformance tests, you'll need a build of solfuzz_sig. Either Debug or ReleaseSafe builds are fine.

```bash
zig build solfuzz_sig
```


# Run

**Run the test vectors**

```bash
# run all conformance test vectors
run

# run only the transaction harness tests
run txn
```

For customization, try `--help`.

**Run the conformance CI job**

```bash
scripts/ci-run.sh
```

**Run solana-conformance directly**

run.py is a helper script to make this process easier. But in some cases when debugging, it's useful to interact directly with solana-conformance. Here's an example of how to run the zk_sdk tests with solana-conformance:

```bash
solana-conformance \
    exec-fixtures \
    -i env/test-vectors/instr/fixtures/zk_sdk \
    -t zig-out/lib/libsolfuzz_sig.so \
    -o env/test-outputs/
```

**Debug Agave**

If you want to debug agave or manually generate fixtures from agave, you'll need to set up the agave environment with `nix develop .#agave`.

You can edit any of the agave code in the env/ folder to debug agave. To run the conformance tests against this code, you'll need to compile solfuzz_agave:

```bash
cd env/solfuzz-agave
cargo build --lib --release
```

Then you can use some commands like these:

```bash
# run the tests against agave
run --exec-lib env/solfuzz-agave/target/release/libsolfuzz_agave.so

# create the fixtures based on agave, and run the conformance tests against sig
run --create

# re-run conformance tests against sig using your created fixtures
run --use-created
```

# Interpreting results

The expected and actual results for all tests are in env/test-outputs. You can use `parseout` to interpret the results.

```bash
parseout txn
```

See [parseout/README.md] for more info.
