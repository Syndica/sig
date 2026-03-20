# Dependencies

Install [nix](https://nixos.org/download/) if you do not have it.

```bash
nix develop           # if you only want to run the tests
nix develop .#full    # if you also want to debug solfuzz-agave
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

If you want to debug solfuzz_agave or manually generate fixtures, you'll need to use the `full` environment (described above). Then you can use some commands like these:

```bash
# create the fixtures from agave, and run the conformance tests
./run.py --create

# re-run conformance tests using your created fixtures
./run.py --use-created

# for more options
./run.py --help
```

# Interpreting results

The expected and actual results for all tests are in env/test-outputs. You can use `parseout` to interpret the results.

```bash
parseout txn
```

See [parseout/README.md] for more info.
