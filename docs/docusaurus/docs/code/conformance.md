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

For customization, try the `--help` option.

**Run the conformance CI job**

```bash
scripts/ci-run.sh
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
