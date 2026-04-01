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

See [parseout/README.md](parseout/README.md) for more info.

# Fixing Conformance Failures

This section explains how to approach fixing conformance failures—the strategy, tools, and common patterns you'll encounter.

## Infrastructure Overview

The conformance system works as follows:

- **Test vectors** are binary `.fix` files in `env/test-vectors/`, each encoding a program input (a transaction, an instruction, an ELF, etc.) along with the expected output that agave produces.
- **Harnesses** in `src/` deserialize those inputs and feed them into sig's runtime. The harness code is the layer between the test framework and sig's actual logic in `../src/`.
- **solana-conformance** (a Python CLI in `env/solana-conformance/`) orchestrates test execution, compares outputs, and writes results to `env/test-outputs/`.
- **solfuzz-agave** (`env/solfuzz-agave/`) contains the equivalent harnesses for agave. You can run the tests against agave to regenerate expected outputs, or add print statements to agave for comparison.

The sig source code is in `../src/`. The agave source code is in `env/agave/`. Both can be edited for debugging—just recompile the respective harness afterward.

## Workflow

### 1. Run the tests and classify failures

```bash
run                    # run all test groups
run txn                # run only the transaction tests
```

For large numbers of failures, use `parseout` to group them by what differs:

```bash
parseout diff env/test-outputs/txn/expected/<file>.txt \
              env/test-outputs/txn/actual/<file>.txt
```

For the txn harness, the `txn` command provides a more useful diff than the `diff` command:

```bash
parseout txn
```

This writes `(diff|txn).csv`, `(diff|txn)-category.json`, and `(diff|txn)-combo.json`. The combo file groups failures by their combination of differing fields, which quickly reveals how many distinct bugs you're dealing with. Fix one representative failure from each group, not every individual case. Usually a single code fix resolves an entire group.

### 2. Pick a failure and compare outputs

Find the fixture in the failing list and look up its entry in the expected and actual output files in `env/test-outputs/`. The outputs are text-format protobuf. For the transaction harness they are all written to a single combined output file per run. Example:

```bash
grep -A20 "<fixture_name>" env/test-outputs/txn/expected/*.txt
grep -A20 "<fixture_name>" env/test-outputs/txn/actual/*.txt
```

### 3. Understand the error encoding

Instruction errors in the output are encoded as integers. The mapping is:

```
proto value = intFromEnum(InstructionError) + 1
```

The full table is in `../src/core/instruction.zig` in the `intFromInstructionError` function. Some common ones:

| Proto value | InstructionError             |
|-------------|------------------------------|
| 3           | InvalidInstructionData       |
| 4           | InvalidAccountData           |
| 26          | Custom                       |
| 31          | UnsupportedProgramId         |
| 32          | CallDepth                    |
| 49          | UnsupportedSysvar            |

`executed_units` reflects total compute units consumed by the transaction up to the point of failure. If agave shows `0` (or no `executed_units` field, which is the protobuf default), the failure occurred before any compute was consumed—often a feature flag check at the top of a program's entrypoint.

`instruction_error_index` indicates which instruction failed (0-indexed). If it's absent, the failure is at instruction 0.

### 4. Locate the divergence

Once you know what error sig produces versus what agave produces, trace the code paths in both:

- **Sig's harness** is in `src/`. It calls into sig's runtime at `../src/runtime/`.
- **Agave's harness** is in `env/solfuzz-agave/src/`. It calls into agave at `env/agave/`.

For a given failing instruction, find the program's execute function in both codebases and compare them. Common places to look:

- `../src/runtime/program/<program>/` — sig's builtin/native program implementations
- `../src/runtime/executor.zig` — instruction dispatch, feature gate checking
- `../src/runtime/program/lib.zig` — the static maps of native programs and precompiles
- `env/agave/programs/<program>/src/lib.rs` — agave's equivalent

### 5. Add print statements for deeper inspection

If the divergence isn't obvious from static reading, add temporary print/log statements to both harnesses and recompile:

```bash
# after editing sig source:
zig build solfuzz_sig

# after editing agave source (requires nix develop .#agave):
cd env/solfuzz-agave && cargo build --lib
```

Then run the tests, observe the output, and iterate. Clean up all debug prints before committing.

## Common Root Causes

### Harness divergence

When updating the test-vectors version, it often also corresponds with changes to solfuzz-agave. If so, most of the failures are likely to be caused by divergence in the test harness.

### Feature flags not checked (or wrong feature checked)

Agave gates program behavior heavily on feature flags. Look in agave for checks like this. Then check whether sig's equivalent program has the same check. 

```rust
if !feature_set.enable_some_feature {
    return Err(InstructionError::InvalidInstructionData);
}
```

Sometimes agave changes the features' pubkeys. Check `env/agave/feature-set/src/lib.rs` for agave's feature pubkeys. In sig, feature pubkeys are listed in `../src/core/features.zon`.

### Validation differences

If both implementations hit a transaction error and fail, but with different error codes, carefully compare the transaction processing logic. Sig's is in loadAndExecuteTransaction.

If both implementations reach the same instruction and fail, but with different error codes, read the respective program's logic side by side.

Pay attention to:

- The order of validation checks (e.g., size check before or after ownership check)
- What `size_of` / `BYTE_LEN` constants are used for proof data types
- Whether a program consumes compute before or after a validation that can fail

### Instruction error index differs

If the error code matches but `instruction_error_index` differs (or one is missing), sig is failing at a different instruction than agave. This usually means sig is incorrectly succeeding at an earlier instruction that agave fails on.

## Commit Checklist

After fixing a bug, follow these steps before committing:

1. **Run the full test suite**:
   ```bash
   run
   ```

2. **Update `scripts/failing.txt`** with the new results:
   ```bash
   cp env/test-outputs/failing.txt scripts/failing.txt
   ```

3. **Check for regressions.** Any lines that were added to `failing.txt` (tests that were previously passing but now fail) mean you introduced a regression. Do not commit if there are any regressions.

4. **Run the CI script** to confirm it passes with the new failing list:
   ```bash
   scripts/ci-run.sh
   ```
