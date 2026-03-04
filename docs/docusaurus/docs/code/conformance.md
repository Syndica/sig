Dependencies:
- python 3.11
- cargo/rust
- zig 0.15.2
- git 2.49

```bash
# set up the test environment
scripts/setup-env.sh
source env/pyvenv/bin/activate

# compile the sig binary to test
zig build -Doptimize=ReleaseSafe solfuzz_sig

# run the conformance tests for the first time
./run.py --create

# re-run conformance tests without re-creating the fixtures from scratch
./run.py

# for more options
./run.py --help
```
