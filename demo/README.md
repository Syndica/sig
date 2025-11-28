# Runtime

The runtime demo has two main components: conformance and replay.

## Conformance: Sealevel Virtual Machine (SVM), Builtins

The conformance component runs the solana conformance test suite against the test cases within
the public test vectors repo. It demonstrates Sig's succesful implementation of the SVM, and its 
ability to correctly execute transactions consisting of instructions which invoke both native 
and sBPF programs.

This can be executed by running the conformance tests in Sig's `conformance` folder.

```bash
# Build the conformance binary from inside the conformance folder
cd conformance
zig build -Doptimize=ReleaseSafe solfuzz_sig

# Create and activate env
./scripts/setup-env.sh
source env/pyvenv/bin/activate

# Create and run all fixtures
python3 run.py --create
```

## Replay: Shred Repair, and State Replay

The replay component demonstrates Sig's repair and replay functionality. The replay component 
involves downloading a snapshot, and running Agave to generate slot hashes for comparison. We then 
run Sig's shred network from this snapshot to populate the blockstore, and subsequently run Sig 
in offline mode to generate slot hashes for comparison. By demostrating that the slot hashes are 
equivalent between Sig and Agave, we demostrate Sig's ability to correctly receive shreds and 
replay blocks.

This can be executed by running the scripts within this demo folder.

```bash
# Clone and build Agave and Sig
./init-env.sh

# Download snapshot and populate Agave's blockstore
./setup-agave.sh

# Copy snapshot and populate Sig's blockstore
# Runs Sig's Shred Network to collect shreds from the network and load them 
# into the blockstore for replay in the next step.
./setup-sig.sh

# Run Agave offline to generate slot hashes 
./run-agave-offline.sh

# Run Sig offline to generate slot hashes
# Reads blocks from Sig's pre-populated blockstore and executes them within the runtime. 
# The state transitions resulting from block execution are confirmed to be correct by comparing the slot hashes against the Agave reference.
./run-sig-offline.sh

# Diff slot hashes (some diffs may occur due to forking...)
diff agave-ledger/run-offline-slot-hashes.log sig-ledger/run-offline-slot-hashes.log 
```

# Consensus

To demo consensus, run the sig validator.

```bash
# Build sig
zig build -Doptimize=ReleaseSafe sig

# Run the validator
zig-out/bin/sig validator -c testnet
```

Compared to main, this branch just adds some extra logs for better visibility into what's going on in consensus.
