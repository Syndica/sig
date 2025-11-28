# Runtime 

## Conformance: Sealevel Virtual Machine (SVM), Builtins

```bash
# Move intoto `sig/conformance`
zig build -Doptimize=ReleaseSafe

# Create and activate env
./scripts/setup-env.sh
source env/pyvenv/bin/activate

# Create and run all fixtures
python3 run.py --create
```

## Replay: Shred Repair, and State Replay

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
