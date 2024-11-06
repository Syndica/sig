# Intro

1. Open the networking png and discuss gulf stream and turbine at a high level.

## Gulf Stream (sig1)

### Plan

1. Open transaction sender readme.md and discuss design
2. Explain work arounds and their context
3. Explain integration test and kick it off 
4. Discuss some parts of code (maybe?)

### Notes

- GulfStream broadly defines Solana's mechanism for moving transactions from the edge of the network into the TPU of a leader node for inclusion in new blocks. 
- Rather than a traditional mempool approach, validators forward transactions directly to upcoming leaders who can begin processing them immediately, allowing for faster execution and reduced confirmation times. 
- Every validator has to know who will be leader for each slot, and have some means of slot relative time keeping. 
- Solana uses a LeaderSchedule to assign a leader to every slot in an epoch
- Solana uses Proof of History to keep track of and prove slot relative timing.

- Gulfstream can be thought of as Solana's mechanism for moving transactions from the edge of the network into the transaction processing unit of a leader validator. 
- Validators make use of a leader schedule identify upcoming leaders and forward transactions to their TPU port using the quic protocol. 
- The TPU info for leaders is discovered over gossip.
- Since sig does not currently have consensus or proof of stake implemented, we rely on rpc calls to get the current slot and check the status of pending transactions.


## Turbine (sig2)

### Plan 

1. Open Turbine readme.md (TODO)
2. Talk through importance of deterministic tree production
3. Start up turbine with overwritten stake 
3. Explain implementing all of agave's unit tests for key data structures
4. Explain and run test cluster equivalence test

### Notes


equivalence test permalinks
agave: https://github.com/Syndica/agave/blob/8d3e1be8de662cd882a55f1fa568d50c98fadf31/turbine/src/cluster_nodes.rs#L884
sig:   https://github.com/Syndica/sig/blob/fc846a33faef9345fb363c4d5e0090484ff52a17/src/turbine/turbine_tree.zig#L873