# Networking 

## Milestones
**Turbine**: Validator is able to forward shreds to other validators according to stake weight and other factors

**Gulfstream**: Validator is able to forward transactions to other validators TPU port for processing (according to leader 
schedule)

<br>

<p>
<img alt="Networking Diagram" src="imgs/networking.png" style="width: 800px; margin: auto;">
</p>

<br>

## Gulfstream - sig/src/transaction_sender

At a high level the sig transaction send service:
- read transactions from channel
- send transactions to upcoming leaders via quic
- adds transactions to a transaction pool for monitoring and retries
- retry transactions until they are rooted, failed, expired, or exceeded max retries

<br>

<p>
<img alt="Transaction Sender Service Diagram" src="imgs/transaction-sender-service.png" style="width: 800px; margin: auto;">
</p>

**Note**: since sig does not support consensus, the transaction send service makes the following RPC calls; getSignatureStatuses, getBlockHeight, and getSlot

### Demonstration - Landing Transfer Transactions

- **Sending Mock Transactions**:
    - Setup two accounts, a 'bank' and 'alice'
    - Ensure 'bank' has enough lamports to conver total transfer amount + transfer fees
    - Ensure 'alice' has zero lamports
    - Send 5_000_000 lamports to 'alice' over five transactions of 1_000_000 lamports each
    - Confirm that 'alice' has received 5_000_000 lamports
    - **permalink**: TODO

- **Gulfstream - Transaction Sender**
    - the sig transaction sender is run as usual
    - **permalink**: TODO
<br>


## Turbine - sig/src/turbine

At a high level the sig turbine retransmit stage:
- reads verified shreds from a channel populated by the shred collector
- runs deduplication of shreds for both the raw bytes and shred ids
- groups shreds by slot to streamline retrieval of turbine trees and slot leaders
- packages each shred into a RetransmitInfo struct containing the data required to compute turbine children
- sends each RetransmitInfo struct along a channel to one of N retransmit threads
- retransmit threads compute the turbine children and their addresses, sending new packets along a channel for transmission to the network

<br>


<p>
<img alt="Turbine Retransmit" src="imgs/turbine-retransmit.png" style="width: 900px; margin: auto;">
</p>

### Demonstration - Retransmitting Shreds as a *Staked Validator 

- **Issue**: unstaked validators are *always leaf nodes on testnet
    - a live demo won't show shred retransmission without stake 
    - real stake would cause negative network effects as sig is incomplete

- **Solution**: manually override our validators stake when building the turbine tree 
    - a live demo will show shred retransmission at both level 0 (root) and level 1 of the turbine tree
    - we will retransmit to the wrong nodes, however, this will have insignificant network effects
    - **permalinks**:
        - sig (stake override): TODO
    
### Demonstration - Retransmitting to the Correct Validators

- **Turbine Tree Determinism**: 
    - the epoch staked nodes always make up the first `n` nodes of a turbine tree; hence
    - the first `n` nodes of a turbine tree are **deterministic** amongst validators with respect to:
        - epoch staked nodes
        - shred id
        - slot leader
    - after the `nth` node, the turbine tree is **non-deterministic** as it depends on each validators internal gossip table
    - **permalinks**:
        - sig (seeding): TODO
        - agave (seeding): https://github.com/Syndica/agave/blob/9cf843b2982fc03259f52fcd7cfa5c1c4d21fe0c/turbine/src/cluster_nodes.rs#L209
        - sig (building): TODO
        - agave (building): https://github.com/Syndica/agave/blob/9cf843b2982fc03259f52fcd7cfa5c1c4d21fe0c/turbine/src/cluster_nodes.rs#L280

- **Black Box Approach**
    - create a test cluster in both sig and agave, consisting of:
        - a random set of staked nodes,
        - a gossip table containing the staked nodes plus other random unstaked nodes
    - create a TurbineTree (sig) / ClusterNodes\<Retransmit\> (agave) using the test cluster 
    - sample N random shred ids and compute the retransmit children 
    - confirm that the gerenated cluster info, and computed retransmit children are identical
    - **permalinks**
        - sig: TODO
        - agave: https://github.com/Syndica/agave/blob/9cf843b2982fc03259f52fcd7cfa5c1c4d21fe0c/turbine/src/cluster_nodes.rs#L884

## TODO: 
- more load on transaction sender 
- additional equivalence test case