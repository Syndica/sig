## Legder docs

The ledger is a datastore component of Sig. Not to be confused with the AccountDB which stores the current state
of an account, the ledger, on the hand stores all block related data, which is why it is also refered to as the Blockstore. 

The ledger stores various block data, two of the most crucial ones are Shreds. [TODO LINK] All the kinds of data
stored by the ledger can be seen in `schema.zig`

## Architecture

Sig's ledger has a pluggable architecture. This allows for the ability to have a swappable database backend. Currently two database backend are implemented: RocksDB [TODO LINK] and In memory HashMap.

<!-- [
    TODO Dive more into the architecture
    - mention the database interface in database.zig and impl in rocks.db and hashmap_db
    - mention the schema.zig as a place to see the kinds of data stored
    - All the various components finally writes to the database. Mention the batch writer here
] -->

## Source Layout
<!-- Overview of source files and what they do -->

## Shreds
As mentioned, the Shred is one, if not the most crucial data stored in the ledger, hence to fully understand the Legder implementation, a good overview of Shreds is required.

<!-- Expand more and give an overview of Shreds -->

## Shred Collector, ShredInserter and Shredder.

<!-- Expand more on these components and the role they play -->

## Erasure Coding

<!-- A brief overview and point out the reed_solomon*.zig files-->


## Writer and Reader

Shreds are a crucial data stored in the ledger, but they are not the only ones. The rest of the data stored and retrieved in the ledger are implemented in the Write `writer.zig` and Reader `reader.zig`

<!-- Expand more on the writer and reader -->


<!-- ## Transaction Status ?? Dive deep into this and see what can be explained here -->

## Putting it together.

<!-- 

Give an overview of how data would possible flow into and out of the ledger in the normal running of sig, possible touching on other components, gossip, turbine etc and how they interface with the ledger. 

-->