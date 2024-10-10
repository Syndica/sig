## Legder docs

The ledger is a datastore component of Sig. Not to be confused with the AccountDB which stores the current state
accounts, the ledger, on the hand stores all block related data, which is why it is also refered to as the Blockstore. 

The ledger stores various block data, two of the most crucial ones are Shreds. All the kinds of data
stored by the ledger can be seen in [`schema.zig`](./schema.zig)

## Architecture

Sig's ledger has a pluggable architecture. This allows for the ability to have a swappable database backend. 

Currently two database backend are implemented: 

1. RocksDB. Implementation found in [`rocksdb.zig`](./schema.zig)
2. HashMap. Implementation found in [`hashmap_db.zig`](./hashmap_db.zig).

The interface that defines what a database backend should look like is found in [`database.zig`](./database.zig). 

Both the RocksDB and the HashMap implementation satisfies this interface. There exist the utility function
`assertIsDatabase` that is used to check that any implementation adheres to the interface.

RocksDB has the concept of column families, which is a mechanism to logically partition the database. You can read more
on column families [here](https://github.com/facebook/rocksdb/wiki/column-families)

The column families defined for the ledger can be found in [`schema.zig`]((./schema.zig)) and this is used by both the RocksDB
implementation and the HashMap implementation. 

Note, that the database also supports the idea of transaction but this is defined as a `WriteBatch` which 
should be used to ensure that a group of operations are either all executed successfully or, none of them are executed.

## Source Layout

The core implementation of the ledger can be found in the `ledger` module.

The repo [rocksdb-zig](https://github.com/Syndica/rocksdb-zig) builds the RocksDB project and makes it usable within `Sig` through RocksDB's C API and auto-generated Zig bindings.

Apart from the code in the `ledger` module, the `shred_collector` module also contains functionality that is closely related to the `ledger`.

The `shred_collector` contains the logic for collecting shreds, which is one of the core data stored by the ledger.

## Shreds
As mentioned, the Shred is one, if not the most crucial data stored in the ledger, hence to fully understand the Legder implementation, a good overview of Shreds is required.

<!-- Expand more and give an overview of Shreds -->

## Shred Collector, ShredInserter and Shredder.

<!-- Expand more on these components and the role they play -->

## Erasure Coding

<!-- A brief overview and point out the reed_solomon*.zig files-->

## Writer and Reader

Shreds are a crucial data stored in the ledger, but they are not the only ones. The rest of the data stored and retrieved 
in the ledger are implemented in the Write `writer.zig` and Reader `reader.zig`.

<!-- Expand more on the writer and reader -->


<!-- ## Transaction Status ?? Dive deep into this and see what can be explained here -->

## Putting it together.

<!-- 

Give an overview of how data would possible flow into and out of the ledger in the normal running of sig, possible touching on other components, gossip, turbine etc and how they interface with the ledger. 

-->