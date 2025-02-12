# AccountsDB

AccountsDB is a database which stores all the accounts on the solana blockchain.

The main code is located in `/src/accountsdb/`.

Checkout the blog post here: [Sig Engineering - Part 3 - Solana’s AccountsDB](https://blog.syndica.io/sig-engineering-part-3-solanas-accountsdb/).

The main struct files include:
- `db.zig`: the main database struct `AccountsDB`
- `accounts_file.zig`: reading + validating account files (which store the on-chain accounts)
- `index.zig`: all index related structs (to map from a pubkey to an account location)
- `snapshots.zig`: fields + data to deserialize snapshot metadata
- `genesis_config.zig`: genesis config fields
- `bank.zig`: minimal logic for bank (still being built out)

Other files include:
- `fuzz.zig`: accounts-db's fuzzer
- `download.zig`: downloading snapshots
- `buffer_pool.zig`: buffer pool for reading from account files
- `swiss_map.zig`: high-performance swissmap hashmap implementation

# Usage

The main entrypoint is the `AccountsDB` struct (from `cmd.zig`):

```zig
var accounts_db = try AccountsDB.init(.{
    .allocator = allocator,
    .logger = logger.unscoped(),
    // where we read the snapshot from
    .snapshot_dir = snapshot_dir,
    // optional geyser to stream accounts to
    .geyser_writer = options.geyser_writer,
    // gossip information for propogating snapshot info
    .gossip_view = if (options.gossip_service) |service|
        try AccountsDB.GossipView.fromService(service)
    else
        null,
    // to use disk or ram for the index
    .index_allocation = if (current_config.accounts_db.use_disk_index) .disk else .ram,
    // number of shards for the index
    .number_of_index_shards = current_config.accounts_db.number_of_index_shards,
});
defer accounts_db.deinit();
```

## Loading from a snapshot

To load from a snapshot, we use the `loadWithDefaults` method:

```zig
try accounts_db.loadWithDefaults(
    allocator,
    // this manifest contains the snapshot metadata for loading (e.g., slot, account files, etc.)
    combined_manifest,
    n_threads_snapshot_load,
    // bool flag to validate after loading
    options.validate_snapshot,
    // used for preallocation of the index
    current_config.accounts_db.accounts_per_file_estimate,
    // fastload/save options
    current_config.accounts_db.fastload,
    current_config.accounts_db.save_index,
);
```

This in turn calls `loadFromSnapshot` which loads the account files into the database and generates the
index. Validation is then performed on the accounts in `validateLoadFromSnapshot` which collects and verifies
all the account hashes.

## Geyser integration

When loading from a snapshot accounts are streamed to geyser in `loadAndVerifyAccountsFiles`.

```zig
indexAndValidateAccountFile(
    self.allocator,
    &self.buffer_pool,
    &accounts_file,
    self.account_index.pubkey_ref_map.shard_calculator,
    shard_counts,
    &slot_references,
    // ! we collect the accounts and pubkeys into geyser storage here
    geyser_slot_storage,
)
```

The collected accounts are then streamed to geyser a few lines down:

```zig
const data_versioned: sig.geyser.core.VersionedAccountPayload = .{
    .AccountPayloadV1 = .{
        .accounts = geyser_storage.accounts.items,
        .pubkeys = geyser_storage.pubkeys.items,
        .slot = slot,
    },
};
try geyser_writer.writePayloadToPipe(data_versioned);
```

# Fuzzing

We also use fuzzing to ensure the database is robust. The fuzzer can be found
in `fuzz.zig` and is run with the following command on the `fuzz` binary:

```bash
zig build -Dno-run fuzz

fuzz accountsdb <seed> <number_of_actions>
```

For a random seed, ommit the seed argument. For infinite fuzzing, omit the number of actions.

# Benchmarking

We also have a few benchmarks for the database:
- read/write benchmarks: this benchmarks the read/write speed for accounts
(can use the `accounts_db_readwrite` flag for the benchmarking binary)
- load and validate from a snapshot: this benchmarks the speed of loading and validating a snapshot
(can use the `accounts_db_snapshot` flag for the benchmarking binary with the `-e` flag)
- swissmap benchmarks: benchmarks the swissmap hashmap implementation against stdlib hashmap
(can use the `swissmap` flag for the benchmarking binary)

The benchmarking code can be found in the structs `BenchmarkAccountsDB`, `BenchmarkAccountsDBSnapshotLoad`,
and `BenchmarkSwissMap` respectively.

# Architecture

While the blog post contains a more detailed explanation of the architecture, we'll also list
some more implementation details here.

## Account File Map

To understand how we made the DB thread-safe, theres three scenarios to consider:
- adding new account files (flushing)
- reading account files (snapshot generation, account queries)
- removing account files (shrinking and purging)

The two main fields include `file_map_fd_rw` and `file_map_rw` which protect account files.

The reason for each of the scenarios is as follows:

### Creating New Account Files

Adding an account file should never invalidate the
account files observed by another thread. The file-map should be
write-locked so any map resizing (if theres not enough space) doesnt
invalidate other threads values.

### Reading Account Files

All reading threads must first acquire a read (shared) lock on the `file_map_fd_rw`,
before acquiring a lock on the file map, and reading an account file - to ensure
account files will not be closed while being read.

After doing so, the `file_map_rw` may be unlocked, without
releasing the file_map_fd_rw, allowing other threads to modify the file_map,
whilst preventing any files being closed until all reading threads have finished their work.

### Removing Account Files

A thread which wants to delete/close an account files must first
acquire a write (exclusive) lock on `file_map_fd_rw`, before acquiring
a write-lock on the file map to access the account_file and close/delete/remove it.

*Note:* Holding a write lock on `file_map_fd_rw` is very expensive, so we only acquire
a write-lock inside `deleteAccountFiles` which has a minimal amount of logic.

*Note:* no method modifieds/mutates account files after they have been
flushed. They are 'shrunk' with deletion + creating a smaller file, or fully purged
with deletion. This allows us to *not* use a lock per-account-file.

## Account Index

The index stores the mapping from Pubkey to the account location (`AccountRef`). A few notes:
- `pubkey_ref_map` is a sharded hashmap which maps from pubkey to `AccountRefHead` (which is a linked-list
of account-refs)
- `slot_reference_map` is a map from slot to a list of `AccountRefs` - these are created when
new accounts are stored in the hashmap, the underlying memory is allocated from the `reference_allocator`,
and re-used as the program runs. The `reference_manager` manages the state of free/used `AccountRefs`
to reduce allocations and increase speed (this is also the `-a` option in the accounts-db cli).
- `reference_allocator`: is the backing allocator to all `AccountRefs` in the database. It either allocates
on RAM or Disk memory depending on the init config.

```zig
pub const AccountIndex = struct {
    /// map from Pubkey -> AccountRefHead
    pubkey_ref_map: ShardedPubkeyRefMap,
    /// map from Slot -> []AccountRef
    slot_reference_map: RwMux(SlotRefMap),

    /// this is the allocator used to allocate reference_memory
    reference_allocator: ReferenceAllocator,
    /// manages reference memory throughout the life of the program (ie, manages the state of free/used AccountRefs)
    reference_manager: *sig.utils.allocators.RecycleBuffer(
        AccountRef,
        AccountRef.DEFAULT,
        .{},
    ),
}
```

# Background Threads

We also run background threads in the `runManagerLoop` method which does the following:
1) flush the cache to account files in `flushSlot`
2) clean account files in `cleanAccountFiles`
3) shrink account files in `shrinkAccountFiles`
4) deletes account files in `deleteAccountFiles`
5) periodically create full snapshots and incremental snapshots

#### Shrink/Delete Account Files

Since acquiring a write-lock on `file_map_fd_rw` is very expensive (ensuring no account-files
can have read-access), we ensure its only write-locked during deletion in `deleteAccountFiles` and
contains the minimal amount of logic.

We also limit how often the method is called by requiring a minimum number of account files to delete
per call (defined by `DELETE_ACCOUNT_FILES_MIN`).

#### Snapshot Creation

Full and incremental snapshots are created every N roots (defined in `ManagerLoopConfig`).
- full snapshots use `makeFullSnapshotGenerationPackage`
- incremental snapshots use `makeIncrementalSnapshotGenerationPackage`

The general usage is to create a snapshot package which implements a write method that can
be used to write a tar-archive of the snapshot (using the method `writeSnapshotTarWithFields`). The
package collects all the account files which should be included in the snapshot and also computes
the accounts-hash and total number of lamports to populate the manifest with.

In the loop, we create the package and then write the tar-archive into a zstd compression library
(`zstd.writerCtx`) which itself pipes into a file on disk.

After the writing has been complete the internal accounts-db state is updated using `commitFullSnapshotInfo` and `commitIncrementalSnapshotInfo` which tracks the new snapshot
created and either deletes or ignores older snapshots (which arent needed anymore).

# Snapshots

## Downloading Snapshots

all the code can be found in `src/accountsdb/download.zig` : `downloadSnapshotsFromGossip`

first, theres two types of snapshots: full snapshots and incremental snapshots
- full snapshots include all the accounts on the network at some specific slot.
- incremental snapshots are smaller and only contain the accounts which changed from a full snapshot.

for example, if the network is on slot 100, the full snapshot could contain all accounts at slot 75, and a matching incremental snapshot could contain all accounts that changed between slot 75 and slot 100.

to download a snapshot, gossip is started up to find other nodes in the network and collect gossip data - we look for peers who
- have a matching shred version (ie, the network version/hard-forks)
- have a valid rpc socket (ie, can download from)
- have a snapshot hash available

the snapshot hash structure is a gossip datatype which contains
- the largest full snapshot (both a the slot and hash)
- and a list of incremental snapshots (also slot and hash)

when downloading,
- we prioritize snapshots with larger slots
- and if we have a list of 'trusted' validators, we only download snapshots whos hashes matches the trusted validators hashes

[https://github.com/Syndica/sig/blob/fd10bad14cd32f99b7f698118305960a4d26da49/src/gossip/data.zig#L908](https://github.com/Syndica/sig/blob/fd10bad14cd32f99b7f698118305960a4d26da49/src/gossip/data.zig#L908)

then for each of these valid peers, we construct the url of the snapshot:
- full: snapshot-(slot)-(hash).tar.zstd
- incremental: incremental-snapshot-(base_slot)-(slot)-(hash).tar.zstd

and then start the download - we periodically check the download speed and make sure its fast enough, or we try another peer

## Decompressing Snapshots

Snapshots are downloaded as `.tar.zstd` and we decompress them using `parallelUnpackZstdTarBall`

we use a zstd library C bindings to create a decompressed stream which we then
feed the results to untar the archive to files on disk. the unarchiving
happens in parallel using `n-threads-snapshot-unpack`. since there is
a large amount of I/O, the default value is 2x the number of CPUs on the machine.

## Validating Snapshots

*note:* this will likely change with future improvements to the solana protocol account hashing

the goal of validating snapshots is to generate a merkle tree over all the accounts in the db and compares the root hash with the hash in the metadata. the entrypoint
is `validateLoadFromSnapshot`.

we take the following approach:
- account hashes are collected in parallel across shards using `getHashesFromIndexMultiThread` - similar to how the index is generated
- each thread will have a slice of hashes, the root hash is computed against this nested slices using `NestedHashTree`

*note:* pubkeys are also sorted so results are consistent

### Validating Other Data

after validating accounts-db data, we also validate a few key structs:
- `GenesisConfig` : this data is validated in against the bank in `Bank.validateBankFields(bank.bank_fields, &genesis_config);`
- `Bank` : contains `bank_fields` which is in the snapshot metadata (not used right now)
- `StatusCache / SlotHistory Sysvar` : additional validation performed in `status_cache.validate`
