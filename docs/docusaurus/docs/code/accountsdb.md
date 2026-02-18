# AccountsDB

AccountsDB is a database which stores all the accounts on the Solana blockchain.

The main code is located in `/src/accountsdb/`.

Checkout the blog post here: [Sig Engineering - Part 3 - Solana's AccountsDB](https://blog.syndica.io/sig-engineering-part-3-solanas-accountsdb/).

## Architecture

The AccountsDB v2 implementation uses a two-tier storage system:

- **Unrooted Storage** (`two/Unrooted.zig`): Stores recent, unrooted account modifications in memory. Supports fork-aware queries using ancestors.
- **Rooted Storage** (`two/Rooted.zig`): Persists finalized (rooted) accounts to disk using SQLite.

The main struct files include:
- `two/Two.zig`: The main database struct that combines rooted and unrooted storage
- `account_store.zig`: Unified interface for reading and writing accounts
- `accounts_file.zig`: Reading + validating account files (which store the on-chain accounts)
- `snapshot/`: Snapshot loading and management

Other files include:
- `fuzz.zig`: AccountsDB fuzzer for testing
- `buffer_pool.zig`: Buffer pool for reading from account files

## Usage

### Basic Operations

The main interface is through `AccountStore` and `AccountReader`:

```zig
const sig = @import("sig");

// Initialize v2 database for testing
var test_state = try sig.accounts_db.Two.initTest(allocator);
defer test_state.deinit();
const db = &test_state.db;

// Create an account store wrapper
const account_store: sig.accounts_db.AccountStore = .{ .accounts_db_two = db };

// Put an account
try account_store.put(slot, pubkey, account_shared_data);

// Get an account (requires ancestors for fork-aware queries)
var ancestors = try sig.core.Ancestors.initWithSlots(allocator, &.{slot});
defer ancestors.deinit(allocator);

const account_reader = account_store.reader();
const account = try account_reader.forSlot(&ancestors).get(allocator, pubkey);
defer if (account) |acc| acc.deinit(allocator);
```

### Rooting Slots

When consensus determines a slot is finalized, call `onSlotRooted` to move accounts from unrooted to rooted storage:

```zig
account_store.onSlotRooted(newly_rooted_slot, &ancestors);
```

## Fuzzing

We use fuzzing to ensure the database is robust. The fuzzer can be found
in `fuzz.zig` and is run with the following command:

```bash
zig build -Dno-run fuzz
./zig-out/bin/fuzz accountsdb --max-slots 1000
```

Options:
- `--max-slots <N>`: Exit after N slots (omit for infinite fuzzing)
- `--non-sequential-slots`: Enable non-sequential slot ordering

## Thread Safety

The v2 AccountsDB is designed for concurrent access:

- **Unrooted storage**: Uses per-slot read-write locks for safe concurrent reads and writes
- **Rooted storage**: Uses SQLite with appropriate transaction handling

Multiple reader threads can safely query accounts while writer threads add new account modifications.

## Fork-Aware Queries

AccountsDB v2 supports Solana's fork-based execution model. When querying an account:

1. The ancestors set defines which slots are visible to the query
2. Unrooted storage is searched first for the most recent version within the ancestor set
3. If not found in unrooted, rooted storage is checked
4. Zero-lamport accounts (deleted accounts) return `null`

Example with competing forks:

```
     1 (rooted)
    / \
   2   3
  /   / \
 4   5   6
```

A query for slot 6 with ancestors `{1, 3, 6}` will:
- Return the slot 6 version if modified there
- Otherwise return the slot 3 version if modified there
- Otherwise return the slot 1 version from rooted storage
- Will NOT see modifications from slots 2, 4, or 5

## Snapshots

### Downloading Snapshots

Code for downloading snapshots is in `src/accountsdb/snapshot/download.zig`.

There are two types of snapshots:
- **Full snapshots**: Contain all accounts at a specific slot
- **Incremental snapshots**: Contain only accounts changed since a full snapshot

### Loading Snapshots

Snapshot loading is handled by the snapshot module. The process involves:
1. Unpacking the compressed tar archive
2. Loading account files
3. Building the account index

### Decompressing Snapshots

Snapshots are downloaded as `.tar.zstd` and decompressed using `parallelUnpackZstdTarBall`.
The unarchiving happens in parallel for improved I/O performance.
