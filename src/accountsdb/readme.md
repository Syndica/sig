# overview

main code is in `src/accounts-db/`

main file outlines: 
- db.zig: main database file 
- accounts_file.zig: reading + validating account files (from snapshots) 
- index.zig: account index structs (account ref, simd hashmap, …)
- snapshots.zig: fields + data to deserialize snapshot metadata
- bank.zig: minimal logic for bank
- genesis_config.zig: fields of the genesis to deserialize (used in snapshot validation)
- sysvars.zig: accounts of all the system variables (clock, slot_history, …) 

main code path starts from the `main()` in `db.zig`

## download a snapshot throught cli 

```
zig-out/bin/sig download_snapshot \
    -s test_data/tmp \
    --entrypoint 34.83.231.102:8001 \
    --entrypoint 145.40.67.83:8001 \
    --min-snapshot-download-speed 50
```

## loading from a snapshot : `loadFromSnapshot`

compressed (tar.zst) snapshots are unpacked using `parallelUnpackZstdTarBall`
- zstd decompression uses a C library located in `src/zstd`

- loading from a snapshot begins in `accounts_db.loadFromSnapshot`
    - reads the account files 
    - validates + indexes every account in each file (in parallel) 
    - combines the results across the threads (also in parallel) 

<div align="center">
<img src="imgs/2024-03-21-09-15-08.png" width="520" height="340">
</div>

notes on how the index is designed 
- account references are stored as blocks of memory (`ArrayList`)
- the index hashmap maps from (Pubkey => *AccountRef) where the reference is also a linked list for different references across different slots.
- the actual AccountRef memory is stored on the heap in blocks - ie, the indexing steps are read all the account references into an array as we parse the account files 
- iterate through the arraylist, `getOrPut` on the hashmap for the pubkey, and then add the reference (or append to the linked list)
    - we did it this way because allocations building a hashmap with the keys as Arraylist(AccountRef) was too slow

## validating a snapshot : `accounts_db.validateLoadFromSnapshot`

note: this will likely change with future improvements to the solana protocol account hashing (talked about at mtndao)

- this function generates a merkle tree over all the accounts in the db and compares the root hash with the hash in the metadata (for data corruption checks)
- account hashes are collected in parallel across bins (getHashesFromIndexMultiThread) 
- each thread will have a slice of hashes, the root hash is computed against this nested slices using `NestedHashTree`

note: pubkeys are also sorted so results are consistent

## validating other metadata
- GenesisConfig : this data is validated in against the bank in `Bank.validateBankFields(bank.bank_fields, &genesis_config);`
- Bank : contains `bank_fields` which is in the snapshot metadata (not used right now)
- StatusCache / SlotHistory Sysvar : additional validation performed in `status_cache.validate`

## read/write benchmarks 
`BenchArgs` contains all the configuration of a benchmark (comments describe each parameter) 
- found at the bottom of `db.zig`

writing accounts uses `putAccountBatch` which takes a slice of accounts 
and `putAccountFile` which takes an account file 
reading accounts uses `accounts_db.getAccount(pubkey);`.
