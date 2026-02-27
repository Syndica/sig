---
sidebar_position: 7
title: Fuzzing
---

Fuzzing logic can be found in the `src/fuzz.zig` file.

We currently support the following filters:

```zig
pub const FuzzFilter = enum {
    accountsdb,
    gossip_service,
    gossip_table,
    ledger,
    allocators,
};
```

You can build and run the fuzzers with the following commands:

```bash
zig build fuzz -- gossip_service
```

*Note:* The accounts-db fuzzer requires many open file descriptors,
so you need to build the binary first and then run it:

```bash
zig build -Dno-run fuzz
./zig-out/bin/fuzz accountsdb --max-slots 1000
```

### AccountsDB Fuzzer Options

The accountsdb fuzzer supports the following options:
- `--max-slots <N>`: Exit after N slots (omit for infinite fuzzing)
- `--non-sequential-slots`: Enable non-sequential slot ordering

### Other Fuzzers

Most other fuzzers include specification of an RNG seed followed by the
maximum number of 'actions' to take. For example:

```bash
zig build fuzz -- gossip_service 19 10000
```

## Kcov

We also support kcov to give coverage information on what was and was not fuzzed:
- [https://github.com/SimonKagstrom/kcov](https://github.com/SimonKagstrom/kcov)

Commands to run:
- `bash scripts/kcov_fuzz_gossip_service.sh`
- `bash scripts/kcov_fuzz_gossip_table.sh`
- `bash scripts/kcov_fuzz_accountsdb.sh`

*Note:* View the scripts for helpful install instructions of kcov.

![](/img/2024-07-10-09-39-25.png)

![](/img/2024-07-10-09-39-57.png)
