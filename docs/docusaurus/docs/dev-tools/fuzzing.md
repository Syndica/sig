---
sidebar_position: 7
title: Fuzzing
---

fuzzing logic can be found in the `src/fuzz.zig` file.

we currently support the following filters:

```zig
pub const FuzzFilter = enum {
    accountsdb,
    snapshot,
    gossip_service,
    gossip_table,
    allocators,
    ledger,
};
```

you can build and run the fuzzers with the following commands:

```bash
zig build fuzz -- gossip_service
```

*Note:* the accounts-db fuzzer requires many open file descriptors,
so you need to build the binary first and then run it (ie,
`zig build fuzz && ./zig-out/bin/fuzz accountsdb`).

*Note:* most commands include specification of a rng seed followed by the
maximum number of 'actions' to take. For example:

```bash
zig build fuzz -- gossip_service 19 10000
```

## Kcov

We also support kcov to give coverage information on what was and was not fuzzed:
- [https://github.com/SimonKagstrom/kcov](https://github.com/SimonKagstrom/kcov)

commands to run:
- `bash scripts/kcov_fuzz_gossip_service.sh`
- `bash scripts/kcov_fuzz_gossip_table.sh`
- `bash scripts/kcov_fuzz_accountsdb.sh`

*note:* view the scripts for helpful install instructions of kcov

![](/img/2024-07-10-09-39-25.png)

![](/img/2024-07-10-09-39-57.png)
