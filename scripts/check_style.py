# script for checking that source files conform to the style guide

import argparse
import math
import os
import re

MAX_LINE_LENGTH = 100

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("dirs", action="append")
arg_parser.add_argument("--check", action="store_true")
arg_parser.add_argument("-v", "--verbose", action="store_true")
args = arg_parser.parse_args()


def get_files():
    files_to_check = []
    dirs = [*args.dirs]
    while len(dirs) > 0:
        d = dirs.pop()
        files = os.listdir(d)
        for file in files:
            full_path = os.path.join(d, file)
            if os.path.isdir(full_path):
                dirs.append(full_path)
            else:
                if file.endswith(".zig"):
                    files_to_check.append(full_path)
    return files_to_check


# Checks for unused imports in files.
def unused_imports():
    files_to_check = get_files()
    import_line_regex = re.compile(
        r'const\s+([a-zA-Z]+)\s+=\s+@import\("([a-zA-Z.]+)"\);'
    )

    total_lines_removed = 0
    lines_removed = 0

    while True:
        lines_removed = 0
        for path in files_to_check:
            with open(path) as f:
                orig_file = f.read()
            orig_lines = orig_file.split("\n")
            if orig_lines[-1] == "":
                orig_lines = orig_lines[0:-1]

            # identify imports
            imported_names = []
            for line_num, line in enumerate(orig_lines):
                match = import_line_regex.match(line)
                if match:
                    imported_names.append((match.groups()[0], line_num))
            lines_to_drop = set()
            num_lines_to_remove = 0

            # identify which imports are unused
            for name, line in imported_names:
                match = re.findall(f"[^a-zA-Z0-9_.]{name}[^a-zA-Z0-9_]", orig_file)
                assert len(match) > 0
                if len(match) == 1:
                    lines_to_drop.add(line)
                    num_lines_to_remove += 1

            # do something about the unused imports
            if num_lines_to_remove:
                if args.check:
                    print(f"Found {num_lines_to_remove} unused import(s) in {path}:")
                    largest_line_num = max(max(lines_to_drop), 1)
                    padding = int(math.log(largest_line_num, 10))
                    for line_num in sorted(lines_to_drop):
                        line_num_str = f"{line_num}".rjust(padding, " ")
                        print(f"{line_num_str} | {orig_lines[line_num]}")
                    print()
                else:
                    with open(path, "w") as f:
                        f.writelines(
                            f"{line}\n"
                            for i, line in enumerate(orig_lines)
                            if i not in lines_to_drop
                        )
                    print(f"Removed {num_lines_to_remove} unused import(s) in {path}")
                    os.system(f"zig fmt {path}")
            elif args.verbose:
                print(path, num_lines_to_remove)

            total_lines_removed += num_lines_to_remove
            lines_removed += lines_removed

        if args.check:
            break
        elif lines_removed == 0:
            break
        else:
            print("Unused imports removed this iteration:", lines_removed)

    print("Files checked:", len(files_to_check))
    if args.check:
        print("Total unused imports found:", total_lines_removed)
    else:
        print("Total unused imports removed:", total_lines_removed)
    if total_lines_removed > 0:
        exit(1)


excluded_files = [
    "src/ledger/reed_solomon_table.zig",
    "src/ledger/test_shreds.zig",
    "src/cmd/cmd.zig",
    "src/benchmarks.zig",
    "src/geyser/main.zig",
    "src/rpc/client.zig",
    "src/rpc/request.zig",
    "src/sync/thread_pool.zig",
    "src/sync/ref.zig",
    "src/sync/channel.zig",
    "src/transaction_sender/service.zig",
    "src/transaction_sender/mock_transfer_generator.zig",
    "src/transaction_sender/transaction_pool.zig",
    "src/common/lru.zig",
    "src/common/merkle_tree.zig",
    "src/bincode/list.zig",
    "src/bincode/bincode.zig",
    "src/bincode/arraylist.zig",
    "src/bincode/shortvec.zig",
    "src/bincode/optional.zig",
    "src/time/time.zig",
    "src/bloom/bit_vec.zig",
    "src/bloom/bloom.zig",
    "src/bloom/bit_set.zig",
    "src/utils/tar.zig",
    "src/utils/allocators.zig",
    "src/utils/fmt.zig",
    "src/utils/thread.zig",
    "src/gossip/service.zig",
    "src/gossip/shards.zig",
    "src/gossip/table.zig",
    "src/gossip/message.zig",
    "src/gossip/data.zig",
    "src/gossip/ping_pong.zig",
    "src/gossip/pull_request.zig",
    "src/accountsdb/snapshots.zig",
    "src/accountsdb/genesis_config.zig",
    "src/accountsdb/cache.zig",
    "src/accountsdb/accounts_file.zig",
    "src/accountsdb/download.zig",
    "src/accountsdb/index.zig",
    "src/accountsdb/fuzz.zig",
    "src/accountsdb/bank.zig",
    "src/accountsdb/sysvars.zig",
    "src/accountsdb/swiss_map.zig",
    "src/accountsdb/fuzz_snapshot.zig",
    "src/accountsdb/db.zig",
    "src/core/account.zig",
    "src/core/epoch_schedule.zig",
    "src/core/transaction.zig",
    "src/core/shred.zig",
    "src/net/echo.zig",
    "src/net/net.zig",
    "src/ledger/meta.zig",
    "src/ledger/benchmarks.zig",
    "src/ledger/reader.zig",
    "src/ledger/tests.zig",
    "src/ledger/shredder.zig",
    "src/ledger/cleanup_service.zig",
    "src/ledger/transaction_status.zig",
    "src/ledger/shred.zig",
    "src/ledger/shred_inserter/recovery.zig",
    "src/shred_collector/service.zig",
    "src/shred_collector/shred_processor.zig",
    "src/shred_collector/repair_service.zig",
    "src/shred_collector/shred_verifier.zig",
    "src/shred_collector/shred_receiver.zig",
    "src/shred_collector/repair_message.zig",
    "src/cmd/config.zig",
    "src/tests.zig",
    "src/fuzz.zig",
    "src/geyser/core.zig",
    "src/rpc/response.zig",
    "src/sync/once_cell.zig",
    "src/sync/mux.zig",
    "src/rand/rand.zig",
    "src/prometheus/histogram.zig",
    "src/prometheus/metric.zig",
    "src/prometheus/registry.zig",
    "src/transaction_sender/leader_info.zig",
    "src/transaction_sender/transaction_info.zig",
    "src/bincode/varint.zig",
    "src/bincode/hashmap.zig",
    "src/bincode/int.zig",
    "src/bloom/bitvec.zig",
    "src/utils/types.zig",
    "src/utils/collections.zig",
    "src/gossip/fuzz_service.zig",
    "src/gossip/fuzz_table.zig",
    "src/gossip/dump_service.zig",
    "src/gossip/pull_response.zig",
    "src/gossip/active_set.zig",
    "src/core/hard_forks.zig",
    "src/core/leader_schedule.zig",
    "src/trace/log.zig",
    "src/net/socket_utils.zig",
    "src/ledger/schema.zig",
    "src/ledger/reed_solomon.zig",
    "src/ledger/result_writer.zig",
    "src/ledger/shred_inserter/slot_chaining.zig",
    "src/ledger/shred_inserter/merkle_root_checks.zig",
    "src/ledger/shred_inserter/shred_inserter.zig",
    "src/ledger/shred_inserter/working_state.zig",
    "src/ledger/database/interface.zig",
    "src/ledger/database/rocksdb.zig",
    "src/ledger/database/hashmap.zig",
    "src/shred_collector/shred_tracker.zig",
    "src/crypto/base58.zig",
    "src/cmd/helpers.zig",
]


# Enforces rows to be at most 100 characters long.
def row_size():
    files_to_check = get_files()
    unique_files = []

    lines_found = 0

    for path in files_to_check:
        if path in excluded_files:
            continue
        with open(path) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if len(line) > MAX_LINE_LENGTH:
                print(f"{path}:{i + 1} is too long: {len(line)}")
                lines_found += 1
                if path not in unique_files:
                    unique_files.append(path)
                print(line)

    print("Files checked:", len(files_to_check))
    print("Lines found:", lines_found)

    for file in unique_files:
        print(f'"{file}",')

    if lines_found > 0:
        exit(1)


checks = [
    unused_imports,
    row_size,
]

for check in checks:
    print("Running check: ", check.__name__)
    check()
