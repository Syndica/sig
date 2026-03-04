# script for checking that source files conform to the style guide

import argparse
import math
import os
import re

MAX_LINE_LENGTH = 100


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("dirs", action="append")
    arg_parser.add_argument("--check", action="store_true")
    arg_parser.add_argument("-v", "--verbose", action="store_true")
    args = arg_parser.parse_args()

    files_to_check = get_files(args)

    checks = [
        unused_imports,
        line_length,
    ]
    fails = 0
    for check in checks:
        print("Running check: ", check.__name__)
        fails += check(args, files_to_check)
    if fails:
        exit(1)


def get_files(args):
    files_to_check = []
    excluded_dirs = {
        ".git",
        ".zig-cache",
        "zig-cache",
        "zig-out",
        "__pycache__",
    }
    dirs = [*args.dirs]
    while len(dirs) > 0:
        d = dirs.pop()
        if os.path.isfile(d):
            return [d]
        files = os.listdir(d)
        for file in files:
            full_path = os.path.join(d, file)
            if os.path.isdir(full_path):
                if file in excluded_dirs:
                    continue
                dirs.append(full_path)
            else:
                if file.endswith(".zig"):
                    files_to_check.append(full_path)
    return files_to_check


def remove_line(file_contents: str, line: int) -> str:
    lines = file_contents.splitlines()
    del lines[line]
    return "\n".join(lines)


def unused_imports(args, files_to_check):
    """Checks for unused imports in files."""
    import_line_regex = re.compile(
        r'const\s+([a-zA-Z0-9_]+)\s+=\s+(@import\("[a-zA-Z0-9_./]+"\))?[a-zA-Z0-9_.]*;'
    )

    total_lines_removed = 0

    while True:
        lines_removed = 0
        for path in files_to_check:
            # get all lines of code
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
                match = re.findall(
                    f"[^a-zA-Z0-9_.]{name}[^a-zA-Z0-9_]", remove_line(orig_file, line)
                )
                if len(match) == 0:
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

    return total_lines_removed


files_excluded_from_line_length_check = [
    "src/bincode/arraylist.zig",
    "src/bincode/bincode.zig",
    "src/bincode/int.zig",
    "src/bincode/shortvec.zig",
    "src/bloom/bit_set.zig",
    "src/bloom/bit_vec.zig",
    "src/bloom/bitvec.zig",
    "src/core/leader_schedule.zig",
    "src/core/transaction.zig",
    "src/gossip/data.zig",
    "src/gossip/fuzz_service.zig",
    "src/gossip/fuzz_table.zig",
    "src/gossip/message.zig",
    "src/gossip/ping_pong.zig",
    "src/gossip/pull_request.zig",
    "src/gossip/service.zig",
    "src/gossip/shards.zig",
    "src/ledger/cleanup_service.zig",
    "src/ledger/database/hashmap.zig",
    "src/ledger/database/rocksdb.zig",
    "src/ledger/reed_solomon_table.zig",
    "src/ledger/reed_solomon.zig",
    "src/ledger/shred_inserter/working_state.zig",
    "src/ledger/shred.zig",
    "src/ledger/test_shreds.zig",
    "src/rpc/client.zig",
    "src/rpc/request.zig",
    "src/rpc/test_serialize.zig",
    "src/shred_network/collector/repair_message.zig",
    "src/shred_network/collector/repair_service.zig",
    "src/sync/thread_pool.zig",
    "src/transaction_sender/mock_transfer_generator.zig",
    "src/transaction_sender/service.zig",
    "src/transaction_sender/transaction_pool.zig",
    # Generated files, will not conform to style guide.
    "src/crypto/bn254/bn254_64.zig",
    "src/crypto/ed25519/wycheproof.zig",
]


def line_length(args, files_to_check):
    """Enforces lines of code to be at most 100 characters long."""

    # map relating file paths to the number of lines that are too long
    unique_files = {}

    lines_found = 0

    fmt_off = False
    for path in files_to_check:
        if path in files_excluded_from_line_length_check:
            continue
        with open(path) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if re.match(r"// [sz]ig fmt: off", stripped):
                fmt_off = True
            if re.match(r"// [sz]ig fmt: on", stripped):
                fmt_off = False
                continue  # Don't check lines that have formatting turned off

            if fmt_off:
                continue

            if stripped.strip().startswith(("//", "\\" + "\\")):
                continue

            code_part = line.split("//", 1)[0].rstrip()
            if len(code_part) > MAX_LINE_LENGTH + 1:  # +1 for \n
                print(f"{path}:{i + 1} is too long: {len(code_part)}")
                lines_found += 1
                if path not in unique_files:
                    unique_files[path] = 1
                else:
                    unique_files[path] += 1
                print(line)

    print("Files checked:", len(files_to_check))
    print("Lines found:", lines_found)

    # sorted_files = sorted(unique_files.items(), key=lambda x: x[1])
    # for file, num_lines in sorted_files:
    #     print(f'"{file}",')

    return lines_found


if __name__ == "__main__":
    main()
