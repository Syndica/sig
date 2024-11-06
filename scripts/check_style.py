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

# Enforces rows to be at most 100 characters long.
def row_size():
    files_to_check = get_files()

    lines_found = 0

    for path in files_to_check:
        with open(path) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if len(line) > MAX_LINE_LENGTH:
                print(f"{path}:{i + 1} is too long: {len(line)}")
                lines_found += 1
                print(line)

    print("Files checked:", len(files_to_check))
    print("Lines found:", lines_found)

checks = [
    unused_imports,
    row_size,
]

for check in checks:
    print("Running check: ", check.__name__)
    check()