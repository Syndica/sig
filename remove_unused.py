# parse arg of file name
import sys
import os
import re

if len(sys.argv) != 2:
    print("Usage: python remove_unused.py <dir name>")
    sys.exit()

zig_files = []
dirs = [sys.argv[1]]
while 1:
    d = dirs.pop()
    files = os.listdir(d)
    for file in files:
        full_path = os.path.join(d, file)
        if os.path.isdir(full_path):
            dirs.append(full_path)
        else:
            # if file ends in .zig
            if file.endswith(".zig"):
                zig_files.append(full_path)

    if len(dirs) == 0:
        break

import_line_regex = re.compile(
    r'const ([a-zA-Z0-9_]+) = (@import\("[a-zA-Z0-9_]+"\))?[a-zA-Z0-9_.]*;'
)

total_num_lines_removed = 0

for path in zig_files:
    with open(path) as f:
        orig_file = f.read()
    orig_lines = orig_file.split("\n")
    if orig_lines[-1] == "":
        orig_lines = orig_lines[0:-1]
    non_import_lines = []
    imported_names = []
    for line_num, line in enumerate(orig_lines):
        match = import_line_regex.match(line)
        if match:
            imported_names.append((match.groups()[0], line_num))
        else:
            non_import_lines.append(line)
    non_import_file = "\n".join(non_import_lines)
    lines_to_drop = set()
    num_lines_to_remove = 0
    for name in imported_names:
        if re.search(f"[^a-zA-Z0-9_]{name[0]}[^a-zA-Z0-9_]", non_import_file) is None:
            lines_to_drop.add(name[1])
            num_lines_to_remove += 1
    with open(path, "w") as f:
        f.writelines(
            f"{line}\n" for i, line in enumerate(orig_lines) if i not in lines_to_drop
        )
    lines_to_drop
    print(path, num_lines_to_remove)
    total_num_lines_removed += num_lines_to_remove

print("total lines removed:", total_num_lines_removed)
