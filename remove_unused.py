# parse arg of file name 
import sys
import os

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
            if file.endswith('.zig'):
                zig_files.append(full_path)

    if len(dirs) == 0: 
        break 

total_removes = 0
n_remove_iter = 0
n_removes = 1
while n_removes > 0:
    n_removes = 0
    print(f"iteration: {n_remove_iter}, lines removed: {n_removes}")
    n_remove_iter += 1

    for filename in zig_files:
        print(filename)

        # open and read lines of file 
        with open(filename, 'r') as f:
            full_lines = f.readlines()

        # parse the value {VAR} name in 'const {VAR} = @import ...' 
        import_var_names = []
        for (i, line) in enumerate(full_lines):
            if not (line.startswith('const') or line.startswith('pub const')):
                continue 

            if '@import' not in line:
                continue

            start_index = line.index("const ")
            end_index = line.index(" = ")
            var_name = line[start_index + 6:end_index]
            import_var_names.append((var_name, i))

        unused_vars = import_var_names.copy()
        for i, line in enumerate(full_lines):

            for var, line_num in import_var_names: 
                if (var in line) and (i != line_num):
                    if (var, line_num) in unused_vars:
                        unused_vars.remove((var, line_num))

        new_lines = []
        lines_to_remove = [i for (_, i) in unused_vars]
        n_removes += len(lines_to_remove)
        total_removes += len(lines_to_remove)

        for (i, line) in enumerate(full_lines): 
            if i in lines_to_remove: 
                continue
            new_lines.append(line)

        if (len(lines_to_remove) > 0): 
            print(filename) 
            print(unused_vars)

        # write 
        with open(filename, 'w') as f:
            f.writelines(new_lines)

print("total iterations: ", n_remove_iter)
print("total lines removed: ", total_removes)
            