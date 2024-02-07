"""
At one point, the sig csv files were messed up,
with line breaks occurring in the wrong place.
This reformats those files to be the correct csv.
"""

import sys

input_filename = sys.argv[1]

xf = input_filename.split(".")
assert len(xf) == 2 and xf[1] == "csv"
output_filename = xf[0] + "-fixed.csv"

fixed_data = None

with open(input_filename) as broken_f:
    fixed = []
    broken = broken_f.read()
    searching = False
    for i, char in enumerate(broken):
        if searching and char.isalpha():
            fixed.append("\n")
            searching = False
        if char == "\n":
            searching = True
        else:
            fixed.append(char)
    fixed_data = "".join(fixed)


with open(output_filename, "w") as fixed_f:
    fixed_f.write(fixed_data)
