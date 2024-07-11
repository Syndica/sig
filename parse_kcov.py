import json 

# read path from cli
import sys
if len(sys.argv) != 2:
    print("Usage: python parse_kcov.py <path_to_coverage.json>")
    sys.exit(1)
coverage_path = sys.argv[1]

with open(coverage_path, "r") as f:
    coverage = json.load(f)

max_path_length = max(len(file_info["file"]) for file_info in coverage["files"])

# order by coverage percentage
coverage["files"].sort(key=lambda x: float(x["percent_covered"]), reverse=False)

output = ""
for file_info in coverage["files"]:
    path = file_info["file"]
    path = path.split("sig/")[2]
    file_coverage = float(file_info["percent_covered"])

    # Determine the color based on the coverage percentage
    if file_coverage < 50:
        color = "\033[91m"  # Red
    elif file_coverage < 75:
        color = "\033[93m"  # Yellow
    else:
        color = "\033[92m"  # Green

    # Reset color
    reset = "\033[0m"
    output += f"{color}{path:<{max_path_length}} --- {file_coverage:>10}%{reset}\n"

print(output)