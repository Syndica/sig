import json 

coverage_path = "kcov-output/fuzz/coverage.json"
with open(coverage_path, "r") as f:
    coverage = json.load(f)

max_path_length = max(len(file_info["file"]) for file_info in coverage["files"])

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