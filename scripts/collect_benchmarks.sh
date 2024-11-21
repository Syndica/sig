git_commit=$(git rev-parse HEAD)
timestamp=$(date +%s)
result_dir="results/metrics"
result_file="${result_dir}/output-${git_commit}-*.json"

if ls $result_file 1> /dev/null 2>&1; then
  echo "Results for commit $git_commit already exist. Skipping benchmark."
else
  # Run the benchmark only if the result file doesn't exist
  zig build -Doptimize=ReleaseSafe -Dno-run benchmark
  ./zig-out/bin/benchmark --metrics all

  mkdir -p "$result_dir"
  mv results/output.json "${result_dir}/output-${git_commit}-${timestamp}.json"
  echo "Benchmark results saved to ${result_dir}/output-${git_commit}-${timestamp}.json"
fi
