git_commit=$(git rev-parse HEAD)
timestamp=$(date +%s)

zig build -Doptimize=ReleaseSafe -Dno-run benchmark
./zig-out/bin/benchmark --metrics all

mkdir -p results/metrics
mv results/output.json results/metrics/output-$timestamp-$git_commit.json
