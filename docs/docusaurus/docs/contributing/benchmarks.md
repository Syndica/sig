---
sidebar_position: 8
title: Benchmarks
---
# Benchmarks

- run all benchmarks: `./zig-out/bin/benchmark`
- filter specific cases: `./zig-out/bin/benchmark accounts_db_readwrite`
- benchmark results are written to csv in `results/`
    - this includes the average stats and the raw runtimes

### dev note

if you want to support multiple return values, you need to include BenchTimeUnits as the first parameter
to know what time unit we are expecting.

### example output

#### average stats
```
benchmark, read_time_min, read_time_max, read_time_mean, read_time_variance, benchmark, write_time_min, write_time_max, write_time_mean, write_time_variance,
readWriteAccounts(100k accounts (1_slot - ram index - ram accounts)), 172156041, 158767959, 162868245, 15183799545214, 303852750, 286908417, 292925858, 39820330697776,
readWriteAccounts(100k accounts (1_slot - disk index - ram accounts)), 165480250, 156170500, 160821658, 7611019088428, 319935833, 286708833, 304248199, 113169780175088,
```

#### raw runtimes
```
readWriteAccounts(100k accounts (1_slot - ram index - ram accounts)) (read_time), 41451000, 40685750, 41123125, 40722417, 40743667
readWriteAccounts(100k accounts (1_slot - ram index - ram accounts)) (write_time), 81834042, 75340000, 76776125, 74969958, 74682792
```

#### visualizing

```bash
./zig-out/bin/benchmark accounts_db_readwrite
# NOTE: need to format doc to below
python scripts/view_bench.py results/BenchmarkAccountsDB/readWriteAccounts_runtimes.csv # view runtimes as a charts with one file source
python scripts/view_bench.py readWriteAccounts_runtimes.csv readWriteAccounts_runtimes_2.csv # compare runtimes against two *equivalent* files
```

- format
```bash
# each file should be something like:
# {benchmark_name}, {runtime1}, {runtime2}, ...
#
# eg,
# % cat b_results.txt
# benchmark1, 1, 2, 3, 4, 5
# benchmark2, 1, 2, 3, 4, 5
```

![example_benchmark_viz](/img/bench_eg.png)
- each point on y-axis=0 is a runtime
- the point on y-axis=1 is the mean with the bar surrounding it being the standard deviation

# tracking benchmarks overtime

two main scripts are used
- `scripts/collect_benchmarks.sh` is periodically called using a cron job to run the benchmarks on new git commits
- `scripts/benchmark_server.py` is run as a server to visualize the results over time
