# %%
import pandas as pd
import argparse
import matplotlib.pyplot as plt
import numpy as np
import random

def random_color_generator():
    r = random.randint(0, 255)
    g = random.randint(0, 255)
    b = random.randint(0, 255)
    return (r / 255, g / 255, b / 255)

def view_results(paths, units):
    dfs = []
    benchmark_names = []
    for i, path in enumerate(paths):
        df = pd.read_csv(path, sep=",", header=None)
        if i == 0: 
            benchmark_names = df[0]
        else: 
            if not (benchmark_names == df[0]).all():
                print("Mismatched benchmark names")
                return
        dfs.append(df)
    
    colors = [random_color_generator() for _ in range(len(paths))]
    for i in range(len(benchmark_names)):
        plt.clf()
        plt.title(benchmark_names[i] + f"{units}", wrap=True)

        for df_i, df in enumerate(dfs):
            benchmark_runtimes = df.T[1:][i]
            # convert to milliseconds 
            if units == 'ms':
                benchmark_runtimes = benchmark_runtimes / 1_000_000
            if units == 's':
                benchmark_runtimes = benchmark_runtimes / 1_000_000_000

            color = colors[df_i]
            mean = np.mean(benchmark_runtimes) 
            plt.scatter(benchmark_runtimes, np.zeros_like(benchmark_runtimes), color=color, label=paths[df_i])

            var = np.var(benchmark_runtimes)
            plt.errorbar(mean, 1, xerr=np.sqrt(var), fmt='o', color=color) # mean

        plt.legend()
        output_path = f"results/{benchmark_names[i]}.png"
        plt.savefig(output_path)
        print("Saved to", output_path)

if __name__ == "__main__":
    # read cli -- either single file or multiple files
    # python scripts/view_bench.py b_results.txt b_results.txt

    # each file should be something like:
    # {benchmark_name}, {runtime1}, {runtime2}, ...
    #
    # eg,
    # % cat b_results.txt
    # benchmark1, 1, 2, 3, 4, 5
    # benchmark2, 1, 2, 3, 4, 5
    parser = argparse.ArgumentParser(description='View benchmark results.')
    parser.add_argument('files', metavar='f', type=str, nargs='+', help='an input file to process')
    # support either seconds or milliseconds
    parser.add_argument('--unit', type=str, choices=['s', 'ms'], default='ms', help='unit of time (seconds or milliseconds)')
    args = parser.parse_args()

    print("Viewing", args.files)

    # make results dir
    import os
    if not os.path.exists("results"):
        os.makedirs("results")
    view_results(args.files, args.unit)