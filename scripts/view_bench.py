# %%
import pandas as pd
import argparse
import matplotlib.pyplot as plt
import numpy as np
import random


def random_color_generator():
    # take [r, g, b] from colormap
    # Dark2 chosen for visibility from
    # https://matplotlib.org/stable/users/explain/colors/colormaps.html#qualitative
    return plt.colormaps["Dark2"](random.random())[:3]


def view_results(paths):
    path = paths[0]
    # split the path and filename
    output_path_dir = path.split("/")
    if len(output_path_dir) == 1:
        output_path_dir = "."
    else:
        output_path_dir = "/".join(output_path_dir[:-1])
    print("outputing to", path)

    dfs = []
    benchmark_names = []
    for i, path in enumerate(paths):
        # NOTE: make sure format() has been run
        df = pd.read_csv(path, sep=",", header=None)
        # [2:] so we remove the format header and the benchmark header
        df = df.iloc[2:].reset_index()
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
        plt.title(benchmark_names[i], wrap=True)

        for df_i, df in enumerate(dfs):
            # remove the header and the benchmark name
            benchmark_runtimes = df.T[2:][i]
            benchmark_runtimes.replace("", np.nan, inplace=True)
            benchmark_runtimes.replace(" ", np.nan, inplace=True)
            benchmark_runtimes.dropna(inplace=True)
            benchmark_runtimes = benchmark_runtimes.to_numpy().astype(int)

            color = colors[df_i]
            mean = np.mean(benchmark_runtimes)
            plt.scatter(
                benchmark_runtimes,
                np.zeros_like(benchmark_runtimes),
                color=color,
                label=paths[df_i],
            )

            var = np.var(benchmark_runtimes)
            plt.errorbar(mean, 1, xerr=np.sqrt(var), fmt="o", color=color)  # mean

        plt.legend()
        output_path = f"{output_path_dir}/{benchmark_names[i]}.png"
        plt.savefig(output_path)
        print("Saved to", output_path)


# makes the files readable by pandas
def format(paths):
    for path in paths:
        # count number of separators in each line
        # then create new header line with that many separators and increasing numbers
        # overwrite the file
        with open(path, "r") as file:
            lines = file.readlines()

        # if already formatted, skip
        if lines[0].startswith("formatted"):
            continue

        i = 0
        for _ in range(len(lines)):
            # remove log lines
            if "time=" in lines[i]:
                lines.remove(lines[i])
            else:
                i += 1

        max_separators = 0
        for line in lines:
            max_separators = max(max_separators, line.count(","))

        header = (
            "formatted, " + ",".join(str(i) for i in range(max_separators + 1)) + "\n"
        )
        lines.insert(0, header)

        print("Formatted", path)
        with open(path, "w") as file:
            file.writelines(lines)


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
    parser = argparse.ArgumentParser(description="View benchmark results.")
    parser.add_argument(
        "files", metavar="f", type=str, nargs="+", help="an input file to process"
    )
    args = parser.parse_args()

    print("Viewing", args.files)

    # make results dir
    import os

    if not os.path.exists("results"):
        os.makedirs("results")

    format(args.files)
    view_results(args.files)
