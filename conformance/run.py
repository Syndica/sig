#!/usr/bin/env python3.11

import os
import argparse
import json
import textwrap

conformance_dir = os.path.dirname(os.path.abspath(__file__))


try:
    from typer.testing import CliRunner
    from test_suite.test_suite import app as solana_test_suite
except:
    print(
        textwrap.dedent(
            f"""
          To create the environment:

              {conformance_dir}/scripts/setup-env.sh

          To activate the environment:

              source {conformance_dir}/env/pyvenv/bin/activate

          """
        )
    )
    raise


def main():
    os.environ["PYTHONUNBUFFERED"] = "1"

    agave = path("env/solfuzz-agave/target/release/libsolfuzz_agave.so")
    sig = path("zig-out/lib/libsolfuzz_sig.so")

    parser = argparse.ArgumentParser(description="Run test fixtures")
    parser.add_argument("fixtures", nargs="*", help="Fixtures to run. Runs all if unspecified")
    parser.add_argument("--create", action="store_true", help="Create the fixtures from scratch")
    parser.add_argument("--no-run", action="store_true", help="Don't exec fixtures (only create)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print commands and output")
    parser.add_argument("--filter", help="Filter for fixture to execute")
    parser.add_argument("--save", help="File to save results in json")
    parser.add_argument("--create-lib", default=agave, help=f"Default: {agave}")
    parser.add_argument("--exec-lib", default=sig, help=f"Default: {sig}")
    parser.add_argument("--num-processes", type=int, default=os.cpu_count())

    args = parser.parse_args()

    results = []
    if args.fixtures:
        line_length = max(len(test) for test in args.fixtures)
        for fixture in args.fixtures:
            results.append(run_test(fixture, args, len(fixture)))
    else:
        with open(path("scripts/fixtures.txt")) as f:
            TESTS = [line.strip() for line in f if line.strip()]
        line_length = max(len(test) for test in TESTS)
        for test in TESTS:
            if args.filter and args.filter not in test:
                continue
            results.append(run_test(test, args, line_length))

    if None in results:
        assert args.no_run
        return

    total_passed = sum(r.get("passed", 0) for r in results)
    total_failed = sum(r.get("failed", 0) for r in results)
    total_skipped = sum(r.get("skipped", 0) for r in results)

    print("\nSummary:")
    print(f"\tPassed:  {total_passed}")
    print(f"\tFailed:  {total_failed}")
    print(f"\tSkipped: {total_skipped}")

    if args.save:
        with open(args.save, "w") as f:
            json.dump(results, f, indent=4)


def path(path):
    """Get absolute path relative to the conformance directory"""
    return os.path.join(conformance_dir, path)


def run_test(vectors, config, line_length):
    print(f"{vectors}" + " " * (1 + line_length - len(vectors)), end="")
    vectors_path = path(f"env/test-vectors/{vectors}")
    fixtures_path = path(f"env/test-fixtures/{vectors}")
    outputs_folder = os.path.dirname(vectors) if vectors.endswith(".fix") else vectors
    outputs_path = path(f"env/test-outputs/{outputs_folder}")
    if not os.path.exists(vectors_path):
        os.makedirs(fixtures_path, exist_ok=True)

    if config.create:
        # fmt: off
        result = run_command([
            "create-fixtures",
                "--num-processes", config.num_processes,
                "-i", vectors_path,
                "-o", fixtures_path,
                "-s", config.create_lib,
            ],
            verbose=config.verbose,
        )
        # fmt: on
        if result.exit_code != 0:
            return {
                "name": vectors,
                "failed": 1,
            }

    if config.no_run:
        return None

    # fmt: off
    result = run_command([
        "exec-fixtures",
            "--num-processes", config.num_processes,
            "-i", fixtures_path,
            "-t", config.exec_lib,
            "-o", outputs_path,
        ],
        verbose=config.verbose,
    )
    # fmt: on
    if result.exit_code != 0:
        return {
            "name": vectors,
            "failed": 1,
        }

    summary = result.stdout.split("\n")[3]
    passed = int(summary.split(",")[0].split(": ")[1])
    failed = int(summary.split(",")[1].split(": ")[1])
    skipped = int(summary.split(",")[2].split(": ")[1])

    print("│ Pass{:>5} │ Fail{:>5} │ Skip{:>5}".format(passed, failed, skipped))

    failed_fixtures = None
    if failed > 0:
        failed_fixtures = result.stdout.split("\n")[4].strip("Failed tests: ").strip()
        failed_fixtures = json.loads(failed_fixtures.replace("'", '"'))

    return {
        "name": vectors,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "failed_fixtures": failed_fixtures,
    }


def run_command(args, verbose=False, show_output=False):
    str_args = [str(c) for c in args]
    cmd_to_show = f"solana-test-suite " + " ".join(str_args)
    if verbose:
        print("\n" + cmd_to_show)
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(
        solana_test_suite,
        str_args,
        standalone_mode=False,
        catch_exceptions=False,
    )
    if result.exit_code != 0:
        inject_command = ":\n" if verbose else f":\n\n  {cmd_to_show}\n\n"
        print(f"command failed{inject_command}{result.stdout}\n{result.stderr}")
    elif verbose:
        print(f"{result.stdout}\n{result.stderr}")
    return result


if __name__ == "__main__":
    main()
