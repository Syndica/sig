#!/usr/bin/env python3.11

import argparse
import json
import os
import shlex
import sys
import textwrap

from collections import defaultdict

conformance_dir = os.path.dirname(os.path.abspath(__file__))

try:
    from typer.testing import CliRunner
    from test_suite.test_suite import app as solana_test_suite
except:
    print(
        textwrap.dedent(
            f"""
          ERROR - Could not import the testing libraries. Do you have a valid active virtual environment?

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

    create_lib = os.environ.get(
        "CREATE_LIB", path("env/solfuzz-agave/target/release/libsolfuzz_agave.so")
    )
    exec_lib = os.environ.get("EXEC_LIB", path("zig-out/lib/libsolfuzz_sig.so"))

    parser = argparse.ArgumentParser(description="Run test fixtures")
    parser.add_argument(
        "fixtures",
        nargs="*",
        default=shlex.split(os.environ["FIXTURES"]) if "FIXTURES" in os.environ else [],
        help="Fixtures to run. Defaults to FIXTURES env var. Runs all if unset.",
    )
    parser.add_argument("--create", action="store_true", help="Create the fixtures from scratch")
    parser.add_argument("--no-run", action="store_true", help="Don't exec fixtures (only create)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print commands and output")
    parser.add_argument("--filter", help="Filter for fixture to execute")
    parser.add_argument("--save", help="File to save results in json")
    parser.add_argument(
        "--create-lib",
        default=create_lib,
        help=f"Default: CREATE_LIB env var if set, otherwise: {create_lib}",
    )
    parser.add_argument(
        "-x",
        "--exec-lib",
        default=exec_lib,
        help=f"Default: EXEC_LIB env var if set, otherwise: {exec_lib}",
    )
    parser.add_argument("--num-processes", type=int, default=os.cpu_count())
    parser.add_argument(
        "--run-separately",
        action="store_true",
        help="Run each fixture with a separate invocation of solana-test-suite. "
        "This makes it easier to see which fixture caused a panic, but takes longer.",
    )

    config = parser.parse_args()

    results = []
    if config.fixtures:
        line_length = max(len(test) for test in config.fixtures)
        for fixture in config.fixtures:
            results.append(run_test(fixture, config, len(fixture)))
    else:
        with open(path("scripts/fixtures.txt")) as f:
            TESTS = [line.strip() for line in f if line.strip()]
        line_length = max(len(test) for test in TESTS)
        for test in TESTS:
            if config.filter and config.filter not in test:
                continue
            results.append(run_test(test, config, line_length))

    if None in results:
        assert config.no_run
        return

    total_passed = sum(r.get("passed", 0) for r in results)
    total_failed = sum(r.get("failed", 0) for r in results)
    total_skipped = sum(r.get("skipped", 0) for r in results)

    print("\nSummary:")
    print(f"\tPassed:  {total_passed}")
    print(f"\tFailed:  {total_failed}")
    print(f"\tSkipped: {total_skipped}")

    if config.save:
        with open(config.save, "w") as f:
            json.dump(results, f, indent=4)


def path(path):
    """Get absolute path relative to the conformance directory"""
    return os.path.join(conformance_dir, path)


def run_test(vectors, config, pad):
    if not config.run_separately:
        print_noln(f"{vectors:<{pad}}")
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
        print(f" │ Fixture(s) generated.")
        return None

    if config.run_separately:
        result = {
            "name": vectors,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "failed_fixtures": [],
        }
        filenames = sorted(os.listdir(fixtures_path))
        pad = max(len(os.path.join(vectors, f)) for f in filenames)
        for fixture in filenames:
            print_noln(f"{os.path.join(vectors, fixture):<{pad}}")
            fixture_path = os.path.join(fixtures_path, fixture)
            one_result = exec_fixtures(config, fixture_path, outputs_path)
            result["passed"] += one_result.get("passed", 0)
            result["failed"] += one_result.get("failed", 0)
            result["skipped"] += one_result.get("skipped", 0)
            result["failed_fixtures"].extend(one_result.get("failed_fixtures", []))
        return result
    else:
        result = exec_fixtures(config, fixtures_path, outputs_path)
        result["name"] = vectors
        return result


def exec_fixtures(config, fixtures_path, outputs_path):
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
        return {"failed": 1}

    summary = result.stdout.split("\n")[3]
    passed = int(summary.split(",")[0].split(": ")[1])
    failed = int(summary.split(",")[1].split(": ")[1])
    skipped = int(summary.split(",")[2].split(": ")[1])

    print(f" │ Pass{passed:>5} │ Fail{failed:>5} │ Skip{skipped:>5}")

    failed_fixtures = []
    if failed > 0:
        failed_fixtures = result.stdout.split("\n")[4].strip("Failed tests: ").strip()
        failed_fixtures = json.loads(failed_fixtures.replace("'", '"'))

    return {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "failed_fixtures": failed_fixtures,
    }


def print_noln(string):
    """
    Equivalent to `print(string, end="")` but flushes immediately. This allows
    us to see which test causes a panic before the full test line is printed.
    """
    sys.stdout.write(string)
    sys.stdout.flush()


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
