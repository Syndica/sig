import os
import argparse
import json
import textwrap

from typer.testing import CliRunner
from test_suite.test_suite import app as solana_test_suite


def main():
    os.environ["PYTHONUNBUFFERED"] = "1"

    parser = argparse.ArgumentParser(description="Run test fixtures")
    parser.add_argument("--create", action="store_true", help="Create the fixtures from scratch")
    parser.add_argument("--skip-run", action="store_true", help="Don't run fixtures")
    parser.add_argument("--verbose", action="store_true", help="Print commands")
    parser.add_argument("--filter", default=None, help="Filter for fixture to execute")
    parser.add_argument("--save", default=None, help="File to save results")
    parser.add_argument(
        "--create-lib",
        default=path("env/solfuzz-agave/target/release/libsolfuzz_agave.so"),
        help="Select the binary used to generate fixtures",
    )
    parser.add_argument(
        "--exec-lib",
        default=path("zig-out/lib/libsolfuzz_sig.so"),
        help="Select the binary used to execute fixtures",
    )
    parser.add_argument("--num-processes", type=int, default=os.cpu_count())

    args = parser.parse_args()

    results = []
    with open(path("scripts/fixtures.txt")) as f:
        TESTS = [line.strip() for line in f if line.strip()]
    for test in TESTS:
        if args.filter and args.filter not in test:
            continue
        results.append(run_test(test, args))

    if None in results:
        assert args.skip_run
        return

    total_passed = sum(r.get("passed", 0) for r in results)
    total_failed = sum(r.get("failed", 0) for r in results)
    total_skipped = sum(r.get("skipped", 0) for r in results)

    print("\nSummary:")
    print(f"\tpassed:  {total_passed}")
    print(f"\tfailed:  {total_failed}")
    print(f"\tskipped: {total_skipped}")

    if args.save:
        with open(args.save, "w") as f:
            json.dump(results, f, indent=4)


conformance_dir = os.path.dirname(os.path.abspath(__file__))


def path(subpath):
    """Helper to get absolute path relative to the conformance directory"""
    return os.path.join(conformance_dir, subpath)


def run_test(test_vectors, config):
    print(f"\n{test_vectors}:")
    vectors_path = path(f"env/test-vectors/{test_vectors}")
    fixtures_path = path(f"env/test-fixtures/{test_vectors}")
    outputs_path = path(f"env/test-outputs/{test_vectors}")
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
                "name": test_vectors,
                "failed": 1,
            }

    if config.skip_run:
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
            "name": test_vectors,
            "failed": 1,
        }

    summary = result.stdout.split("\n")[3]
    passed = int(summary.split(",")[0].split(": ")[1])
    failed = int(summary.split(",")[1].split(": ")[1])
    skipped = int(summary.split(",")[2].split(": ")[1])

    failed_fixtures = None
    if failed > 0:
        failed_fixtures = result.stdout.split("\n")[4].strip("Failed tests: ").strip()
        failed_fixtures = json.loads(failed_fixtures.replace("'", '"'))

    print(f"\tpassed:  {passed}")
    print(f"\tfailed:  {failed}")
    print(f"\tskipped: {skipped}")

    return {
        "name": test_vectors,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "failed_fixtures": failed_fixtures,
    }


def run_command(args, verbose):
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
    return result


if __name__ == "__main__":
    main()
