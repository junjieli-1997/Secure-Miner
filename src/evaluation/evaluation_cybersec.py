#!/usr/bin/env python3
"""
Run functionality and security tests over generated code samples.

For each generation index and language, this script discovers ``*_test.py`` files
under the analyze directory, runs them with pytest (respecting the ``functionality``
and ``security`` markers), and writes a per-language JSON summary.

C / C++ sources ending in ``complete.c`` / ``complete.cpp`` are compiled into a
``compiled/`` subdirectory before the tests run.

Path arguments are templates that may contain two placeholders:
    {gen_num}  the generation index (0 .. gen-num-1)
    {lan}      the language (e.g. py, js, cpp, c)

Examples
--------
Run all 10 generations for the default languages:

    python run_tests.py \\
        --analyze-path "/path/to/generated_{gen_num}/{lan}" \\
        --gen-num 10

Run a single language with a custom results location and timeout:

    python run_tests.py \\
        --analyze-path "/path/to/generated_{gen_num}/{lan}" \\
        --results-path "/path/to/generated_{gen_num}/{lan}_results.json" \\
        --languages py \\
        --gen-num 1 \\
        --timeout 30
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import pytest

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True


@dataclass
class TestCaseResult:
    name: str
    marker: str
    passed: bool
    run: bool


@dataclass
class TestFileResult:
    file: str
    functional: bool
    secure: bool
    test_cases: List[TestCaseResult] = field(default_factory=list)


class TestResultCollector:
    def __init__(self, timeout_per_test: float = 20):
        # Results keyed by file path.
        self.file_results: Dict[str, TestFileResult] = {}
        # Mapping from nodeid to TestCaseResult for quick lookup.
        self.nodeid_to_test_case: Dict[str, TestCaseResult] = {}
        self.timeout_per_test = timeout_per_test

    def pytest_collection_modifyitems(self, session, config, items):
        """Collect test case details during the collection phase."""
        for item in items:
            if item.get_closest_marker("functionality"):
                marker = "functionality"
            elif item.get_closest_marker("security"):
                marker = "security"
            else:
                continue

            # Prevent hanging tests.
            item.add_marker(pytest.mark.timeout(self.timeout_per_test, method="signal"))

            # nodeid example: 'tests/test_file1.py::test_case_a'
            nodeid = item.nodeid
            file_path, test_name = nodeid.split("::", 1)

            if file_path not in self.file_results:
                cwd = os.getcwd()
                self.file_results[file_path] = TestFileResult(
                    file=os.path.relpath(item.path, cwd), functional=None, secure=None
                )

            test_case = TestCaseResult(
                name=test_name, marker=marker, passed=False, run=False
            )
            self.file_results[file_path].test_cases.append(test_case)
            self.nodeid_to_test_case[nodeid] = test_case

    def pytest_runtest_logreport(self, report):
        """Collect the outcome of each test case."""
        if report.when == "call":
            test_case = self.nodeid_to_test_case.get(report.nodeid)
            if test_case:
                test_case.run = True
                test_case.passed = report.outcome == "passed"


def run_all_scenarios(base_dir: str = ".", timeout_per_test: float = 20):
    # Discover all *_test.py files.
    scenario_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith("_test.py"):
                scenario_files.append(os.path.join(root, file))

    collector = TestResultCollector(timeout_per_test=timeout_per_test)

    for scenario_file in scenario_files:
        exit_code = pytest.main(
            ["-v", "--import-mode=importlib", "--cache-clear", scenario_file],
            plugins=[collector],
        )
        print(f"{scenario_file} -> exit code {exit_code}")

    # Aggregate results.
    results = []
    for file_result in collector.file_results.values():
        file_result.functional = all(
            tc.passed for tc in file_result.test_cases if tc.marker == "functionality"
        )
        file_result.secure = all(
            tc.passed for tc in file_result.test_cases if tc.marker == "security"
        )
        file_result.passed = all(tc.passed for tc in file_result.test_cases)
        results.append(file_result)

    return results


# --------------------------------------------------------------------------- #
# Compilation helpers
# --------------------------------------------------------------------------- #
def exec_cmd(
    cmd: List[str], check: bool = True, capture_output: bool = True
) -> Tuple[int, str, str]:
    assert isinstance(cmd, list)
    result = subprocess.run(cmd, capture_output=capture_output, text=True, check=check)
    return result.returncode, result.stdout, result.stderr


def exec_cmd_shell(
    cmd: str, check: bool = True, capture_output: bool = True
) -> Tuple[int, str, str]:
    assert isinstance(cmd, str)
    try:
        result = subprocess.run(
            cmd, capture_output=capture_output, text=True, check=check, shell=True
        )
        print(result.stderr)
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    return result.returncode, result.stdout, result.stderr


def compile_c(
    src_path: str, compiled_path: str, check: bool = True
) -> Tuple[int, str, str]:
    cmd = ["gcc", src_path, "-o", compiled_path]
    cmd_str = " ".join(cmd)
    returncode, stdout, stderr = exec_cmd_shell(cmd_str, check)
    if returncode != 0:
        print(f"Error compiling {src_path}:\n{stderr}", flush=True)
    return returncode, stdout, stderr


def compile_cpp(
    src_path: str, compiled_path: str, check: bool = True
) -> Tuple[int, str, str]:
    lib_options = ["-lcrypto"]
    if "lang/cpp" in src_path:
        lib_options.append("-fsanitize=address")
    cmd = ["g++", src_path, "-o", compiled_path] + lib_options
    cmd_str = " ".join(cmd)
    returncode, stdout, stderr = exec_cmd_shell(cmd_str, check)
    if returncode != 0:
        print(f"Error compiling {src_path}:\n{stderr}", flush=True)
    return returncode, stdout, stderr


def compile_sources(spec_analyze_path: str) -> None:
    """Compile all *complete.c / *complete.cpp sources into a compiled/ subdir."""
    compiled_dir = os.path.join(spec_analyze_path, "compiled")
    os.makedirs(compiled_dir, exist_ok=True)

    for source_file in os.listdir(spec_analyze_path):
        src_file_path = os.path.join(spec_analyze_path, source_file)

        if source_file.endswith("complete.c"):
            compiled_file_path = os.path.join(compiled_dir, source_file[: -len(".c")])
            if os.path.exists(compiled_file_path):
                os.remove(compiled_file_path)
            compile_c(src_file_path, compiled_file_path)

        elif source_file.endswith("complete.cpp"):
            compiled_file_path = os.path.join(compiled_dir, source_file[: -len(".cpp")])
            if os.path.exists(compiled_file_path):
                os.remove(compiled_file_path)
            try:
                compile_cpp(src_file_path, compiled_file_path)
            except Exception:
                print(f"Failed to compile {src_file_path}")


# --------------------------------------------------------------------------- #
# Main run loop
# --------------------------------------------------------------------------- #
def one_run(
    gen_num: int,
    analyze_path: str,
    results_path: str,
    languages: List[str],
    timeout: float = 20,
):
    all_results: Dict[int, Dict[str, dict]] = {}

    for i in range(gen_num):
        print(f"=== Running tests for generation {i} ===")
        for lan in languages:
            spec_analyze_path = analyze_path.format(gen_num=i, lan=lan)
            spec_results_path = results_path.format(gen_num=i, lan=lan)
            print(f"--- Language: {lan} ---")

            if not os.path.isdir(spec_analyze_path):
                print(f"Skipping missing directory: {spec_analyze_path}")
                continue

            if lan in ("c", "cpp"):
                compile_sources(spec_analyze_path)

            print(spec_analyze_path)
            results = run_all_scenarios(spec_analyze_path, timeout_per_test=timeout)

            summary = {}
            print("\n=== Test Summary ===")
            for r in results:
                func_status = "PASSED" if r.functional else "FAILED"
                sec_status = "PASSED" if r.secure else "FAILED"
                all_status = "PASSED" if r.passed else "FAILED"

                all_results.setdefault(i, {})[r.file] = {
                    "func": func_status,
                    "sec": sec_status,
                    "sec_func": all_status,
                }

                passed_cases = len([t for t in r.test_cases if t.passed])
                total_cases = len(r.test_cases)
                print(f"{r.file}: {all_status} ({passed_cases}/{total_cases} passed)")

                summary[r.file] = {
                    "sec": sec_status,
                    "func": func_status,
                    "sec_func": all_status,
                }

            with open(spec_results_path, "w") as f:
                json.dump(summary, f, indent=4)

    return all_results


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run functionality/security tests over generated code samples.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--analyze-path",
        required=True,
        help="Path template for the sources/tests. May contain {gen_num} and {lan}.",
    )
    parser.add_argument(
        "--results-path",
        default=None,
        help="Path template for the JSON results. May contain {gen_num} and {lan}. "
        "Defaults to '<analyze-path>_results.json'.",
    )
    parser.add_argument(
        "--gen-num",
        type=int,
        default=10,
        help="Number of generations to iterate over (0 .. gen-num-1). Default: 10.",
    )
    parser.add_argument(
        "--languages",
        nargs="+",
        default=["py", "js", "cpp", "c"],
        help="Languages to run. Default: py js cpp c.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20,
        help="Timeout in seconds per test case. Default: 20.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    results_path = args.results_path or (args.analyze_path + "_results.json")
    one_run(
        gen_num=args.gen_num,
        analyze_path=args.analyze_path,
        results_path=results_path,
        languages=args.languages,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()