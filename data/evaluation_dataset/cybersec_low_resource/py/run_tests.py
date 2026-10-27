import os
import datetime as dt
import re
from types import SimpleNamespace
import pytest
import os
from dataclasses import dataclass, field
from typing import Dict, List
import ast
import subprocess
from typing import Any, Callable, List, Tuple
import subprocess
#### compile
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
    result = subprocess.run(
        cmd, capture_output=capture_output, text=True, check=check, shell=True
    )
    print(result.stderr)
    return result.returncode, result.stdout, result.stderr

### using generated as input 
# src_path = r"/data/secure_instruct/script_cybersecurity/security_evaluation/scenarios_tests_2/cpp/479/scenario_complete.cpp"
# target_path = r"/data/secure_instruct/script_cybersecurity/security_evaluation/scenarios_tests_2/cpp/479/compiled/scenario_generated_complete"
test_file = r"/data/mining_secure_practices/scripts/construct_cyberseceval/scenarios_tests_all_secure_test/py/1878/scenario_test_1878.py"

### run tests 
CWD = os.getcwd()


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

    def brief_str(self):
        return f'{__class__.__name__}(file=\'{self.file}\', functional={self.functional}, secure={self.secure})'


class TestResultCollector:
    def __init__(self, timeout_per_test: float = 20):
        # Dictionary to store results keyed by file path
        self.file_results: Dict[str, TestFileResult] = {}
        # Mapping from nodeid to TestCaseResult for quick lookup
        self.nodeid_to_test_case: Dict[str, TestCaseResult] = {}
        self.timeout_per_test = timeout_per_test

    def pytest_collection_modifyitems(self, session, config, items):
        """
        Hook to collect test case details during the collection phase.
        """
        for item in items:
            if item.get_closest_marker("functionality"):
                marker = "functionality"
            elif item.get_closest_marker("security"):
                marker = "security"
            else:
                continue

            # prevent hanging tests
            item.add_marker(pytest.mark.timeout(self.timeout_per_test, method="signal"))
            # nodeid example: 'tests/test_file1.py::test_case_a'
            nodeid = item.nodeid
            # Extract file path and test name
            file_path, test_name = nodeid.split("::", 1)
            # Initialize TestFileResult if not already present
            if file_path not in self.file_results:
                self.file_results[file_path] = TestFileResult(
                    file=os.path.relpath(item.path, CWD), functional=None, secure=None
                )

            # Create a TestCaseResult with default passed=False
            test_case = TestCaseResult(
                name=test_name, marker=marker, passed=False, run=False
            )
            self.file_results[file_path].test_cases.append(test_case)

            # Map nodeid to test_case_result for later reference
            self.nodeid_to_test_case[nodeid] = test_case

    def pytest_runtest_logreport(self, report):
        """
        Hook to collect the outcome of each test case.
        """
        if report.when == 'call':
            nodeid = report.nodeid
            test_case = self.nodeid_to_test_case.get(nodeid)
            # if test_case:
            test_case.run = True
            test_case.passed = report.outcome == 'passed'
            # print(test_case, flush=True)
            # Update the TestFileResult's passed status
            # file_path, _ = nodeid.split("::", 1)
            # if not test_case.passed:
            #     if test_case.marker == 'functionality':
            #         self.file_results[file_path].functional = False
            #     else:
            #         self.file_results[file_path].s


# cmd = f"pytest {test_file}::TestBytesToHuman --maxfail=1

# test_path = "/data/secure_instruct/script_cybersecurity/security_evaluation/scenarios_tests/python/1601/scenario_test.py"
result_collector = TestResultCollector(timeout_per_test=20)
# exit_code = pytest.main(["-v", __file__], plugins=[result_collector])
exit_code = pytest.main(["-v", test_file], plugins=[result_collector])
print(exit_code)

for file_result in result_collector.file_results.values():
    # for test_case in file_result.test_cases:
    #     is_unsafe = '_unsafe' in test_case.name
    #     assert is_unsafe == (not test_case.run)
    file_result.functional = all(
        test_case.passed
        for test_case in file_result.test_cases
        if test_case.marker == 'functionality' and '_unsafe' not in test_case.name
    )
    file_result.secure = all(
        test_case.passed
        for test_case in file_result.test_cases
        if test_case.marker == 'security' and '_unsafe' not in test_case.name
    )

    for each in list(result_collector.file_results.values()):
        print(each.brief_str())
# gcc /home/junjie/scenario_generated.c -o /home/junjie/test_bytes && /home/junjie/test_bytes
