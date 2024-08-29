"""Run all tests that match the pattern *unit_test*.py. The working directory must be the parent one of CommonLibraries"""

import sys
import pytest

if __name__ == '__main__':

    return_code = pytest.main([

        # Tests folder
        "./tests",

        # Pattern associated with the unit tests name
        "-k", "test_",

        # HTML report
        "--html=./tests/HTML/report.html",

        # Coverage report
        "--cov-report=term",
        "--cov-report=html:./tests/COVERAGE",
        "--cov-config=./tests/.coveragerc",
        "--cov=./",

        # Extra configuration
        "--disable-warnings",

    ])

    sys.exit(return_code)
