import pytest
import json
import os

# Store CVSS results during test runs
_cvss_results = {}

def save_cvss_result(test_name, cvss_score, severity):
    _cvss_results[test_name] = {
        "cvss_score": cvss_score,
        "severity": severity
    }

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    
    # Attach CVSS data to the report if available
    if call.when == "call":
        test_name = item.name
        if test_name in _cvss_results:
            report.cvss_score = _cvss_results[test_name]["cvss_score"]
            report.severity = _cvss_results[test_name]["severity"]

@pytest.hookimpl(optionalhook=True)
def pytest_json_modifyreport(json_report):
    """Add CVSS scores directly into the JSON report"""
    for test in json_report.get("tests", []):
        test_name = test["nodeid"].split("::")[-1]
        if test_name in _cvss_results:
            test["cvss_score"] = _cvss_results[test_name]["cvss_score"]
            test["severity"] = _cvss_results[test_name]["severity"]