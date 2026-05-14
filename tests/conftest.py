import pytest
import os

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Store CVSS results during test runs
_cvss_results = {}
_scenario_names = {}

def save_cvss_result(request, cvss_score, severity):
    _cvss_results[request.node.name] = {
        "cvss_score": cvss_score,
        "severity": severity
    }

def pytest_bdd_after_scenario(request, feature, scenario):
    _scenario_names[request.node.name] = {
        "feature": feature.name,
        "scenario": scenario.name,
        "scenario_description": scenario.description,
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
        
        if test_name in _scenario_names:
            test["feature"] = _scenario_names[test_name]["feature"]
            test["scenario"] = _scenario_names[test_name]["scenario"]
            test["scenario_description"] = _scenario_names[test_name]["scenario_description"]

# settings for page from pytest-playwright plugin
@pytest.fixture(scope="session") 
def browser_launch_options():
    return {
        "args": ["--no-sandbox", "--disable-dev-shm-usage"] if os.getenv("CI") else []
    }