import pytest
import html
import os

from playwright.sync_api import sync_playwright
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Store CVSS results during test runs
_cvss_results = {}
_scenario_names = {}

@pytest.fixture(scope="function")
def new_page():
    """Setup Playwright browser for testing"""
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless= True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
            ] if os.getenv('CI') else []
        )
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(30000)
        
        yield page
        
        context.close()
        browser.close()

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

def pytest_html_results_table_row(report, cells):
    # This hook changes the names of the tests to sanatize them for possible XSS strings
    # The second parameter is the test name with parameter
    
    cellTestName : str = cells[1]
    
    # remove the <td class="col-testId"> and </td> from front and back
    tags = ['<td class="col-testId">','</td>']
    
    cellTestName = cellTestName.replace(tags[0], '')
    cellTestName = cellTestName.replace(tags[1], '')
    
    # sanatize
    cellTestName = html.escape(cellTestName, quote=True)
    
    # Add td tags back
    cells[1] = tags[0] + cellTestName + tags[1]