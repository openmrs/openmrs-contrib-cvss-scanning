import pytest
import pytest_bdd
import html
import os

from dotenv import load_dotenv

import mysql.connector
from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from typing import Generator
from pytest import FixtureRequest
from tests.utils import login_and_select_default_location, DEFAULT_WAIT_TIME, O3_BASE_URL, O3_ROOT_URL
from playwright.sync_api import Page

# Load environment variables
load_dotenv()

# Store CVSS results during test runs
_cvss_results = {}
_scenario_names = {}
_test_params = {}

@pytest.fixture(scope="session")
def connection():
    connection : MySQLConnection = mysql.connector.connect(
        host="localhost",
        port=3306,
        user="root",
        password="openmrs",
        database="openmrs"
    )
    
    yield connection
    connection.close()

@pytest.fixture
def cursor(connection:MySQLConnection) -> Generator[MySQLCursor, None, None]:
    cursor : MySQLCursor = connection.cursor(dictionary=True)
    yield cursor
    connection.rollback()
    cursor.close()

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

@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    if hasattr(item, "callspec"):
        _test_params[item.name] = dict(item.callspec.params)

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
        
        if test_name in _test_params:
            test["params"] = _test_params[test_name]
        else:
            test["params"] = {}

# settings for page from pytest-playwright plugin
@pytest.fixture(scope="session") 
def browser_launch_options():
    return {
        "args": ["--no-sandbox", "--disable-dev-shm-usage"] if os.getenv("CI") else []
    }

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

@pytest.fixture(scope="function")
def cleanup_clear_user_lockout(request:FixtureRequest, cursor:MySQLCursor, connection:MySQLConnection):
    
    # get account to clear lockout
    # expects a string
    if hasattr(request, 'param'):
        lockoutAccount:str = request.param
    else:
        # if parametrizing, use username as parameter name
        lockoutAccount:str = request.getfixturevalue('username')
        
    # if the username is admin, the database treats this as an empty string
    lockoutAccount = "" if lockoutAccount == "admin" else lockoutAccount
    
    yield
        
    # https://openmrs.atlassian.net/wiki/spaces/docs/pages/25477734/Administering+Users#Managing-User-Lockout
    
    # clear number of attempts
    # clear last attempted time
    
    delete_login_attempts = """
    DELETE user_property
    FROM user_property
    JOIN users ON users.user_id = user_property.user_id
    WHERE user_property.property = 'loginAttempts'
    AND users.username = %s;
    """
    
    delete_lockout_timestamp = """
    DELETE user_property
    FROM user_property
    JOIN users ON users.user_id = user_property.user_id
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = %s;
    """
    
    delete_last_login_timestamp = """
    DELETE user_property
    FROM user_property
    JOIN users ON users.user_id = user_property.user_id
    WHERE user_property.property = 'lastLoginTimestamp'
    AND users.username = %s;
    """
        
    cursor.execute(delete_login_attempts, [lockoutAccount])
    cursor.execute(delete_lockout_timestamp, [lockoutAccount])
    cursor.execute(delete_last_login_timestamp, [lockoutAccount])
    
    # commit to db
    connection.commit()

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def given_login_page_shown(page:Page):
    page.goto(O3_BASE_URL + '/login')
    page.wait_for_url(O3_BASE_URL + '/login')

@pytest_bdd.when('a user logs in to the login page with the correct credentials')
def when_a_user_logs_in_to_the_login_page_with_the_correct_credentials(page:Page, username, password):
    
    login_and_select_default_location(page, username, password)

@pytest_bdd.step('the user logs out of their account')
def given_user_logs_out(page:Page):
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_role("button", name="My Account").click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_role("button", name="Logout").click()
@pytest.fixture(scope="function")

def cleanup_delete_patient(patient_data, page:Page):    
    yield
    
    patient_ids:list = patient_data["patient_id"]
    
    for i in range(0, len(patient_ids)):
    
        patient_id:str = patient_ids[i]
        
        # go to legacy admin
        page.goto(f"{O3_ROOT_URL}admin/patients/index.htm")

        # delete patient
        page.locator("#inputNode").press_sequentially(patient_id)
        
        page.wait_for_timeout(DEFAULT_WAIT_TIME)
        
        page.get_by_text(patient_id).all()[1].click()
        
        page.wait_for_timeout(DEFAULT_WAIT_TIME)
        
        page.locator("[name='voidReason']").press_sequentially("Testing Purposes")
        
        page.get_by_role("button", name="Delete Patient", exact=True).click()
        
        page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest.fixture(scope="function")
def patient_data():
    return {
        "patient_id":[]
    }
