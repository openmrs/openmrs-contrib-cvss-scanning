import pytest
import html
import os

from dotenv import load_dotenv

import mysql.connector
from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from typing import Generator
from pytest import FixtureRequest

# Load environment variables
load_dotenv()

# Store CVSS results during test runs
_cvss_results = {}
_scenario_names = {}

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