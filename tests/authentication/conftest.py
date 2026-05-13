import pytest
import pytest_bdd
import string
import random
import mysql.connector
import requests
import base64

from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from typing import Generator
from playwright.sync_api import Page
from pytest import FixtureRequest
from tests.utils import O3_BASE_URL, O3_API_URL

### SHARED STEPS ###

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def given_login_page_shown(page:Page):
    page.goto(O3_BASE_URL + '/login')
    page.wait_for_url(O3_BASE_URL + '/login')

### SHARED FUNCATIONALITY ###

# generate random passwords
def random_password(length=8):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def login(page:Page, username, password):
    page.wait_for_selector("#username")
    page.fill("#username", username)
    page.keyboard.press("Enter")
    page.wait_for_timeout(500)
    page.wait_for_selector("#password")
    page.fill("#password", password)
    page.keyboard.press("Enter")
    page.wait_for_timeout(500)

def login_api(username, password):
    
    isAuthenticated = False
    
    credentials = base64.b64encode(f'{username}:{password}'.encode()).decode()
    headers = {
        'Authorization': f'Basic {credentials}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(O3_API_URL, headers=headers, timeout=10)
        status_code = response.status_code

        if status_code == 200:
            try:
                print(response.text[:200])
                data = response.json()
                authenticated = data.get('authenticated', False)
                if authenticated:
                    print(f"  Result: Login SUCCEEDED (unexpected!) HTTP {status_code}")
                    
                    isAuthenticated = True
                else:
                    print(f"  Result: Login FAILED (expected) HTTP {status_code}")
            except:
                print(f"  Result: HTTP {status_code} (could not parse response)")
        else:
            print(f"  Result: HTTP {status_code}")

    except requests.exceptions.RequestException as e:
        print(f"  Result: Request failed - {e}")
    
    return isAuthenticated

### PYTEST FIXTURES ###

@pytest.fixture(scope="function")
def login_data():
    return {}

# Database access
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

@pytest.fixture(scope="function")
def cleanup_clear_user_lockout(request:FixtureRequest, cursor:MySQLCursor, connection:MySQLConnection):
    
    # get account to clear lockout
    # expects a string
    lockoutAccount:str = request.param
    
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