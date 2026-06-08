import pytest
import pytest_bdd
import string
import random
import requests
import base64

from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from playwright.sync_api import Page
from tests.utils import O3_BASE_URL, O3_API_URL, DEFAULT_WAIT_TIME, login

### SHARED STEPS ###

@pytest_bdd.given('the REST API is locked out from 7 failed login attempts')
def given_the_rest_api_is_locked_out_from_7_failed_login_attempts():

    for i in range(0,8):
        login_api("doctor", f"BADPASS{i}")
    
    # checks the lockout
    assert login_api("doctor", "Doctor123") == False

@pytest_bdd.given('the login page is locked out from 7 failed login attempts')
def given_the_login_page_is_locked_out_from_7_failed_login_attempts(page:Page):
    
    for i in range(0,8):
        login(page, "doctor", f"BADPASS{i}")
    
    login(page, "doctor", "Doctor123")
    assert page.url == O3_BASE_URL + "/login"

@pytest_bdd.when('a user logs in to the REST API with the correct credentials')
def when_a_user_logs_in_to_the_rest_api_with_the_correct_credentials(login_data):
    
    login_data["is_authenticated"] = login_api("doctor", "Doctor123")

@pytest_bdd.when('a user simulates waiting 4 minutes and 50 seconds for a lockout')
def when_a_user_simulates_waiting_4_minutes_and_50_seconds_for_a_lockout(cursor:MySQLCursor, connection:MySQLConnection):
    
    select_lockout_query = """
    SELECT user_property.property_value
    FROM user_property
    JOIN users ON users.user_id = user_property.user_id
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = 'doctor';
    """
    
    cursor.execute(select_lockout_query)
    currentLockoutTimestamp = cursor.fetchone()['property_value']
    currentLockoutTimestamp = int(currentLockoutTimestamp)
        
    # subtract 5 minutes
    currentLockoutTimestamp -= 5 * 60 * 1000
    
    # add 10 seconds to test before
    currentLockoutTimestamp += 10 * 1000
    
    update_lockout_query = """
    UPDATE user_property
    JOIN users ON users.user_id = user_property.user_id
    SET user_property.property_value = %s
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = 'doctor';
    """
    
    cursor.execute(update_lockout_query, [currentLockoutTimestamp])
    
    connection.commit()

@pytest_bdd.when('a user simulates waiting 5 minutes for a lockout')
def when_a_user_simulates_waiting_5_minutes_for_a_lockout(cursor:MySQLCursor, connection:MySQLConnection):
    
    select_lockout_query = """
    SELECT user_property.property_value
    FROM user_property
    JOIN users ON users.user_id = user_property.user_id
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = 'doctor';
    """
    
    cursor.execute(select_lockout_query)
    currentLockoutTimestamp = cursor.fetchone()['property_value']
    currentLockoutTimestamp = int(currentLockoutTimestamp)
        
    # subtract 5 minutes
    currentLockoutTimestamp -= 5 * 60 * 1000
    
    update_lockout_query = """
    UPDATE user_property
    JOIN users ON users.user_id = user_property.user_id
    SET user_property.property_value = %s
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = 'doctor';
    """
    
    cursor.execute(update_lockout_query, [currentLockoutTimestamp])
    
    connection.commit()

@pytest_bdd.when('a user logs in to the login page with the correct credentials')
def when_a_user_logs_in_to_the_login_page_with_the_correct_credentials(page:Page):
    
    login(page, "doctor", "Doctor123")

@pytest_bdd.then('the login page should block the correct credentials')
def then_the_login_page_should_block_the_correct_credentials(page:Page):
    # use correct username and password
    # Then it should be NOT off of the login page because it is locked out
    
    if page.url == O3_BASE_URL + '/login':
        login(page, "doctor", "Doctor123")
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    assert page.url == O3_BASE_URL + '/login'

### SHARED FUNCATIONALITY ###

# generate random passwords
def random_password(length=8):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

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