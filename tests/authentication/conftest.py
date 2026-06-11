import pytest
import pytest_bdd
import string
import random

from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from playwright.sync_api import Page
from tests.utils import O3_BASE_URL, O3_HOME_URL, DEFAULT_WAIT_TIME, login, login_api, LoginApiResponse

### SHARED STEPS ###

@pytest_bdd.given('the REST API is locked out from 7 failed login attempts')
def given_the_rest_api_is_locked_out_from_7_failed_login_attempts(username, password):

    for i in range(0,8):
        login_api(username, f"BADPASS{i}")
    
    # checks the lockout
    loginApiResponse : LoginApiResponse = login_api(username, password)
    assert loginApiResponse.is_authenticated == False

@pytest_bdd.given('the login page is locked out from 7 failed login attempts')
def given_the_login_page_is_locked_out_from_7_failed_login_attempts(page:Page, username, password):
    
    for i in range(0,8):
        login(page, username, f"BADPASS{i}")
    
    login(page, username, password)
    assert page.url == O3_BASE_URL + "/login"

@pytest_bdd.when('a user logs in to the REST API with the correct credentials')
def when_a_user_logs_in_to_the_rest_api_with_the_correct_credentials(login_data, username, password):
    
    loginApiResponse : LoginApiResponse = login_api(username, password)
    
    login_data["is_authenticated"] = loginApiResponse.is_authenticated

@pytest_bdd.when('a user simulates waiting 4 minutes and 50 seconds for a lockout')
def when_a_user_simulates_waiting_4_minutes_and_50_seconds_for_a_lockout(cursor:MySQLCursor, connection:MySQLConnection, username):
    
    select_lockout_query = """
    SELECT user_property.property_value
    FROM user_property
    JOIN users ON users.user_id = user_property.user_id
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = %s;
    """
    
    cursor.execute(select_lockout_query, [username])
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
    AND users.username = %s;
    """
    
    cursor.execute(update_lockout_query, [currentLockoutTimestamp, username])
    
    connection.commit()

@pytest_bdd.when('a user simulates waiting 5 minutes for a lockout')
def when_a_user_simulates_waiting_5_minutes_for_a_lockout(cursor:MySQLCursor, connection:MySQLConnection, username):
    
    select_lockout_query = """
    SELECT user_property.property_value
    FROM user_property
    JOIN users ON users.user_id = user_property.user_id
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = %s;
    """
    
    cursor.execute(select_lockout_query, [username])
    currentLockoutTimestamp = cursor.fetchone()['property_value']
    currentLockoutTimestamp = int(currentLockoutTimestamp)
        
    # subtract 5 minutes
    currentLockoutTimestamp -= 5 * 60 * 1000
    
    update_lockout_query = """
    UPDATE user_property
    JOIN users ON users.user_id = user_property.user_id
    SET user_property.property_value = %s
    WHERE user_property.property = 'lockoutTimestamp'
    AND users.username = %s;
    """
    
    cursor.execute(update_lockout_query, [currentLockoutTimestamp, username])
    
    connection.commit()

@pytest_bdd.then('the login page should block the correct credentials')
def then_the_login_page_should_block_the_correct_credentials(page:Page, username, password):
    # use correct username and password
    # Then it should be NOT off of the login page because it is locked out
    
    if page.url == O3_BASE_URL + '/login':
        login(page, username, password)
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    assert page.url == O3_BASE_URL + '/login'

@pytest_bdd.then('the location selection or home page should be shown')
def then_the_location_selection_or_home_page_should_be_shown(page:Page):
    
    page.reload()
    
    isOnLoginPageOrHomePage = page.url == O3_BASE_URL + "/login/location" or O3_HOME_URL in page.url
    
    assert isOnLoginPageOrHomePage, f"URL not on homepage or location page but on {page.url}"

@pytest_bdd.then('the user should be authenticated')
def then_the_correct_credentials_should_log_into_the_rest_api(login_data):

    assert login_data["is_authenticated"] == True

### SHARED FUNCATIONALITY ###

# generate random passwords
def random_password(length=8):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

### PYTEST FIXTURES ###

@pytest.fixture(scope="function")
def login_data():
    return {}