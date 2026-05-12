import pytest
import pytest_bdd
import string
import random

from tests.utils import O3_BASE_URL

import mysql.connector
from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from typing import Generator

from playwright.sync_api import Page

@pytest.fixture
def login_data():
    return {}

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def given_login_page_shown(page:Page):
    page.goto(O3_BASE_URL + '/login')
    page.wait_for_url(O3_BASE_URL + '/login')

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