import pytest
import pytest_bdd
import string
import random

from tests.utils import O3_BASE_URL

# This file will run before anything in pytest.

# This file is for shared Given, When, and Thens
# Any time two or more features share a step, that has the same implementation (unlike CVSS)
# then putting them here will allow pytest to read them for each test.
# This saves time because you do not need to rewrite many functions

# Fixtures may also be used here or in the tests directly. They can store data between tests
# or between steps, like Given/When/Then. For a concrete example, see the session management tests.

# As a note, Pytest hooks can be used here, but that will require futher documenation lookup.
# As well, parameterized steps may be utilized as well to help with code reuse.

@pytest.fixture
def login_data():
    return {}

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def given_login_page_shown(new_page):
    new_page.goto(O3_BASE_URL + '/login')
    new_page.wait_for_url(O3_BASE_URL + '/login')

# generate random passwords
def random_password(length=8):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))