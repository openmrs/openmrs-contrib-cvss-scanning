import pytest
import pytest_bdd

from tests.utils import O3_BASE_URL

from playwright.sync_api import Page, Response

### SHARED STEPS ###

@pytest_bdd.given('the login page response is returned')
def given_the_login_page_response_is_returned(page:Page, response_data:dict):
    
    response : Response = page.goto(O3_BASE_URL)
    
    response_data["response"] = response
    

@pytest_bdd.when('the security headers are checked')
def when_the_security_headers_are_checked(response_data:dict):
    
    response : Response = response_data["response"]
    
    response_data["headers"] = response.all_headers()

### SHARED FUNCTIONALITY ###


### PYTEST FIXTURES ###

@pytest.fixture(scope="function")
def response_data():
    return {}