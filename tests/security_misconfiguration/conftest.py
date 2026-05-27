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

@pytest_bdd.then('the content-security-policy should be present')
def then_the_content_security_policy_should_be_present(response_data:dict):
    
    headers : dict = response_data["headers"]
    
    assert "content-security-policy" in headers.keys()

### SHARED FUNCTIONALITY ###

def format_content_security_policy_directives_as_dict(headers:dict):
    content_security_policy : str = headers["content-security-policy"]
    directives = content_security_policy.split(";")

    security_policy_dict : dict = {}

    for i in range(0, len(directives)):
        line : str = directives[i]
        line = line.strip()
        line = line.split(" ")
        
        if len(line) >= 2:
            security_policy_dict[line[0]] = line[1:]

    return security_policy_dict

### PYTEST FIXTURES ###

@pytest.fixture(scope="function")
def response_data():
    return {}