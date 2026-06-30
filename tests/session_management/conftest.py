import pytest
import pytest_bdd

from playwright.sync_api import Page
from tests.utils import O3_BASE_URL, O3_LOGIN_URL, DEFAULT_WAIT_TIME

@pytest.fixture
def context_data():
    return {}

# Shared given, when, thens can go here

# In the given decorator, fill out the parameter as the text of the
# Given statement in Background or the Scenario. For each given in the
# Background and Scenario, a new decorator should be made.
@pytest_bdd.given('the OpenMRS 3 home page is show after login')
def given_openMRS_page_logged_in(page:Page):
    # This function represents what will be run before the When and Then
    # steps. It is to put the system into a known state.
    #
    # If different givens exist, it is important to name the functions
    # differently. This function should be renamed to reflect what the
    # Given's functionality is.

    page.goto(O3_BASE_URL + '/login')
    page.wait_for_selector("#username")
    page.fill("#username", "admin")
    page.keyboard.press("Enter")
    page.wait_for_selector("#password")
    page.fill("#password", "Admin123")
    page.keyboard.press("Enter")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    # when it asks for the site
    if page.url == O3_BASE_URL + "/login/location":
        page.click("text=Outpatient Clinic")
        page.keyboard.press("Enter")
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.when('Cookies are accessed from the browser')
def when_cookies_are_accessed_from_the_browser(page:Page, context_data):
    # This function represents what will happen during the When step of the scenario.
    
    # get the cookies
    cookies = page.context.cookies()
    
    context_data["cookies"] = cookies

@pytest_bdd.given('cookie information is saved')
def given_cookie_information_is_saved(page:Page, context_data):
    # This function represents what will be run before the When and Then
    # steps. It is to put the system into a known state.
    #
    # If different givens exist, it is important to name the functions
    # differently. This function should be renamed to reflect what the
    # Given's functionality is.
    
    cookies = page.context.cookies()
    context_data["cookies"] = cookies

@pytest_bdd.then('the login page should be shown')
def then(page:Page):
    # This function represents what will happen during the Then step of the scenario.
    page.wait_for_url(O3_LOGIN_URL)
    assert page.url == O3_LOGIN_URL

@pytest_bdd.when('the url is directed at /spa')
def when_url_is_directed_at_spa(page:Page):
    # This function represents what will happen during the When step of the scenario.
    page.goto(O3_BASE_URL)
