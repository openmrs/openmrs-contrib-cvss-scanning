import pytest
import pytest_bdd

from playwright.sync_api import sync_playwright
from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_BASE_URL, O3_LOGIN_URL

import os
from dotenv import load_dotenv

DEFAULT_LOAD_TIME = 1000

@pytest.fixture
def context_data():
    return {}

# Shared given, when, thens can go here

# In the given decorator, fill out the parameter as the text of the
# Given statement in Background or the Scenario. For each given in the
# Background and Scenario, a new decorator should be made.
@pytest_bdd.given('the OpenMRS 3 home page is show after login')
def given_openMRS_page_logged_in(new_page):
    # This function represents what will be run before the When and Then
    # steps. It is to put the system into a known state.
    #
    # If different givens exist, it is important to name the functions
    # differently. This function should be renamed to reflect what the
    # Given's functionality is.

    new_page.goto(O3_BASE_URL + '/login')
    new_page.wait_for_selector("#username")
    new_page.fill("#username", "admin")
    new_page.keyboard.press("Enter")
    new_page.wait_for_selector("#password")
    new_page.fill("#password", "Admin123")
    new_page.keyboard.press("Enter")
    
    # when it asks for the site
    new_page.wait_for_timeout(DEFAULT_LOAD_TIME)
    new_page.click("text=Outpatient Clinic")
    new_page.keyboard.press("Enter")
    new_page.wait_for_timeout(DEFAULT_LOAD_TIME)

@pytest_bdd.when('Cookies are accessed from the browser')
def when_cookies_are_accessed_from_the_browser(new_page, context_data):
    # This function represents what will happen during the When step of the scenario.
    
    # get the cookies
    cookies = new_page.context.cookies()
    
    context_data["cookies"] = cookies

@pytest_bdd.given('cookie information is saved')
def given_cookie_information_is_saved(new_page, context_data):
    # This function represents what will be run before the When and Then
    # steps. It is to put the system into a known state.
    #
    # If different givens exist, it is important to name the functions
    # differently. This function should be renamed to reflect what the
    # Given's functionality is.
    
    cookies = new_page.context.cookies()
    context_data["cookies"] = cookies

@pytest_bdd.given('the user logs out of their account')
def given_user_logs_out(new_page):
    # This function represents what will happen during the When step of the scenario.
    new_page.wait_for_timeout(1000)
    new_page.get_by_role("button", name="My Account").click()
    new_page.wait_for_timeout(1000)
    new_page.get_by_role("button", name="Logout").click()

@pytest_bdd.then('the login page should be shown')
def then(new_page):
    # This function represents what will happen during the Then step of the scenario.
    new_page.wait_for_url(O3_LOGIN_URL)
    assert new_page.url == O3_LOGIN_URL

@pytest_bdd.when('the url is directed at /spa')
def when_url_is_directed_at_spa(new_page):
    # This function represents what will happen during the When step of the scenario.
    new_page.wait_for_url(O3_LOGIN_URL)
    new_page.goto(O3_BASE_URL)
