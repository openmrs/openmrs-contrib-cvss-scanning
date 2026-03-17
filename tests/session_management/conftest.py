import pytest
import pytest_bdd

from playwright.sync_api import sync_playwright
from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_BASE_URL

import os
from dotenv import load_dotenv

DEFAULT_LOAD_TIME = 1000

# URL configuration
O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')
O3_LOGIN_URL = f'{O3_BASE_URL}/login'
O3_HOME_URL = f'{O3_BASE_URL}/home'

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

