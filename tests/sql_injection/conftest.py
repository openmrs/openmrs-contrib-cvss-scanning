
import pytest_bdd
import os
from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from tests.utils import O3_LOGIN_URL,O3_HOME_URL, O3_BASE_URL, DEFAULT_WAIT_TIME
from playwright.sync_api import Page
import pytest

# URL configuration
O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')
O3_LOGIN_URL = f'{O3_BASE_URL}/login'
O3_HOME_URL = f'{O3_BASE_URL}/home'

@pytest_bdd.given("logged into OpenMRS O3")
def login(page:Page):
    page.goto(O3_LOGIN_URL)
    page.locator('#username').fill("admin")
    page.get_by_text("Continue").click()
    page.locator('#password').fill("Admin123")
    page.get_by_text("Log in").click()

    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    if(page.url.find("/openmrs/spa/login/location")!=-1):
        page.get_by_text("Outpatient Clinic").click()
        page.get_by_text("Remember my location").click()
        page.get_by_text("Confirm").click()
        page.wait_for_timeout(DEFAULT_WAIT_TIME)

def createTestPatient(page:Page):
    page.goto(O3_HOME_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Add patient').click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator('#givenName').fill("Test")
    page.locator('#familyName').fill("Patient")
    page.get_by_text("Other").click()

    #date of birth -> no, estimated age
    page.locator("button").get_by_text('No').last.click()
    page.locator('#yearsEstimated').fill("26")
    page.locator('#monthsEstimated').fill("0")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Register patient").click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('a test patient has been created')
def verifyTestPatientExists(page:Page):
    page.goto(O3_HOME_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Search patient',exact=True).click()
    page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    if(not page.get_by_text("Other").count()>=1):
        createTestPatient(page)
        page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('the OpenMRS 3 edit patient page is displayed')
def navigateToTestPatient(page:Page,url_data):
    page.goto(O3_HOME_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    if(page.get_by_placeholder('Search for a patient by name or identifier number').count()<1):
        page.get_by_label('Search patient',exact=True).click()    
    page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    page.get_by_role("button",name="Search").first.click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #find and click actions button
    child = page.get_by_text("Actions")
    child.click()
    #find and click actions button
    page.wait_for_timeout(DEFAULT_WAIT_TIME/5)
    child = page.get_by_text("Edit patient details")
    child.click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    url_data["edit_url"]=page.url

@pytest.fixture(scope="function")
def url_data():
    return {}
