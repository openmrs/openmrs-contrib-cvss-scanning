import pytest
import pytest_bdd
from tests.utils import DEFAULT_WAIT_TIME, O3_LOGIN_URL, O3_HOME_URL,createTestPatient
from playwright.sync_api import Page

@pytest.fixture(scope="function")
def page_data():
    return {}

@pytest.fixture(scope="function")
def cleanupTestPatient(page:Page,page_data):
    yield
    if page_data['editUrl']!=None:
        page.goto(page_data['editUrl'])
        page.wait_for_timeout(DEFAULT_WAIT_TIME)

        page.locator("#givenName").fill("Test")
        page.locator("#middleName").fill("Ing")
        page.locator("#familyName").fill("Ing")
        page.locator("#address1").fill("10000 Avenue Road")
        page.locator("#address2").fill("243")
        page.locator("#cityVillage").fill("Village Town")
        page.locator("#stateProvince").fill("St.Mrs Province")
        page.locator("#country").fill("USA")
        page.locator("#postalCode").fill("00000")
        page.locator("#phone").fill("XXX-555-XXXX")
        page.get_by_text("Update patient").click()
        #waits for page to load then ends
        child = page.get_by_text("Vitals and biometrics")
        child.wait_for()

@pytest_bdd.given("logged into OpenMRS O3")
def login(page:Page,page_data):
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

@pytest_bdd.given('a test patient has been created')
def verifyTestPatientExists(page:Page,page_data):
    page.goto(O3_HOME_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Search patient',exact=True).click()
    page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Ing")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    if(page.get_by_text("Other").count()>=1):
        "hello"
    else:
        createTestPatient(page)
        page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('the OpenMRS 3 edit patient page is displayed')
def navigateToTestPatient(page:Page,page_data):
    page.goto(O3_HOME_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    if(page.get_by_placeholder('Search for a patient by name or identifier number').count()<1):
        page.get_by_label('Search patient',exact=True).click()    
    page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Ing")
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
    page_data['editUrl']=page.url

