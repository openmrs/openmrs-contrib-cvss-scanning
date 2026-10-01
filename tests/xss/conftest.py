import pytest
import pytest_bdd
from tests.utils import DEFAULT_WAIT_TIME, O3_BASE_URL, O3_LOGIN_URL, createTestPatient
from playwright.sync_api import Page

O3_REST_URL = O3_BASE_URL.removesuffix("/spa") + "/ws/rest/v1"

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
        page.locator("#familyName").fill("Patient")
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
def verifyTestPatientExists(page:Page,page_data,patient_data):
    # Uses the REST API rather than the patient search UI so the lookup doesn't depend on render timing.
    # page.request shares the browser's session cookie, so this runs as the logged-in admin.
    response = page.request.get(f"{O3_REST_URL}/patient", params={"q": "Test Patient", "v": "custom:(uuid)"})
    assert response.ok, f"Patient search failed: {response.status} {response.text()}"
    results = response.json()["results"]
    if results:
        page_data['patientUuid'] = results[0]["uuid"]
    else:
        createTestPatient(page,family_name="Patient")
        page_data['patientUuid'] = page.url.split("/")[6]
        patient_data["patient_id"].append(page_data['patientUuid'])
        page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('the OpenMRS 3 edit patient page is displayed')
def navigateToTestPatient(page:Page,page_data):
    page_data['editUrl']=f"{O3_BASE_URL}/patient/{page_data['patientUuid']}/edit"
    page.goto(page_data['editUrl'])
    page.locator("#givenName").wait_for()
