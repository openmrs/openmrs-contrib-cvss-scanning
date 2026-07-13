import pytest
from tests.utils import DEFAULT_WAIT_TIME
from playwright.sync_api import Page

@pytest.fixture(scope="function")
def page_data():
    return {}

@pytest.fixture(scope="function",autouse=True)
def cleanupTestPatient(page:Page):
    yield
    global editUrl
    if editUrl!=None:
        page.goto(editUrl)
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