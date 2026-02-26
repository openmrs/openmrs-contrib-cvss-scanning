import re
import pytest
from pytest_bdd import scenarios, given, when, then, parsers
from playwright.sync_api import Page, expect

O3_LOGIN_URL = 'http://0.0.0.0:80/openmrs/spa/login'
O3_WELCOME_URL = 'http://0.0.0.0:80/openmrs/spa/login/location'
O3_HOMEPAGE_URL = 'http://0.0.0.0:80/openmrs/spa/home/service-queues#'
DEFAULT_WAIT_TIME = 1000
alertPresent=False

scenarios('o3_xss_security.feature')
xssTestStrings= [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "javascript:alert('XSS')"
    ]
xssEditProfileLocations = [
    "#givenName",
    "#middleName",
    "#familyName",
    "#address1",
    "#address2",
    "#cityVillage",
    "#stateProvince",
    "#country",
    "#postalCode",
    "#phone",
    
]
 
@given("logged into OpenMRS O3")
def login(page:Page):
    page.goto(O3_LOGIN_URL)
    page.locator('#username').fill("admin")
    page.get_by_text("Continue").click()
    page.locator('#password').fill("Admin123")
    page.get_by_text("Log in").click()

    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    if(page.url==O3_WELCOME_URL):
        page.get_by_text("Outpatient Clinic").click()
        page.get_by_text("Remember my location").click()
        page.get_by_text("Confirm").click()


def createTestPatient(page:Page):
    page.goto(O3_HOMEPAGE_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Add patient').click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator('#givenName').fill("Test")
    page.locator('#familyName').fill("Patient")
    page.get_by_text("Other").click()

    #date of birth -> no, estimated age
    page.locator('[class="cds--content-switcher cds--layout-constraint--size__default-md cds--layout-constraint--size__min-sm cds--layout-constraint--size__max-lg"]').get_by_text('No').click()
    page.locator('#yearsEstimated').fill("26")
    page.locator('#monthsEstimated').fill("0")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Register patient").click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@given('a test patient has been created')
def verifyTestPatientExists(page:Page):
    page.goto(O3_HOMEPAGE_URL)
    #page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #page.get_by_label('Search patient',exact=True).click()
    #page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #if(page.get_by_text("Other").count()>=1):
        #page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #else:
        #createTestPatient(page)
        #page.wait_for_timeout(DEFAULT_WAIT_TIME)

@given('the OpenMRS 3 edit patient page is displayed')
def navigateToTestPatient(page:Page):
    page.goto(O3_HOMEPAGE_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Search patient',exact=True).click()
    page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    child = page.get_by_text("01-Jan-2000")
    child.click()
    #parent = page.locator(".a").filter(has=child)
    #parent.click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME*2)
    #find and click actions button
    child = page.get_by_text("Actions")
    child.click()
    #parent = page.location("button").filter(has=child)
    #parent.click()
    #find and click actions button
    page.wait_for_timeout(DEFAULT_WAIT_TIME/5)
    child = page.get_by_text("Edit patient details")
    child.click()
    #parent = page.location("button").filter(has=child)
    #parent.click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)


def setAlertPresent(val):
        alertPresent=val

loggedIn = False
editUrl = None
@when('the attacker tries to edit a patient middle name using a set of potential XSS strings and an alert was found after any string')
@pytest.mark.parametrize("testString",xssTestStrings)
@pytest.mark.parametrize("testLocation",xssEditProfileLocations)
def test_xss_injection_edit_profile_parameterized(page:Page,testString,testLocation):
    global loggedIn
    global editUrl
    if(not loggedIn):
        login(page)
        verifyTestPatientExists(page)
        navigateToTestPatient(page)
        loggedIn=True
    if (editUrl==None):
        editUrl = page.url
    if(editUrl is not None):
        page.wait_for_timeout(DEFAULT_WAIT_TIME)
        print(f"Edit url:{editUrl}")
        page.goto(editUrl)
        page.wait_for_timeout(DEFAULT_WAIT_TIME)
        if(page.url.find("login")>=0):
            login(page)
            page.wait_for_timeout(DEFAULT_WAIT_TIME)
            page.goto(editUrl)
        page.wait_for_timeout(DEFAULT_WAIT_TIME)
        print(page.url)
    global alertPresent
    setAlertPresent(False)

    #run the test
    #fill in middle name and update patient
    page.locator(testLocation).fill(testString)
    page.get_by_text("Update patient").click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Show more").click()
    #now on patient main phase, expect no alert from xss
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.on('dialog', lambda: setAlertPresent(True))
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    #expect(alertPresent).to_be_truthy()
    #if pass, go to next, else stop


@then('calculate CVSS score and report failure. ')
def calculate_cvss_score():
    if alertPresent:
        return "CVSS Base Score: 7.4"
    else:
        return "CVSS Base Score: 0.0"        









