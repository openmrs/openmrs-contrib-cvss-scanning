import re
import pytest
import pytest_bdd
from pytest_bdd import parsers, scenarios, scenario
from playwright.sync_api import Page, expect
from tests.utils import display_results,get_cvss_severity,calculate_cvss_v4_score, O3_LOGIN_URL, O3_WELCOME_URL,O3_HOME_URL,DEFAULT_WAIT_TIME
from tests.conftest import save_cvss_result



loggedIn = False
editUrl = None
testLocation = None

sqlTestStrings= [
    "'",                    # Most fundamental probe — breaks unparameterized queries instantly
    "' OR 'a'='a",         # Tautology in pure string context — no numbers needed
    "';--",                 # Statement termination — tests for multi-statement execution
    "O'Brien",              # Realistic input — catches basic escaping failures without looking malicious
    "' OR ''='",            # Minimal tautology — slips past naive filters that block keywords like OR+number
]

sqlEditProfileNameLocations = {
    "first name":    "#givenName",
    "middle name":   "#middleName",
    "family name":   "#familyName",
}
sqlEditProfileAddressLocations = {
    "address 1":     "#address1",
    "address 2":     "#address2",
    "city":          "#cityVillage",
    "state":         "#stateProvince",
    "country":       "#country",
    "postal code":   "#postalCode",
}

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):
    #print cvss information
    cvss_score=calculate_cvss_v4_score('N','L','N','L','N','H','H','H','N','N','N',)
    severity = get_cvss_severity(cvss_score)
    save_cvss_result(request, cvss_score, severity)

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
def navigateToTestPatient(page:Page):
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
    global editUrl
    editUrl=page.url



@pytest.mark.parametrize("testString",sqlTestStrings)
@scenario('sql_injection.feature', 'SQL injection on <personNameSQLString> field of edit patient page')
@pytest_bdd.when(parsers.parse('the attacker tries to edit a patient {personNameSQLString} using a set of potential SQL strings'))
def test_sql_injection_on_edit_profile_page_parameterized(page:Page,testString,request):
    #run the test
    #fill in field and update patient
    global editUrl
    page.goto(editUrl)
    global testLocation
    scenarioString = request.getfixturevalue('_pytest_bdd_example')['personNameSQLString']
    testLocation=scenarioString
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator(sqlEditProfileNameLocations[scenarioString]).fill(testString)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Update patient").click()



@pytest_bdd.then('see if SQL injection was successful')
def see_if_SQL_injection_was_successful(page):
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    global editUrl
    page.goto(editUrl)
    page.wait_for_timeout(DEFAULT_WAIT_TIME*1.5)

    global testLocation
    someTestStringFound=False

    inputValue=page.locator(sqlEditProfileNameLocations[testLocation]).input_value()
    for testString in sqlTestStrings:
        #at least one of the test strings should be on the page, if not there was an injection and we can assert a test fail
        if(inputValue==testString):
            someTestStringFound=True
        
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #if one of the test strings wasnt found this will be false indicating an injection
    assert someTestStringFound

@pytest.fixture(scope="function",autouse=True)
def cleanupTestPatient(page):
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



    








