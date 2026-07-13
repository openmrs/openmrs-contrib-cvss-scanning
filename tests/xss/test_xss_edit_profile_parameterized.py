import pytest
import pytest_bdd
from pytest_bdd import parsers, scenario
from playwright.sync_api import Page
from tests.utils import get_cvss_severity, calculate_cvss_v4_score, createTestPatient, O3_HOME_URL, O3_LOGIN_URL, DEFAULT_WAIT_TIME
from tests.conftest import save_cvss_result


xssEditProfileLocations = {
    "first name":    "#givenName",
    "middle name":   "#middleName",
    "family name":   "#familyName",
    "address 1":     "#address1",
    "address 2":     "#address2",
    "city":          "#cityVillage",
    "state":         "#stateProvince",
    "country":       "#country",
    "postal code":   "#postalCode",
    "phone number":  "#phone",
}

xssTestStrings= [
        "<img src/onerror=prompt('XSS')",
        '<img src=x onerror=prompt("XSS")>',
        '<svg onload=prompt("XSS")>'
    ]


@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):
    #print cvss information
    cvss_score=calculate_cvss_v4_score('N','L','N','L','N','H','H','H','N','N','N',)
    severity = get_cvss_severity(cvss_score)
    save_cvss_result(request, cvss_score, severity)

@pytest.mark.parametrize("testString", xssTestStrings)
@scenario('o3_xss_security.feature', 'XSS injection on <scenarioString> field of edit patient page, parameterized')
@pytest_bdd.when(parsers.parse('the attacker tries to edit a patient {scenarioString} using a set of potential XSS strings'))
def test_xss_injection_on_edit_profile_page_parameterized(page:Page,testString,request,page_data):
    scenarioString = request.getfixturevalue('_pytest_bdd_example')['scenarioString']
    page.goto(page_data["editUrl"])
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator(xssEditProfileLocations[scenarioString]).fill(testString)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Update patient").click()



@pytest_bdd.then('see if XSS injection was successful')
def see_if_XSS_injection_was_successful(page,cleanupTestPatient):
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Show more").click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #if Cancel and Ok shows up on this page, a dialog has opened up - there is an XSS vulnerability
    if(page.get_by_text("Cancel").count()!=1 and page.get_by_text("Ok").count()!=1):
        #trigger test failure
        assert False




    









