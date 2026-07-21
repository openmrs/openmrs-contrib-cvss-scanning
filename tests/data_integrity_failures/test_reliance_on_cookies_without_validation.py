import pytest_bdd
import pytest
from playwright.sync_api import Page, Playwright,expect
from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result
from tests.utils import O3_BASE_URL, login

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):
    # For an indepth reference to CVSS 4.0
    # https://www.first.org/cvss/v4.0/specification-document

    # To determine the CVSS score, the following metrics will need
    # to be decided. Here is each metric, and the possible values.
    # These are basic descriptions of the metrics. For further clarification
    # inspect the specification document linked above.

    # Attack Vector (AV) / BaseMetrics.AttackVector
    AV = BaseMetrics.AttackVector.LOCAL

    # Attack Complexity (AC) / BaseMetrics.AttackComplexity
    AC = BaseMetrics.AttackComplexity.HIGH

    # Attack Requirements (AT) / BaseMetrics.AttackRequirements
    AT = BaseMetrics.AttackRequirements.PRESENT

    # Privileges Required (PR) / BaseMetrics.PriviledgesRequired
    PR = BaseMetrics.PriviledgesRequired.LOW

    # User Interaction (UI) / BaseMetrics.UserInteraction
    UI = BaseMetrics.UserInteraction.NONE

    # Impact Metrics
    # Impact to the Vulnerable System (VC) / .VulnerableSystem
    VC = BaseMetrics.Confidentiality.VulnerableSystem.HIGH

    # Impact to the Subsequent System (SC) / .SubsequentSystem
    SC = BaseMetrics.Confidentiality.SubsequentSystem.HIGH

    # Integrity (VI/SI) / BaseMetrics.Integrity
    VI = BaseMetrics.Integrity.VulnerableSystem.HIGH

    # Impact to the Subsequent System (SI) / .SubsequentSystem
    SI = BaseMetrics.Integrity.SubsequentSystem.HIGH

    # Availability (VA/SA) BaseMetrics.Availability
    
    VA = BaseMetrics.Availability.VulnerableSystem.NONE

    # Impact to the Subsequent System (SA) / .SubsequentSystem
    SA = BaseMetrics.Availability.SubsequentSystem.NONE

    # Calculate CVSS 4.0 score
    cvss_score = calculate_cvss_v4_score(
        AV = AV, AC = AC, AT = AT, PR = PR, UI = UI, VC = VC, VI = VI, VA = VA, SC = SC, SI = SI, SA = SA
        )

    # This is calculated automatically
    # It has possible values of Low, Medium, High, Critical
    severity = get_cvss_severity(cvss_score)

    display_results(cvss_score=cvss_score, severity=severity)
        
    # This is required to be able to add the CVSS and Severity to the dashboard.
    save_cvss_result(request, cvss_score, severity)


@pytest_bdd.given("a clerk account has been logged into and their login token saved")
def a_clerk_account_has_been_logged_into(page:Page,playwright:Playwright,login_data):
    #launch a new browser
    chromium=playwright.chromium
    browser=chromium.launch()
    second_page=browser.new_page()

    #login to clerk on second browser
    second_page.goto(O3_BASE_URL + '/login')
    login(second_page,"clerk","Clerk123")
    #when it asks for the site
    if second_page.url == O3_BASE_URL + "/login/location":
        second_page.click("text=Outpatient Clinic")
        second_page.keyboard.press("Enter")

    #find value of clerk account cookies and save them
    clerk_cookies = second_page.context.cookies()
    login_data["clerk_cookies"]=clerk_cookies

@pytest_bdd.scenario("data_integrity_failures.feature", "Replace session cookies with another's session")
@pytest_bdd.when("another account's login token is replaced with the clerk's")
def test_another_accounts_login_token_is_replaced(page:Page,login_data):
    #login to the platform with an admin account
    page.goto(O3_BASE_URL + '/login')
    login(page,"admin","Admin123")
    # when it asks for the site
    if page.url == O3_BASE_URL + "/login/location":
        page.click("text=Outpatient Clinic")
        page.keyboard.press("Enter")

    #set admin account session cookie to clerk's
    page.context.add_cookies(login_data["clerk_cookies"])
    
    # wait for the page url
    page.wait_for_url(O3_BASE_URL + "/home/**")
    
    # wait for the page to fully load
    page.wait_for_load_state("domcontentloaded")

@pytest_bdd.then("the page shouldn't be logged into the clerk account")
def the_page_shouldnt_be_logged_into_the_clerk_account(page:Page):
    #refresh the first browser page
    page.reload()
    #see who's logged in on it, should be the admin and thats who was logged in on the browser
    page.get_by_label("My Account").click()
    expect(page.get_by_text("Super User"), message="Another account, other than Admin, was logged in to").to_have_count(1)
        

@pytest.fixture(scope="function")
def login_data():
    return {}