import re
import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_ROOT_URL, DEFAULT_WAIT_TIME
from tests.conftest import save_cvss_result
from playwright.sync_api import Page, expect

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):

    AV = BaseMetrics.AttackVector.NETWORK
    AC = BaseMetrics.AttackComplexity.LOW
    AT = BaseMetrics.AttackRequirements.NONE
    PR = BaseMetrics.PriviledgesRequired.NONE
    UI = BaseMetrics.UserInteraction.NONE
    VC = BaseMetrics.Confidentiality.VulnerableSystem.LOW
    SC = BaseMetrics.Confidentiality.SubsequentSystem.NONE
    VI = BaseMetrics.Integrity.VulnerableSystem.NONE
    SI = BaseMetrics.Integrity.SubsequentSystem.NONE
    VA = BaseMetrics.Availability.VulnerableSystem.NONE
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

@pytest_bdd.scenario('mishandling_of_exceptional_conditions.feature','Web server version number should not be shown on 404 page')
def test_web_server_version_number_should_not_be_shown_on_404_page():
    pass

@pytest_bdd.given('the attacker visits the page /openmrs/doesnotexist')
def given_the_attacker_visits_the_page_openmrsdoesnotexist(page:Page):
    page.goto(O3_ROOT_URL + '/doesnotexist')
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('the HTTP status 404 error page is shown')
def given_the_http_status_404_error_page_is_shown(page:Page):
    locator = page.get_by_text("HTTP Status 404 \u2013 Not Found")
    expect(locator).to_be_visible()

@pytest_bdd.when('the attacker looks for the version number')
def when_the_attacker_looks_for_the_version_number(page:Page, page_data):
    locator = page.get_by_text(re.compile(r"Apache Tomcat\/\d+\.\d+\.\d+"))
    
    page_data["is_text_on_page"] = locator.is_visible()

@pytest_bdd.then('the version number will not be shown')
def then_the_version_number_will_not_be_shown(page_data):
    
    assert page_data["is_text_on_page"] == False

@pytest.fixture(scope="function")
def page_data():
    return {}