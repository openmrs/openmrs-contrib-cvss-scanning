import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_HOME_URL, O3_LOGIN_URL
from tests.conftest import save_cvss_result
from playwright.sync_api import Page

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):

    AV = BaseMetrics.AttackVector.NETWORK
    AC = BaseMetrics.AttackComplexity.LOW
    AT = BaseMetrics.AttackRequirements.NONE
    PR = BaseMetrics.PriviledgesRequired.NONE
    UI = BaseMetrics.UserInteraction.PASSIVE
    VC = BaseMetrics.Confidentiality.VulnerableSystem.HIGH
    SC = BaseMetrics.Confidentiality.SubsequentSystem.HIGH
    VI = BaseMetrics.Integrity.VulnerableSystem.HIGH
    SI = BaseMetrics.Integrity.SubsequentSystem.HIGH
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

@pytest_bdd.scenario('session_management.feature', 'Session cookie can be used by a valid user')
def test_session_cookie_can_be_used_by_a_valid_user():
    pass

@pytest_bdd.given('the user navigates to a different page')
def given_the_user_navigates_to_a_different_page(page:Page):
    page.goto("https://www.google.com")

@pytest_bdd.when('a valid cookie is injected')
def when_a_valid_cookie_is_injected(page:Page, context_data):
    
    cookies = context_data["cookies"]
    
    page.context.add_cookies(cookies)

@pytest_bdd.then('the home page should be shown')
def then_the_home_page_should_be_shown(page:Page):
    
    assert O3_HOME_URL in page.url, "Home page was not accessed after trying to log in."
    assert page.url != O3_LOGIN_URL, "Login page is shown. Login failed."