import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_BASE_URL
from tests.conftest import save_cvss_result
from playwright.sync_api import Page, Response

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):

    AV = BaseMetrics.AttackVector.NETWORK
    AC = BaseMetrics.AttackComplexity.HIGH
    AT = BaseMetrics.AttackRequirements.PRESENT
    PR = BaseMetrics.PriviledgesRequired.NONE
    UI = BaseMetrics.UserInteraction.PASSIVE
    VC = BaseMetrics.Confidentiality.VulnerableSystem.LOW
    SC = BaseMetrics.Confidentiality.SubsequentSystem.NONE
    VI = BaseMetrics.Integrity.VulnerableSystem.LOW
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

@pytest_bdd.scenario('security_misconfiguration.feature','Security header x-content-type-options is set to nosniff on login page')
def test_security_header_x_content_type_options_is_set_to_nosniff_on_login_page():
    pass

@pytest_bdd.given('the login page response is returned')
def given_the_login_page_response_is_returned(page:Page, response_data:dict):
    
    response : Response = page.goto(O3_BASE_URL)
    
    response_data["response"] = response
    

@pytest_bdd.when('the security headers are checked')
def when_the_security_headers_are_checked(response_data:dict):
    
    response : Response = response_data["response"]
    
    response_data["headers"] = response.all_headers()

@pytest_bdd.then('the x-content-type-options should be present')
def then_the_x_content_type_options_should_be_present(response_data:dict):
    
    headers : dict = response_data["headers"]
    
    assert "x-content-type-options" in headers.keys()

@pytest_bdd.then('the value of x-content-type-options is set to nosniff')
def then_the_value_of_x_content_type_options_is_set_to_nosniff(response_data:dict):
    
    headers : dict = response_data["headers"]
    
    assert headers["x-content-type-options"] == "nosniff"

@pytest.fixture(scope="function")
def response_data():
    return {}