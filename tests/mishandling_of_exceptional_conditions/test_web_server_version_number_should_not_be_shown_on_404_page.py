import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result

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
def given_the_attacker_visits_the_page_openmrsdoesnotexist():
    pass

@pytest_bdd.given('the HTTP status 404 error page is shown')
def given_the_http_status_404_error_page_is_shown():
    pass

@pytest_bdd.when('the attacker looks for the version number')
def when_the_attacker_looks_for_the_version_number():
    pass

@pytest_bdd.then('the version number will not be shown')
def then_the_version_number_will_not_be_shown():
    pass