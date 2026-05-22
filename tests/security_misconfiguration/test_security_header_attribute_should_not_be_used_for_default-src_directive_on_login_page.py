import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result
from tests.security_misconfiguration.conftest import format_content_security_policy_directives_as_dict
from pytest_bdd import parsers

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):

    AV = BaseMetrics.AttackVector.NETWORK
    AC = BaseMetrics.AttackComplexity.LOW
    AT = BaseMetrics.AttackRequirements.NONE
    PR = BaseMetrics.PriviledgesRequired.NONE
    UI = BaseMetrics.UserInteraction.PASSIVE
    VC = BaseMetrics.Confidentiality.VulnerableSystem.HIGH
    SC = BaseMetrics.Confidentiality.SubsequentSystem.LOW
    VI = BaseMetrics.Integrity.VulnerableSystem.HIGH
    SI = BaseMetrics.Integrity.SubsequentSystem.LOW
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

@pytest_bdd.scenario('security_misconfiguration.feature', 'Security header attribute <attribute> should not be used for default-src directive on login page')
def test_security_header_attribute_should_not_be_used_for_default_src_directive_on_login_page():
    pass

@pytest_bdd.then(parsers.parse('{attribute} should not be present in default-src'))
def then_attribute_should_not_be_present_in_default_src(response_data:dict, attribute):
    
    # get the content-security-policy
    headers : dict = response_data["headers"]
    security_policy_dict = format_content_security_policy_directives_as_dict(headers)
    
    # check if attribute is in the line
    assert attribute not in security_policy_dict["default-src"]