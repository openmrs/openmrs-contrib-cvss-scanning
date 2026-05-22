import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result
from pytest_bdd import parsers

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

@pytest_bdd.scenario('security_misconfiguration.feature', 'Security header attribute <attribute> should not be used for default-src directive on login page')
def test_security_header_attribute_should_not_be_used_for_default_src_directive_on_login_page():
    pass

@pytest_bdd.then('the content-security-policy should be present')
def then_the_content_security_policy_should_be_present(response_data:dict):
    
    headers : dict = response_data["headers"]
    
    assert "content-security-policy" in headers.keys()

@pytest_bdd.then(parsers.parse('{attribute} should not be present in default-src'))
def then_attribute_should_not_be_present_in_default_src(response_data:dict, attribute):
    
    # get the content-security-policy
    headers : dict = response_data["headers"]
    content_security_policy : str = headers["content-security-policy"]
    directives = content_security_policy.split(";")
    
    security_policy_dict : dict = {}
    
    for i in range(0, len(directives)):
        line : str = directives[i]
        line = line.strip()
        line = line.split(" ")
        
        if len(line) >= 2:
            security_policy_dict[line[0]] = line[1:]
    
    # check if attribute is in the line
    assert attribute not in security_policy_dict["default-src"]