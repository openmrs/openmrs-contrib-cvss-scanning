import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result
from tests.security_misconfiguration.conftest import format_content_security_policy_directives_as_dict
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

@pytest_bdd.scenario('security_misconfiguration.feature', "Security header directive <directive> should not be set to * or http: on login page")
def test_security_header_directive_should_not_be_set_to_star_or_http_on_login_page():
    pass

@pytest_bdd.then(parsers.parse("{directive} should not be set to * or http: if it exists and {fallback} to default-src"))
def then_directive_should_not_be_set_to_star_or_http_if_it_exists_and_fallback_to_default_src(response_data:dict, directive, fallback):
    
    fallback = True if fallback.lower() == "true" else False
    
    # get the content-security-policy
    headers : dict = response_data["headers"]
    security_policy_dict = format_content_security_policy_directives_as_dict(headers)
    
    # default is false
    is_directive_secure = False
    
    print(directive)
    
    if directive in security_policy_dict.keys():
        # check is not self or none
        if "*" not in security_policy_dict[directive] and "http:" not in security_policy_dict[directive]:
            is_directive_secure = True
    else:
        if fallback == True:
            # check default-src
            if "*" not in security_policy_dict['default-src'] and "http:" not in security_policy_dict['default-src']:
                is_directive_secure = True
    
    assert is_directive_secure == True