"""
BDD tests for Content Security Policy (CSP) security headers.
Tests that OpenMRS sets secure CSP headers that prevent XSS attacks.

Add this file to: tests/security_misconfiguration/
"""
import pytest_bdd
from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result
from tests.security_misconfiguration.conftest import format_content_security_policy_directives_as_dict


# ---------------------------------------------------------------------------
# Scenario 1: CSP should not allow unsafe-eval
# ---------------------------------------------------------------------------

@pytest_bdd.scenario(
    'security_misconfiguration.feature',
    'Content Security Policy should not allow unsafe-eval'
)
def test_csp_should_not_allow_unsafe_eval():
    pass


# ---------------------------------------------------------------------------
# Scenario 2: CSP should not allow unsafe-inline scripts
# ---------------------------------------------------------------------------

@pytest_bdd.scenario(
    'security_misconfiguration.feature',
    'Content Security Policy should not allow unsafe-inline scripts'
)
def test_csp_should_not_allow_unsafe_inline():
    pass


# ---------------------------------------------------------------------------
# Scenario 3: CSP should have form-action directive
# ---------------------------------------------------------------------------

@pytest_bdd.scenario(
    'security_misconfiguration.feature',
    'Content Security Policy should have form-action directive'
)
def test_csp_should_have_form_action():
    pass


# ---------------------------------------------------------------------------
# Shared step — CVSS score
# ---------------------------------------------------------------------------

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):
    cvss_score = calculate_cvss_v4_score(
        AV=BaseMetrics.AttackVector.NETWORK,
        AC=BaseMetrics.AttackComplexity.LOW,
        AT=BaseMetrics.AttackRequirements.NONE,
        PR=BaseMetrics.PriviledgesRequired.NONE,
        UI=BaseMetrics.UserInteraction.PASSIVE,
        VC=BaseMetrics.Confidentiality.VulnerableSystem.HIGH,
        VI=BaseMetrics.Integrity.VulnerableSystem.HIGH,
        VA=BaseMetrics.Availability.VulnerableSystem.NONE,
        SC=BaseMetrics.Confidentiality.SubsequentSystem.NONE,
        SI=BaseMetrics.Integrity.SubsequentSystem.NONE,
        SA=BaseMetrics.Availability.SubsequentSystem.NONE,
    )
    severity = get_cvss_severity(cvss_score)
    display_results(cvss_score=cvss_score, severity=severity)
    save_cvss_result(request, cvss_score, severity)


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------

@pytest_bdd.then(
    'the Content-Security-Policy header should not contain unsafe-eval'
)
def then_csp_no_unsafe_eval(response_data: dict):
    headers = response_data["headers"]
    csp = headers.get("content-security-policy", "")
    assert "unsafe-eval" not in csp, (
        f"CSP contains 'unsafe-eval' — allows arbitrary JS execution. "
        f"Full CSP: {csp}"
    )


@pytest_bdd.then(
    "the Content-Security-Policy header should not contain unsafe-inline for scripts"
)
def then_csp_no_unsafe_inline(response_data: dict):
    headers = response_data["headers"]
    csp = headers.get("content-security-policy", "")
    csp_dict = format_content_security_policy_directives_as_dict(headers)
    script_src = csp_dict.get("script-src", [])
    assert "'unsafe-inline'" not in script_src, (
        f"CSP script-src contains 'unsafe-inline' — allows inline scripts. "
        f"script-src: {script_src}"
    )


@pytest_bdd.then(
    "the Content-Security-Policy header should contain a form-action directive"
)
def then_csp_has_form_action(response_data: dict):
    headers = response_data["headers"]
    csp_dict = format_content_security_policy_directives_as_dict(headers)
    assert "form-action" in csp_dict, (
        f"CSP missing 'form-action' directive — allows form hijacking. "
        f"CSP directives found: {list(csp_dict.keys())}"
    )