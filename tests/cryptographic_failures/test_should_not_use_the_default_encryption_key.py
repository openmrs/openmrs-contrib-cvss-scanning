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

@pytest_bdd.scenario('cryptographic_failures.feature','The OpenMRS application should not use the default encryption key')
def test_should_not_use_default_encryption_key():
    pass

@pytest_bdd.given('the default encrpytion key')
def given():
    "dTfyELRrAICGDwzjHDjuhw=="
    pass

@pytest_bdd.when('the runtime properties are accessed')
def when_the_runtime_properties_are_accessed():
    pass

@pytest_bdd.when('the encryption key is found')
def when_the_encryption_key_is_found():
    pass

@pytest_bdd.then('the encryption key should not equal to the default key')
def then_the_encryption_key_should_not_equal_to_the_default_key():
    assert True