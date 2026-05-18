import pytest_bdd
import re

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

@pytest_bdd.scenario('cryptographic_failures.feature','The OpenMRS application should not use the default encryption vector')
def test_should_not_use_default_encryption_vector():
    pass

@pytest_bdd.given('the default encrpytion vector')
def given_the_default_encryption_vector(encryption_data):
    encryption_data["default_vector"] = "9wyBUNglFCRVSUhMfsTa3Q=="

@pytest_bdd.when('the encryption vector is found')
def when_the_encryption_vector_is_found(encryption_data):
    
    vector:str = ""
    
    raw:str = encryption_data["runtime_properties"]
    lines = raw.split('\n')
    
    for line in lines:
        # match encryption.key=
        
        if re.search(r"encryption\.vector=", line):
            vector = re.split(r"encryption\.vector=", line)[1]
            vector = vector.replace("\\", "")
    
    assert vector != ""
    
    encryption_data["current_vector"] = vector

@pytest_bdd.then('the encryption vector should not equal to the default vector')
def then_the_encryption_vector_should_not_equal_to_the_default_vector(encryption_data):
    
    assert encryption_data["current_vector"] != encryption_data["default_vector"]