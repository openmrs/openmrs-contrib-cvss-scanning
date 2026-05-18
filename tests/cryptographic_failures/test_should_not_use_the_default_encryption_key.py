import pytest
import pytest_bdd
import docker
import io
import tarfile
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

@pytest_bdd.scenario('cryptographic_failures.feature','The OpenMRS application should not use the default encryption key')
def test_should_not_use_default_encryption_key():
    pass

@pytest_bdd.given('the default encrpytion key')
def given_the_default_encryption_key(encryption_data):
    encryption_data["default_key"] = "dTfyELRrAICGDwzjHDjuhw=="

@pytest_bdd.when('the runtime properties are accessed')
def when_the_runtime_properties_are_accessed(encryption_data):
    
    client = docker.from_env()
    container = client.containers.get("openmrs-contrib-cvss-scanning-backend-1")
    
    # read in file from docker
    bits, stat = container.get_archive("/openmrs/data/openmrs-runtime.properties")
    
    # convert stream to memory
    buffer = io.BytesIO()
    for chunk in bits:
        buffer.write(chunk)
    buffer.seek(0)
    
    content = ""
    
    with tarfile.open(fileobj=buffer) as tar:
        f = tar.extractfile(tar.getmembers()[0])
        content = f.read().decode("utf-8")
    
    encryption_data["runtime_properties"] = content

@pytest_bdd.when('the encryption key is found')
def when_the_encryption_key_is_found(encryption_data):
    
    key:str = ""
    
    raw:str = encryption_data["runtime_properties"]
    lines = raw.split('\n')
    
    for line in lines:
        # match encryption.key=
        
        if re.search(r"encryption\.key=", line):
            key = re.split(r"encryption\.key=", line)[1]
            key = key.replace("\\", "")
    
    assert key != ""
    
    encryption_data["current_key"] = key

@pytest_bdd.then('the encryption key should not equal to the default key')
def then_the_encryption_key_should_not_equal_to_the_default_key(encryption_data):
    
    assert encryption_data["current_key"] != encryption_data["default_key"]

@pytest.fixture(scope="function")
def encryption_data():
    return {}