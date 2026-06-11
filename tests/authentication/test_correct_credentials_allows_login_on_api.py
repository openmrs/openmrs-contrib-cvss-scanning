import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, USER_CREDENTIALS
from tests.conftest import save_cvss_result

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):

    AV = BaseMetrics.AttackVector.NETWORK
    AC = BaseMetrics.AttackComplexity.LOW
    AT = BaseMetrics.AttackRequirements.NONE
    PR = BaseMetrics.PriviledgesRequired.NONE
    UI = BaseMetrics.UserInteraction.NONE
    VC = BaseMetrics.Confidentiality.VulnerableSystem.NONE
    SC = BaseMetrics.Confidentiality.SubsequentSystem.NONE
    VI = BaseMetrics.Integrity.VulnerableSystem.NONE
    SI = BaseMetrics.Integrity.SubsequentSystem.NONE
    VA = BaseMetrics.Availability.VulnerableSystem.HIGH
    SA = BaseMetrics.Availability.SubsequentSystem.HIGH

    cvss_score = calculate_cvss_v4_score(
        AV=AV, AC=AC, AT=AT, PR=PR, UI=UI, VC=VC, VI=VI, VA=VA, SC=SC, SI=SI, SA=SA
    )
    severity = get_cvss_severity(cvss_score)
    display_results(cvss_score=cvss_score, severity=severity)
    save_cvss_result(request, cvss_score, severity)

@pytest.mark.parametrize("username,password", USER_CREDENTIALS)
@pytest_bdd.scenario('authentication.feature', 'Correct credentials allows login on REST API')
def test_correct_credentials_allows_login_on_rest_api(login_data, username, password):
    pass