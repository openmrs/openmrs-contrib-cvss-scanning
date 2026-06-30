import re
import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, USER_CREDENTIALS
from tests.conftest import save_cvss_result
from playwright.sync_api import Page
from datetime import timezone, datetime

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

@pytest.mark.parametrize("username,password", USER_CREDENTIALS)
@pytest_bdd.scenario('security_logging_and_alerting_failures.feature','Server logs should not show failed login attempts with correct credentials')
def test_server_logs_should_not_show_failed_login_attempts_with_correct_credentials(username, password):
    pass

@pytest_bdd.then('a failed login attempt log should not exist')
def then_a_failed_login_attempt_log_should_not_exist(page:Page, date_time_data):

    server_log_table = page.get_by_role("table")
    server_log_rows = server_log_table.get_by_role("row")
    last_row_text = server_log_rows.all()[-1].text_content()
    
    # verify time
    
    datetime_pattern : re.Pattern = re.compile(r"\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d")
    datetime_match : re.Match = datetime_pattern.search(last_row_text)
    
    # format timestamp
    current_datetime_str : str = datetime_match.group(0)
    
    current_datetime : datetime = datetime.fromisoformat(current_datetime_str)
    current_datetime = current_datetime.replace(tzinfo=timezone.utc)
    
    assert current_datetime < date_time_data["saved_timestamp"]