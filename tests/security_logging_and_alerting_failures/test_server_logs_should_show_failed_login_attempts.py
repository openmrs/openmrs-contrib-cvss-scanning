import re
import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, login, O3_BASE_URL
from tests.conftest import save_cvss_result
from datetime import datetime, timezone
from playwright.sync_api import Page

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

@pytest.mark.parametrize("username", [
    "admin",
    "doctor",
    "nurse",
    "clerk",
    "technician",
    "fakeusername1",
    "fakeusername2",
])
@pytest_bdd.scenario('security_logging_and_alerting_failures.feature','Server logs should show failed login attempts')
def test_server_logs_should_show_failed_login_attempts(cleanup_clear_user_lockout, username):
    pass

@pytest_bdd.when('a user attempts to login with the wrong username or password')
def when_a_user_attempts_to_login_with_the_wrong_username_or_password(page:Page, username):
    
    page.goto(O3_BASE_URL)
    
    login(page, username, "BADPASS1")

@pytest_bdd.then('a failed login attempt log should exist after the saved timestamp')
def then_a_failed_login_attempt_log_should_exist_after_the_saved_timestamp(page:Page, date_time_data, username):
    
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
    
    assert current_datetime > date_time_data["saved_timestamp"]
    
    # verify lockout on specific account
    lockout_text_pattern : re.Pattern = re.compile(r"Failed login attempt \(login=.+\) - Invalid username and\/or password: .+")
    
    assert lockout_text_pattern.search(last_row_text) != None
    assert username in last_row_text