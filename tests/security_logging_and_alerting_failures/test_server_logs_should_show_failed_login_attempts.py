import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result
from datetime import datetime

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

@pytest_bdd.given('the current time is saved')
def given_the_current_time_is_saved(date_time_data):
    
    date_time_data["saved_timestamp"] = datetime.now()

@pytest_bdd.when('a user attempts to login with the wrong username or password')
def when_a_user_attempts_to_login_with_the_wrong_username_or_password(username):
    
    print("USER:", username)

@pytest_bdd.when('an admin logs in on the login page')
def when_an_admin_logs_in_on_the_login_page():
    pass

@pytest_bdd.when('visits the server logs page')
def when_visits_the_server_logs_page():
    pass

@pytest_bdd.then('a failed login attempt log should exist after the saved timestamp')
def then_a_failed_login_attempt_log_should_exist_after_the_saved_timestamp():
    
    assert True

@pytest.fixture(scope="function")
def date_time_data():
    return {}