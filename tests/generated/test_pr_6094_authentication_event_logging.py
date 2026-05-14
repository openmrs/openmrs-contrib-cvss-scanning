import os
import json
from pathlib import Path
import pytest
from pytest_bdd import scenarios, given, when, then, parsers

from tests.security_lib.openmrs_client import OpenMRSClient
from tests.security_lib.observations import RuntimeObservation
from tests.security_lib.cvss_profiles import score_observation
from tests.security_lib.result_writer import write_security_result

scenarios("pr_6094_authentication_event_logging.feature")

@pytest.fixture
def openmrs_client():
    client = OpenMRSClient()

    if not client.credentials_configured():
        pytest.skip("OpenMRS credentials are not configured in O3_* environment variables.")

    return client

@pytest.fixture
def runtime_observation():
    return RuntimeObservation(
        source_repo="openmrs/openmrs-core",
        source_pr=6094,
        candidate_risk_id="risk_001",
        test_name="pr_6094_authentication_event_logging",
        owasp_category="A09:2025 Security Logging and Alerting Failures",
        cvss_profile="authentication_event_integrity"
    )

@given("an OpenMRS test instance with security event logging enabled")
def _(openmrs_client):
    if not openmrs_client.credentials_configured():
        pytest.skip("OpenMRS client credentials not configured")

@given("a test user account is available for authentication")
def _(openmrs_client):
    if not openmrs_client.username:
        pytest.skip("Test user not configured in OpenMRSClient")

@when("the test user performs a login attempt")
def _(openmrs_client, runtime_observation):
    if not openmrs_client.username or not openmrs_client.password:
        pytest.skip("Test user credentials not configured in OpenMRSClient")

    try:
        response = openmrs_client.login()
        runtime_observation.add_status_code(response.status_code)
        if response.status_code == 200:
            runtime_observation.add_note("Successful login attempt recorded")
            runtime_observation.login_event_observed = True
        else:
            runtime_observation.add_note(f"Login attempt failed with status code {response.status_code}")
            runtime_observation.login_event_observed = False
    except Exception as e:
        runtime_observation.add_note(f"Login attempt failed: {str(e)}")
        runtime_observation.login_event_observed = False

@when("the test user performs a logout action")
def _(openmrs_client, runtime_observation):
    try:
        response = openmrs_client.logout()
        runtime_observation.add_status_code(response.status_code)
        if response.status_code == 200:
            runtime_observation.add_note("Successful logout action recorded")
            runtime_observation.logout_event_observed = True
        else:
            runtime_observation.add_note(f"Logout action failed with status code {response.status_code}")
            runtime_observation.logout_event_observed = False
    except Exception as e:
        runtime_observation.add_note(f"Logout action failed: {str(e)}")
        runtime_observation.logout_event_observed = False

@then("authentication-related security events should be observable in the audit logging output")
def _(runtime_observation):
    runtime_observation.add_note("Direct inspection of audit logs is not available")
    runtime_observation.add_note("Assessing based on login/logout success status")
    runtime_observation.user_identifier_observed = False
    runtime_observation.timestamp_observed = False
    runtime_observation.outcome_status_observed = False

@then("the observed security behavior should be recorded for later CVSS 4.0 scoring")
def _(runtime_observation):
    score_result = score_observation(runtime_observation)
    output_path = "results/generated/pr_6094_authentication_event_logging_result.json"
    write_security_result(
        observation=runtime_observation,
        score_result=score_result,
        output_path=output_path
    )