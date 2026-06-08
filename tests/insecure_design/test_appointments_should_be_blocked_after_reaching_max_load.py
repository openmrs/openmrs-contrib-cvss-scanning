import pytest
import pytest_bdd
import requests
from playwright.sync_api import Page

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, login_and_select_default_location, login_api, createTestPatient, BaseMetrics, LoginApiResponse, O3_ROOT_URL, DEFAULT_WAIT_TIME, O3_WELCOME_URL, O3_BASE_URL
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
    VA = BaseMetrics.Availability.VulnerableSystem.NONE
    SA = BaseMetrics.Availability.SubsequentSystem.NONE

    cvss_score = calculate_cvss_v4_score(
        AV=AV, AC=AC, AT=AT, PR=PR, UI=UI, VC=VC, VI=VI, VA=VA, SC=SC, SI=SI, SA=SA
    )
    severity = get_cvss_severity(cvss_score)
    display_results(cvss_score=cvss_score, severity=severity)
    save_cvss_result(request, cvss_score, severity)

@pytest.mark.parametrize("service_name", [
    "General Medicine service",
    "Outpatient Department",
    "Rehabilitation service",
])
@pytest_bdd.scenario('insecure_design.feature', 'Appointments should be blocked after reaching max load')
def test_appointments_should_be_blocked_after_reaching_max_load(reset_max_appointments_limit, service_name, cleanup_delete_patient):
    pass

@pytest_bdd.given('3 test patients are created', target_fixture='scenario_data')
def given_3_test_patients_are_created(page: Page, patient_data):
    data = {}
    data['patient_uuids'] = []

    page.goto(O3_BASE_URL)

    login_and_select_default_location(page, "admin", "Admin123")

    for _ in range(3):
        uuid = create_test_patient_and_get_uuid(page, patient_data)
        data['patient_uuids'].append(uuid)
        print(f"Created patient: {uuid}")

    assert len(data['patient_uuids']) == 3, "Failed to create 3 test patients"
    return data

@pytest_bdd.given('the max appoitment limit for services is set to 2', target_fixture='scenario_data')
def and_max_appointment_limit_is_set(scenario_data, cursor, connection, service_name):

    # Fetch the service UUID from the API
    loginApiResponse : LoginApiResponse = login_api("admin", "Admin123")
    
    assert loginApiResponse.is_authenticated, "Admin failed to login through API"
    
    jsessionid = loginApiResponse.jsessionid
    
    service_uuid = get_service_uuid(jsessionid, service_name)
    scenario_data['service_uuid'] = service_uuid

    # Set the max limit to 2 via the database
    cursor.execute(
        "UPDATE appointment_service SET max_appointments_limit = 2 WHERE name = %s",
        [service_name]
    )
    
    connection.commit()

    # Verify it was set
    cursor.execute(
        "SELECT max_appointments_limit FROM appointment_service WHERE name = %s",
        [service_name]
    )
    result = cursor.fetchone()
        
    assert result["max_appointments_limit"] == 2, f"Expected max limit to be 2 but got {result[0]}"

    return scenario_data

@pytest_bdd.when('3 appointment requests are made over the api', target_fixture='scenario_data')
def when_3_appointments_are_made(scenario_data):
    
    loginApiResponse : LoginApiResponse = login_api("admin", "Admin123")
    
    assert loginApiResponse.is_authenticated, "Admin failed to login through API"
    
    jsessionid = loginApiResponse.jsessionid

    successful_bookings = 0
    for patient_uuid in scenario_data['patient_uuids']:
        success = book_appointment(jsessionid, patient_uuid, scenario_data['service_uuid'])
        if success:
            successful_bookings += 1

    scenario_data['successful_bookings'] = successful_bookings
    return scenario_data

@pytest_bdd.then('2 out of 3 appointments should be successful')
def then_2_out_of_3_appointments_should_be_successful(scenario_data):
    successful = scenario_data['successful_bookings']

    # If the system were secure, only 2 should succeed.
    # All 3 succeeding proves the vulnerability — the limit is not enforced.
    assert successful == 2, ("The system does not enforce maxAppointmentsLimit.")

def create_test_patient_and_get_uuid(page: Page, patient_data):
    
    createTestPatient(page)
    
    # get ID
    page.wait_for_timeout(DEFAULT_WAIT_TIME * 3)
    spans = page.locator("div.cds--tag span").all()
    id_text = spans[-1].text_content()
    patient_data["patient_id"].append(id_text)

    # Extract UUID from the URL after redirect e.g. /patient/<uuid>/chart
    url = page.url
    uuid = url.split("/patient/")[1].split("/")[0]
    return uuid


def get_service_uuid(jsessionid, service_name):
    url = f"{O3_ROOT_URL}ws/rest/v1/appointments"
    cookies = {"JSESSIONID": jsessionid}

    try:
        response = requests.get(url, params={"v": "full"}, cookies=cookies, timeout=10)
        if response.status_code == 200:
            appointments = response.json()
            for appt in appointments:
                service = appt.get("service", {})
                if service.get("name") == service_name:
                    return service.get("uuid")
    except requests.exceptions.RequestException as e:
        print(f"GET SERVICE exception: {e}")

    return None


def book_appointment(jsessionid, patient_uuid, service_uuid):
    url = f"{O3_ROOT_URL}ws/rest/v1/appointments"
    cookies = {"JSESSIONID": jsessionid}
    payload = {
        "patientUuid": patient_uuid,
        "serviceUuid": service_uuid,
        "startDateTime": "2026-01-01T09:00:00.000Z",
        "endDateTime": "2026-01-01T09:30:00.000Z",
        "appointmentKind": "Scheduled",
        "comments": "Security test appointment"
    }

    try:
        response = requests.post(url, json=payload, cookies=cookies, timeout=10)
        print(f"BOOK: {response.status_code} - {response.text}")
        return response.status_code in (200, 201)
    except requests.exceptions.RequestException as e:
        print(f"BOOK exception: {e}")
        return False

@pytest.fixture(scope="function")
def scenario_data():
    return {}

@pytest.fixture(scope="function")
def reset_max_appointments_limit(cursor, connection, service_name):
    yield
    cursor.execute(
        "UPDATE appointment_service SET max_appointments_limit = NULL WHERE name = %s",
        [service_name]
    )
    
    connection.commit()