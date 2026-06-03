import pytest
import pytest_bdd
import requests
import base64
from playwright.sync_api import Page

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_API_URL, O3_ROOT_URL, O3_HOME_URL, DEFAULT_WAIT_TIME, O3_WELCOME_URL
from tests.conftest import save_cvss_result


# ── Fixture to share data across steps ────────────────────────────────────────

@pytest.fixture
def scenario_data():
    return {}


# ── Fixture to reset max appointments limit after test ─────────────────────────

@pytest.fixture(scope="function")
def reset_max_appointments_limit(cursor, connection):
    yield
    cursor.execute(
        "UPDATE appointment_service SET max_appointments_limit = NULL WHERE name = 'General Medicine service'"
    )
    
    connection.commit()


# ── CVSS ───────────────────────────────────────────────────────────────────────

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


# ── Scenario ───────────────────────────────────────────────────────────────────

@pytest_bdd.scenario('insecure_design.feature', 'Appointments should be blocked after reaching max load')
def test_appointments_should_be_blocked_after_reaching_max_load(reset_max_appointments_limit):
    pass


# ── Given ──────────────────────────────────────────────────────────────────────

@pytest_bdd.given('3 test patients are created', target_fixture='scenario_data')
def given_3_test_patients_are_created(page: Page):
    data = {}
    data['patient_uuids'] = []

    login(page, "admin", "Admin123")

    for _ in range(3):
        uuid = create_test_patient_and_get_uuid(page)
        data['patient_uuids'].append(uuid)
        print(f"Created patient: {uuid}")

    assert len(data['patient_uuids']) == 3, "Failed to create 3 test patients"
    return data


# ── And ────────────────────────────────────────────────────────────────────────

@pytest_bdd.given('the max appoitment limit for General Medicine services is set to 2', target_fixture='scenario_data')
def and_max_appointment_limit_is_set(scenario_data, cursor, connection):

    # Fetch the service UUID from the API
    jsesh = login_api("admin", "Admin123")
    service_uuid = get_general_medicine_service_uuid(jsesh)
    scenario_data['service_uuid'] = service_uuid

    # Set the max limit to 2 via the database
    cursor.execute(
        "UPDATE appointment_service SET max_appointments_limit = 2 WHERE name = 'General Medicine service'"
    )
    
    connection.commit()

    # Verify it was set
    cursor.execute(
        "SELECT max_appointments_limit FROM appointment_service WHERE name = 'General Medicine service'"
    )
    result = cursor.fetchone()
        
    assert result["max_appointments_limit"] == 2, f"Expected max limit to be 2 but got {result[0]}"

    return scenario_data


# ── When ───────────────────────────────────────────────────────────────────────

@pytest_bdd.when('3 appointment requests are made over the api', target_fixture='scenario_data')
def when_3_appointments_are_made(scenario_data):
    jsesh = login_api("admin", "Admin123")

    successful_bookings = 0
    for patient_uuid in scenario_data['patient_uuids']:
        success = book_appointment(jsesh, patient_uuid, scenario_data['service_uuid'])
        if success:
            successful_bookings += 1

    scenario_data['successful_bookings'] = successful_bookings
    return scenario_data


# ── Then ───────────────────────────────────────────────────────────────────────

@pytest_bdd.then('2 out of 3 appointments should be successful')
def then_2_out_of_3_appointments_should_be_successful(scenario_data):
    successful = scenario_data['successful_bookings']

    # If the system were secure, only 2 should succeed.
    # All 3 succeeding proves the vulnerability — the limit is not enforced.
    assert successful == 2, (
        f"Vulnerability confirmed: all 3 appointments succeeded despite a max limit of 2. "
        f"The system does not enforce maxAppointmentsLimit."
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

def login(page: Page, username, password):
    page.goto(O3_HOME_URL)
    page.wait_for_selector("#username")
    page.fill("#username", username)
    page.keyboard.press("Enter")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.wait_for_selector("#password")
    page.fill("#password", password)
    page.keyboard.press("Enter")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    if page.url == O3_WELCOME_URL:
        page.keyboard.press("Tab")
        page.keyboard.press("Tab")
        page.keyboard.press("Space")
        page.keyboard.press("Enter")
        page.wait_for_timeout(DEFAULT_WAIT_TIME)


def login_api(username, password):

    jsessionid = None

    credentials = base64.b64encode(f'{username}:{password}'.encode()).decode()
    headers = {
        'Authorization': f'Basic {credentials}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(O3_API_URL, headers=headers, timeout=10)
        status_code = response.status_code

        if status_code == 200:
            try:
                print(response.text[:200])
                data = response.json()
                authenticated = data.get('authenticated', False)
                if authenticated:
                    print(f"  Result: Login SUCCEEDED HTTP {status_code}")
                    jsessionid = response.cookies.get("JSESSIONID")
                else:
                    print(f"  Result: Login FAILED HTTP {status_code}")
            except:
                print(f"  Result: HTTP {status_code} (could not parse response)")
        else:
            print(f"  Result: HTTP {status_code}")

    except requests.exceptions.RequestException as e:
        print(f"  Result: Request failed - {e}")

    return jsessionid


def create_test_patient_and_get_uuid(page: Page):
    page.goto(O3_HOME_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Add patient').click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator('#givenName').fill("Test")
    page.locator('#familyName').fill("Patient")
    page.get_by_text("Other").click()

    page.locator("button").get_by_text('No').last.click()
    page.locator('#yearsEstimated').fill("26")
    page.locator('#monthsEstimated').fill("0")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Register patient").click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    # Extract UUID from the URL after redirect e.g. /patient/<uuid>/chart
    url = page.url
    uuid = url.split("/patient/")[1].split("/")[0]
    return uuid


def get_general_medicine_service_uuid(jsessionid):
    url = f"{O3_ROOT_URL}ws/rest/v1/appointments"
    cookies = {"JSESSIONID": jsessionid}

    try:
        response = requests.get(url, params={"v": "full"}, cookies=cookies, timeout=10)
        if response.status_code == 200:
            appointments = response.json()
            for appt in appointments:
                service = appt.get("service", {})
                if service.get("name") == "General Medicine service":
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
        "startDateTime": "2026-06-10T09:00:00.000Z",
        "endDateTime": "2026-06-10T09:30:00.000Z",
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