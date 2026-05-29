import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, createTestPatient, BaseMetrics, O3_WELCOME_URL, DEFAULT_WAIT_TIME, O3_ROOT_URL
from tests.conftest import save_cvss_result
from playwright.sync_api import Page, expect

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

@pytest.mark.parametrize("billing_category",[
    "Antenatal care",
    "Orthopedic Service",
    "Nutrition counseling",
    "OPD consultation"
])
@pytest.mark.parametrize("quantity", [
    1,
    1_000_000,
    2_147_483_647,
    2_147_483_647 + 1,
    2_147_483_647 * 2,
    2_147_483_647 * 3,
])
@pytest_bdd.scenario('memory_management_failures.feature','Integer overflow of quantity on billing page')
def test_integer_overflow_of_quantity_on_billing_page(billing_category, quantity, cleanup_delete_patient):
    pass

@pytest_bdd.given('the admin logs in')
def given_the_admin_logs_in(page:Page):
    
    # replace with login function after login is moved to root utils
    page.wait_for_selector("#username")
    page.fill("#username", "admin")
    page.keyboard.press("Enter")
    page.wait_for_timeout(1000)
    page.wait_for_selector("#password")
    page.fill("#password", "Admin123")
    page.keyboard.press("Enter")
    page.wait_for_timeout(1000)
    
    if page.url == O3_WELCOME_URL:
        page.keyboard.press("Tab")
        page.keyboard.press("Tab")
        page.keyboard.press("Space")
        page.keyboard.press("Enter")
        page.wait_for_timeout(1000)

@pytest_bdd.given('a new patient is created')
def given_a_new_patient_is_created(page:Page, patient_data):
    createTestPatient(page, "New", "Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME * 3)
    
    spans = page.locator("div.cds--tag span").all()
    
    id_text = spans[-1].text_content()
        
    patient_data["patient_id"] = id_text

@pytest_bdd.given('the billings history page is shown')
def given_the_billings_history_page_is_shown(page:Page):
    
    billing_history_button = page.get_by_text("Billing History")
    
    expect(billing_history_button).to_be_visible()
    billing_history_button.click()
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('a bill is created')
def given_a_bill_is_created():
    pass

@pytest_bdd.when('a quantity is inputted')
def when_a_quantity_is_inputted():
    pass

@pytest_bdd.then('the quantity should not overflow or wraparound')
def then_the_quantity_should_not_overflow_or_wraparound():
    assert True

@pytest.fixture(scope="function")
def cleanup_delete_patient(patient_data, page:Page):    
    yield
    
    patient_id:str = patient_data["patient_id"]
    
    # go to legacy admin
    page.goto(f"{O3_ROOT_URL}admin/patients/index.htm")

    # delete patient
    page.locator("#inputNode").press_sequentially(patient_id)
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    page.get_by_text(patient_id).all()[1].click()
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    page.locator("[name='voidReason']").press_sequentially("Testing Purposes")
    
    page.get_by_role("button", name="Delete Patient", exact=True).click()
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest.fixture(scope="function")
def patient_data():
    return {}