import pytest
import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, createTestPatient, login_and_select_default_location, BaseMetrics, DEFAULT_WAIT_TIME
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
])
@pytest_bdd.scenario('memory_management_failures.feature','Integer overflow of quantity on billing page')
def test_integer_overflow_of_quantity_on_billing_page(billing_category, quantity, cleanup_delete_patient):
    pass

@pytest_bdd.given('the admin logs in')
def given_the_admin_logs_in(page:Page):
    login_and_select_default_location(page, "admin", "Admin123")

@pytest_bdd.given('a new patient is created')
def given_a_new_patient_is_created(page:Page, patient_data):
    createTestPatient(page, "New", "Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME * 3)
    
    spans = page.locator("div.cds--tag span").all()
    
    id_text = spans[-1].text_content()
        
    patient_data["patient_id"].append(id_text)

@pytest_bdd.given('the billings history page is shown')
def given_the_billings_history_page_is_shown(page:Page):
    
    billing_history_button = page.get_by_text("Billing History")
    
    expect(billing_history_button).to_be_visible()
    billing_history_button.click()
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('a bill is created')
def given_a_bill_is_created(page:Page, billing_category):
    
    add_bill_items = page.get_by_text("Add bill items", exact=True)
    expect(add_bill_items).to_be_visible()
    add_bill_items.click()
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    search_items_box = page.locator("#searchItems")
    expect(search_items_box).to_be_visible()
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    search_items_box.press_sequentially(billing_category)
    page.keyboard.press("Enter")
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.when('a quantity is inputted')
def when_a_quantity_is_inputted(page:Page, quantity):
    
    quantity_box = page.locator('input[type="number"]')
    expect(quantity_box).to_be_visible()
    quantity_box.fill(str(quantity))
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    
    page.keyboard.press("Enter")
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.then('the quantity should not overflow or wraparound')
def then_the_quantity_should_not_overflow_or_wraparound(page:Page, quantity):
    
    page.locator("td button").click()
    
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
        
    line_items_table = page.locator('table[aria-label="Invoice line items"]')
    expect(line_items_table).to_be_visible()
    
    cells = line_items_table.locator('tbody tr td').all()
    quantity_value = int(cells[3].text_content())
    
    assert quantity_value == quantity