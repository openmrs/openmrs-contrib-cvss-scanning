import pytest
import pytest_bdd
from selenium.webdriver import Chrome
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Chrome configuration for headless mode
options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

patient_uuid = '84f728b5-4ca8-419f-95d6-fe8acaacc95a'

# Test configuration
O3_LOGIN_URL = 'https://o3.openmrs.org/openmrs/spa/login'
O3_EDIT_PATIENT_URL = 'https://o3.openmrs.org/openmrs/spa/patient/{patient_uuid}/edit'

# Page element IDs
MIDDLE_NAME_FIELD = 'middleName'
UPDATE_PATIENT_BUTTON_CLASS = '-esm-patient-registration__patient-registration__submitButton___Ps1do'

@pytest.fixture
def browser():
    """Initialize Chrome browser for testing"""
    driver = Chrome(options=options)
    driver.implicitly_wait(10)
    yield driver
    driver.quit()

@pytest_bdd.scenario('o3_xss_security.feature', 
                     'XSS injection on patient edit page',
                     features_base_dir='')
def test_xss_injection():
    """Test Case 1: XSS injection attack"""
    pass

@pytest_bdd.given('the OpenMRS 3 edit patient page is displayed')
def navigate_to_edit_patient(browser):
    """Navigate to O3 login and then to edit patient page"""
    # First login
    browser.get(O3_LOGIN_URL)
    time.sleep(3)
    
    wait = WebDriverWait(browser, 10)
    
    # Enter username
    username_field = wait.until(EC.presence_of_element_located((By.ID, 'username')))
    username_field.clear()
    username_field.send_keys('admin')
    
    # Click Continue button
    try:
        button = wait.until(EC.element_to_be_clickable(
            (By.XPATH, "//button[contains(text(), 'Continue') or contains(text(), 'Log in')]")))
        button.click()
    except:
        button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.cds--btn--primary")))
        button.click()
    
    time.sleep(3)
    
    # Enter password
    try:
        password_field = browser.find_element(By.ID, 'password')
        if password_field.is_displayed():
            password_field.clear()
            password_field.send_keys('Admin123')
            
            login_btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Log in')]")))
            login_btn.click()
            
            time.sleep(3)
    except:
        pass
    
    # Navigate to edit patient page (using a test patient UUID)
    # Note: You'll need to replace this with an actual patient UUID from your system
    patient_uuid = '9d231338-ff73-487d-8ae6-526ae31dba07'  # Replace with actual UUID
    edit_url = O3_EDIT_PATIENT_URL.format(patient_uuid=patient_uuid)
    browser.get(edit_url)
    time.sleep(3)

@pytest_bdd.when('the attacker tries to edit a patient middle name to make an alert when perform XSS')
def store_attack_type(browser):
    """Store the attack configuration (Purkayastha style - just setup)"""
    # Store what type of XSS attack we're performing
    browser.attack_type = 'xss_injection'
    browser.injection_field = 'middle_name'
    
    print("Attack type configured: XSS Injection")
    print("Target field: Middle Name")

@pytest_bdd.then('check if an alert was made, if so, calculate CVSS score.')
def perform_xss_attack_and_calculate_cvss(browser):
    """
    Purkayastha style: This step does EVERYTHING
    1. Inject XSS payloads into middle name field
    2. Check if alerts are triggered
    3. Calculate CVSS score based on vulnerability
    4. Display results
    """
    
    # CVSS Base Metrics (constant for XSS tests)
    AV = 0.85  # Attack Vector: Network
    PR = 0.62  # Privileges Required: Low (needs authenticated user)
    UI = 0.85  # User Interaction: None (for stored XSS)
    S = 0.85   # Scope: Unchanged
    C = 0.22   # Confidentiality Impact: Low (can steal some data)
    I = 0.22   # Integrity Impact: Low (can modify some content)
    A = 0.0    # Availability Impact: None
    
    # Calculate Impact Score
    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    Impact = 6.42 * ISS
    
    wait = WebDriverWait(browser, 10)
    xss_triggered = False
    
    print("")
    print("="*60)
    print("STARTING ATTACK: XSS Injection on Patient Edit Page")
    print("="*60)
    print("Target: Middle Name Field")
    print("Element ID: " + MIDDLE_NAME_FIELD)
    print("-"*60)
    
    # ===================================================================
    # PART 1: XSS PAYLOAD INJECTION
    # ===================================================================
    
    # Common XSS payloads to test
    xss_payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "javascript:alert('XSS')"
    ]
    
    payload_results = []
    
    for i, payload in enumerate(xss_payloads, 1):
        print("Attempt " + str(i) + "/" + str(len(xss_payloads)))
        print("Payload: " + payload)
        
        time.sleep(2)
        
        try:
            # Find and clear the middle name field
            middle_name_field = wait.until(
                EC.presence_of_element_located((By.ID, MIDDLE_NAME_FIELD)))
            middle_name_field.clear()
            middle_name_field.send_keys(payload)
            
            print("  Payload entered into middle name field")
            
            # Click Update Patient button
            update_button = wait.until(
                EC.element_to_be_clickable((By.CLASS_NAME, UPDATE_PATIENT_BUTTON_CLASS)))
            update_button.click()
            
            time.sleep(2)
            
            # Check for JavaScript alert
            try:
                alert = browser.switch_to.alert
                alert_text = alert.text
                print("  Result: XSS ALERT TRIGGERED!")
                print("  Alert text: " + alert_text)
                alert.accept()
                xss_triggered = True
                payload_results.append({
                    'payload': payload,
                    'triggered': True
                })
                break  # Stop testing if we found a vulnerability
            except:
                print("  Result: No alert triggered (payload blocked or sanitized)")
                payload_results.append({
                    'payload': payload,
                    'triggered': False
                })
            
            # Navigate back to edit page for next attempt
            browser.back()
            time.sleep(2)
            
        except Exception as e:
            #print("  Result: Error during injection - " + str(e))
            payload_results.append({
                'payload': payload,
                'triggered': False
                #'error': str(e)
            })
    
    # ===================================================================
    # PART 2: CALCULATE CVSS SCORE
    # ===================================================================
    
    # Determine Attack Complexity based on XSS results
    if xss_triggered:
        # XSS was successful - LOW complexity (easy to exploit)
        AC = 0.77
        security_status = "VULNERABLE - XSS payload executed successfully"
        complexity_level = "LOW (0.77)"
    else:
        # XSS was blocked - HIGH complexity (hard to exploit)
        AC = 0.44
        security_status = "PROTECTED - All XSS payloads blocked or sanitized"
        complexity_level = "HIGH (0.44)"
    
    # Calculate Exploitability Score
    Exploitability = 8.22 * AV * AC * PR * UI
    
    # Calculate Base CVSS Score
    if Impact <= 0:
        Base_score = 0
    else:
        Base_score = min((Impact + Exploitability), 10)
        Base_score = round(Base_score, 1)
    
    # ===================================================================
    # PART 3: DISPLAY RESULTS
    # ===================================================================
    
    print("")
    print("="*60)
    print("CVSS VULNERABILITY SCORE CALCULATION")
    print("="*60)
    print("Test: XSS Injection Attack")
    print("Security Status: " + security_status)
    print("Attack Complexity: " + complexity_level)
    print("-"*60)
    print("CVSS Base Score: " + str(Base_score))
    print("-"*60)
    print("Total payloads tested: " + str(len(xss_payloads)))
    print("Successful injections: " + str(sum(1 for r in payload_results if r['triggered'])))
    print("Blocked/Sanitized: " + str(sum(1 for r in payload_results if not r['triggered'])))
    print("")
    print("Payload Results:")
    for j, result in enumerate(payload_results, 1):
        status = "TRIGGERED" if result['triggered'] else "BLOCKED"
        print("  " + str(j) + ". " + status + " - " + result['payload'])
    print("")
    print("CVSS Metrics:")
    print("  Attack Vector (AV): " + str(AV) + " (Network)")
    print("  Attack Complexity (AC): " + str(AC))
    print("  Privileges Required (PR): " + str(PR) + " (Low)")
    print("  User Interaction (UI): " + str(UI) + " (None)")
    print("  Scope (S): " + str(S) + " (Unchanged)")
    print("  Confidentiality (C): " + str(C) + " (Low)")
    print("  Integrity (I): " + str(I) + " (Low)")
    print("  Availability (A): " + str(A) + " (None)")
    print("  Impact Score: " + str(round(Impact, 2)))
    print("  Exploitability Score: " + str(round(Exploitability, 2)))
    print("="*60)
    
    # Assert for pytest
    assert Base_score is not None, "CVSS score calculation failed"
    assert 0.0 <= Base_score <= 10.0, "Invalid CVSS score: " + str(Base_score)
