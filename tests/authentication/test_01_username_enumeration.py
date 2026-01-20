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

# Test configuration
O3_LOGIN_URL = 'https://o3.openmrs.org/openmrs/spa/login'
O3_HOME_URL = 'https://o3.openmrs.org/openmrs/spa/home'

@pytest.fixture
def browser():
    """Initialize Chrome browser for testing"""
    driver = Chrome(options=options)
    driver.implicitly_wait(10)
    yield driver
    driver.quit()

@pytest_bdd.scenario('o3_authentication_security.feature', 
                     'Username enumeration with wrong usernames',
                     features_base_dir='')
def test_username_enumeration():
    """Test Case 1: Username enumeration attack"""
    pass

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def navigate_to_login(browser):
    """Navigate to O3 login page"""
    browser.get(O3_LOGIN_URL)
    time.sleep(3)

@pytest_bdd.when('the attacker tries to login with invalid "username" and valid password')
def store_attack_type(browser):
    """Store the attack configuration (Purkayastha style - just setup)"""
    # Store what credentials are invalid/valid
    browser.attack_type = 'username_enumeration'
    browser.invalid_credential = 'username'
    browser.valid_credential = 'password'
    
    print("Attack type configured: Username Enumeration")
    print("Invalid: username | Valid: password")

@pytest_bdd.then(pytest_bdd.parsers.parse(
    'check after {num:d} incorrect attempts, the CVSS score for {attack_name} should be calculated'))
def perform_attack_and_calculate_cvss(browser, num, attack_name):
    """
    Purkayastha style: This step does EVERYTHING
    1. Perform N incorrect login attempts
    2. Try correct credentials
    3. Calculate CVSS score
    4. Display results
    """
    
    # CVSS Base Metrics (constant for all authentication tests)
    AV = 0.85  # Attack Vector: Network
    PR = 0.85  # Privileges Required: None
    UI = 0.85  # User Interaction: None
    S = 0.85   # Scope: Unchanged
    C = 0.56   # Confidentiality Impact: High
    I = 0.56   # Integrity Impact: High
    A = 0.56   # Availability Impact: High
    
    # Calculate Impact Score
    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    Impact = 6.42 * ISS
    
    wait = WebDriverWait(browser, 10)
    fail_count = 0
    
    print("")
    print("="*60)
    print("STARTING ATTACK: " + attack_name)
    print("="*60)
    print("Total attempts to perform: " + str(num) + " (wrong credentials)")
    print("Final attempt: 1 (correct credentials)")
    print("-"*60)
    
    # ===================================================================
    # PART 1: PERFORM N INCORRECT LOGIN ATTEMPTS
    # ===================================================================
    
    # Generate wrong usernames for testing
    wrong_usernames = []
    for i in range(num):
        wrong_usernames.append('user' + str(i+1))
    
    # Attempt logins with wrong usernames + correct password
    for i, username in enumerate(wrong_usernames, 1):
        print("Attempt " + str(i) + "/" + str(num) + 
              ": username='" + username + "', password='Admin123'")
        
        time.sleep(2)
        
        # Enter username
        username_field = wait.until(EC.presence_of_element_located((By.ID, 'username')))
        username_field.clear()
        username_field.send_keys(username)
        
        # Click Continue button
        try:
            button = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Continue') or contains(text(), 'Log in')]")))
            button.click()
        except:
            button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.cds--btn--primary")))
            button.click()
        
        time.sleep(3)
        
        # Enter password if field appears
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
        
        # Check result
        if O3_HOME_URL in browser.current_url:
            print("  Result: Login SUCCEEDED (unexpected!)")
            break
        else:
            print("  Result: Login FAILED")
            fail_count += 1
            browser.get(O3_LOGIN_URL)
            time.sleep(2)
    
    # ===================================================================
    # PART 2: ATTEMPT LOGIN WITH CORRECT CREDENTIALS
    # ===================================================================
    
    print("")
    print("-"*60)
    print("Now attempting login with CORRECT credentials...")
    print("-"*60)
    
    attempt_number = fail_count + 1
    print("Attempt " + str(attempt_number) + ": username='admin', password='Admin123'")
    
    time.sleep(2)
    
    # Enter correct username
    username_field = wait.until(EC.presence_of_element_located((By.ID, 'username')))
    username_field.clear()
    username_field.send_keys('admin')
    
    # Click Continue
    try:
        button = wait.until(EC.element_to_be_clickable(
            (By.XPATH, "//button[contains(text(), 'Continue') or contains(text(), 'Log in')]")))
        button.click()
    except:
        button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.cds--btn--primary")))
        button.click()
    
    time.sleep(3)
    
    # Enter correct password
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
    
    # Check if correct credentials succeeded or were blocked
    final_attempt_blocked = False
    if O3_HOME_URL in browser.current_url:
        print("  Result: Login SUCCEEDED")
    else:
        print("  Result: Login FAILED (System blocked correct credentials)")
        fail_count += 1
        final_attempt_blocked = True
    
    # ===================================================================
    # PART 3: CALCULATE CVSS SCORE
    # ===================================================================
    
    # Determine Attack Complexity based on blocking behavior
    if final_attempt_blocked:
        # System blocked even correct credentials - Has strong blocking
        AC = 0.44  # HIGH complexity (hard to exploit)
        security_status = "System blocked ALL attempts (including correct credentials)"
        complexity_level = "HIGH (0.44)"
    elif fail_count >= num:
        # All wrong attempts failed but correct succeeded - No rate limiting
        AC = 0.77  # LOW complexity (easy to exploit)
        security_status = "System allowed " + str(num) + "+ attempts without blocking"
        complexity_level = "LOW (0.77)"
    else:
        # Blocked before N attempts - Has protection
        AC = 0.44  # HIGH complexity
        security_status = "System blocked after " + str(fail_count) + " attempts"
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
    # PART 4: DISPLAY RESULTS
    # ===================================================================
    
    print("")
    print("="*60)
    print("CVSS VULNERABILITY SCORE CALCULATION")
    print("="*60)
    print("Test: " + attack_name)
    print("Security Status: " + security_status)
    print("Attack Complexity: " + complexity_level)
    print("-"*60)
    print("CVSS Base Score: " + str(Base_score))
    print("-"*60)
    print("Total login attempts: " + str(attempt_number))
    print("Failed attempts: " + str(fail_count))
    print("Correct credentials blocked: " + ("YES" if final_attempt_blocked else "NO"))
    print("")
    print("CVSS Metrics:")
    print("  Attack Vector (AV): " + str(AV) + " (Network)")
    print("  Attack Complexity (AC): " + str(AC))
    print("  Privileges Required (PR): " + str(PR) + " (None)")
    print("  User Interaction (UI): " + str(UI) + " (None)")
    print("  Impact Score: " + str(round(Impact, 2)))
    print("  Exploitability Score: " + str(round(Exploitability, 2)))
    print("="*60)
    
    # Assert for pytest
    assert Base_score is not None, "CVSS score calculation failed"
    assert 0.0 <= Base_score <= 10.0, "Invalid CVSS score: " + str(Base_score)
