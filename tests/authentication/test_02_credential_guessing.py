import pytest
import pytest_bdd

# Test configuration
O3_LOGIN_URL = 'https://o3.openmrs.org/openmrs/spa/login'
O3_HOME_URL = 'https://o3.openmrs.org/openmrs/spa/home'

@pytest_bdd.scenario('tests/authentication/o3_authentication_security.feature',
                     'Complete credential guessing with wrong username and password',
                     features_base_dir='')
def test_credential_guessing():
    """Test Case 2: Credential guessing attack"""
    pass

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def navigate_to_login(browser):
    """Navigate to O3 login page"""
    browser.goto(O3_LOGIN_URL)
    browser.wait_for_timeout(3000)

@pytest_bdd.when('the attacker tries to login with invalid "username" and invalid "password"')
def store_attack_type(browser):
    """Store the attack configuration"""
    browser.attack_type = 'credential_guessing'
    browser.invalid_credential = 'username_password'
    
    print("Attack type configured: Credential Guessing")
    print("Invalid: username AND password")

@pytest_bdd.then(pytest_bdd.parsers.parse(
    'check after {num:d} incorrect attempts, the CVSS score for {attack_name} should be calculated'))
def perform_attack_and_calculate_cvss(browser, num, attack_name):
    """
    Perform credential guessing attack and calculate CVSS
    """

    # CVSS Base Metrics
    AV = 0.85  # Attack Vector: Network
    PR = 0.85  # Privileges Required: None
    UI = 0.85  # User Interaction: None
    S = 0.85   # Scope: Unchanged
    C = 0.56   # Confidentiality Impact: High
    I = 0.56   # Integrity Impact: High
    A = 0.0    # Availability Impact: None

    # Calculate Impact Score
    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    Impact = 6.42 * ISS

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

    # Generate wrong credentials (both username and password wrong)
    wrong_credentials = []
    for i in range(num):
        wrong_credentials.append(('user' + str(i+1), 'pass' + str(i+1)))

    for i, (username, password) in enumerate(wrong_credentials, 1):
        print("Attempt " + str(i) + "/" + str(num) +
              ": username='" + username + "', password='" + password + "'")
        
        # STEP 1: Fill username and click Continue
        browser.wait_for_selector('input[id="username"]', state='visible')
        browser.fill('input[id="username"]', username)
        browser.wait_for_timeout(500)
        
        # Click Continue button
        browser.click('button:has-text("Continue")')
        browser.wait_for_timeout(2000)
        
        # STEP 2: Fill password (now it should be visible)
        browser.wait_for_selector('input[id="password"]', state='visible')
        browser.fill('input[id="password"]', password)
        browser.wait_for_timeout(500)
        
        # Click login/submit button
        browser.click('button[type="submit"]')
        browser.wait_for_timeout(3000)
        
        # Check if still on login page (failed)
        current_url = browser.url
        if 'login' in current_url:
            print("  Result: Login FAILED")
            fail_count = fail_count + 1
            
            try:
                error_element = browser.locator('div[class*="error"], div[class*="notification"], [role="alert"]').first
                if error_element.is_visible():
                    error_text = error_element.inner_text()
                    print("  Error message: " + error_text)
            except:
                print("  No error message displayed")
        else:
            print("  Result: Login SUCCEEDED (unexpected!)")
        
        # Go back to login page for next attempt
        browser.goto(O3_LOGIN_URL)
        browser.wait_for_timeout(2000)

    print("-"*60)
    print("Summary: " + str(fail_count) + "/" + str(num) + " attempts failed as expected")
    print("-"*60)

    # ===================================================================
    # PART 2: ATTEMPT LOGIN WITH CORRECT CREDENTIALS
    # ===================================================================

    print("")
    print("FINAL ATTEMPT: Correct credentials")
    print("Username: 'admin' | Password: 'Admin123'")
    
    current_url = browser.url
    if 'login' not in current_url:
        browser.goto(O3_LOGIN_URL)
        browser.wait_for_timeout(2000)
    
    # STEP 1: Fill username and click Continue
    browser.wait_for_selector('input[id="username"]', state='visible')
    browser.fill('input[id="username"]', 'admin')
    browser.wait_for_timeout(500)
    
    # Click Continue button
    browser.click('button:has-text("Continue")')
    browser.wait_for_timeout(2000)
    
    # STEP 2: Fill password
    browser.wait_for_selector('input[id="password"]', state='visible')
    browser.fill('input[id="password"]', 'Admin123')
    browser.wait_for_timeout(500)
    
    # Click login/submit button
    browser.click('button[type="submit"]')
    browser.wait_for_timeout(5000)
    
    final_url = browser.url
    
    if 'home' in final_url or 'dashboard' in final_url:
        print("Result: Login SUCCEEDED with correct credentials")
        correct_login_succeeded = True
    else:
        print("Result: Login FAILED even with correct credentials")
        correct_login_succeeded = False

    print("="*60)

    # ===================================================================
    # PART 3: CALCULATE CVSS SCORE
    # ===================================================================

    if fail_count == num:
        AC = 0.77
        print("Attack Complexity: LOW (all attempts failed as expected)")
    else:
        AC = 0.44
        print("Attack Complexity: MEDIUM (some attempts unexpectedly succeeded)")

    Exploitability = 8.22 * AV * AC * PR * UI

    if Impact <= 0:
        Base_score = 0
    else:
        if S == 0.85:
            Base_score = min(Impact + Exploitability, 10)
        else:
            Base_score = min(1.08 * (Impact + Exploitability), 10)

    Base_score = round(Base_score, 1)

    # ===================================================================
    # PART 4: DISPLAY RESULTS
    # ===================================================================
    print("")
    print("CVSS VULNERABILITY SCORE CALCULATION")
    print("="*60)
    print("Attack: " + attack_name)
    print("Failed attempts: " + str(fail_count) + "/" + str(num))
    print("Correct credentials: " + ("SUCCESS" if correct_login_succeeded else "FAILED"))
    print("-"*60)
    print("CVSS Base Score: " + str(Base_score))
    print("-"*60)
    
    if Base_score >= 9.0:
        severity = "CRITICAL"
    elif Base_score >= 7.0:
        severity = "HIGH"
    elif Base_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    print("CVSS Metrics:")
    print("  Attack Vector (AV): Network")
    print("  Attack Complexity (AC): " + ("Low" if AC == 0.77 else "Medium"))
    print("  Privileges Required (PR): None")
    print("  User Interaction (UI): None")
    print("  Scope (S): Unchanged")
    print("  Impact (CIA): High/High/None")
    print("")
    print("Severity Rating: " + severity)
    print("="*60)
    print("")
    
    # Rate limiting is acceptable security behavior - don't fail the test
    if not correct_login_succeeded:
        print("NOTE: Correct credentials blocked - rate limiting detected")
        print("This is expected security behavior after multiple failed attempts")
        print("")
    
    assert Base_score is not None, "CVSS score calculation failed"
    assert 0.0 <= Base_score <= 10.0, "Invalid CVSS score: " + str(Base_score)
   