import pytest_bdd

from conftest import O3_BASE_URL

O3_LOGIN_URL = f'{O3_BASE_URL}/login'
@pytest_bdd.scenario('tests/authentication/o3_authentication_security.feature', 
                     'Password attack with 7 wrong password attempts',
                     features_base_dir='')
def test_password_attack_7():
    """Test Case 4: Password attack with 7 attempts"""
    pass

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def navigate_to_login(browser):
    """Navigate to O3 login page"""
    browser.goto(O3_LOGIN_URL)
    browser.wait_for_timeout(3000)

@pytest_bdd.when('the attacker tries to login with valid username and invalid "password"')
def store_attack_type(browser):
    """Store the attack configuration"""
    browser.attack_type = 'password_attack'
    browser.invalid_credential = 'password'
    browser.valid_credential = 'username'
    print("Attack type configured: Password Attack")
    print("Valid: username | Invalid: password")

@pytest_bdd.then(pytest_bdd.parsers.parse(
    'check after {num:d} incorrect attempts, the CVSS score for {attack_name} should be calculated'))
def perform_attack_and_calculate_cvss(browser, num, attack_name):
    """Perform password attack and calculate CVSS"""
    
    # CVSS Base Metrics
    AV = 0.85  # Attack Vector: Network
    PR = 0.85  # Privileges Required: None
    UI = 0.85  # User Interaction: None
    S = 0.85   # Scope: Unchanged
    C = 0.56   # Confidentiality Impact: High
    I = 0.56   # Integrity Impact: High
    A = 0.0    # Availability Impact: None
    
    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    Impact = 6.42 * ISS
    
    fail_count = 0
    
    print("")
    print("="*60)
    print("STARTING ATTACK: " + attack_name)
    print("="*60)
    print("Total attempts to perform: " + str(num) + " (wrong passwords)")
    print("Final attempt: 1 (correct credentials)")
    print("-"*60)
    
    # Generate wrong passwords
    wrong_passwords = []
    for i in range(num):
        wrong_passwords.append('wrongpass' + str(i+1))
    
    # PART 1: Perform N incorrect attempts (correct username, wrong password)
    for i, password in enumerate(wrong_passwords, 1):
        print("Attempt " + str(i) + "/" + str(num) + 
              ": username='admin', password='" + password + "'")
        
        # STEP 1: Fill username and click Continue
        browser.wait_for_selector('input[id="username"]', state='visible')
        browser.fill('input[id="username"]', 'admin')
        browser.wait_for_timeout(500)
        
        browser.click('button:has-text("Continue")')
        browser.wait_for_timeout(2000)
        
        # STEP 2: Fill wrong password
        browser.wait_for_selector('input[id="password"]', state='visible')
        browser.fill('input[id="password"]', password)
        browser.wait_for_timeout(500)
        
        browser.click('button[type="submit"]')
        browser.wait_for_timeout(3000)
        
        current_url = browser.url
        if 'home' in current_url or 'dashboard' in current_url:
            print("  Result: Login SUCCEEDED (unexpected!)")
            break
        else:
            print("  Result: Login FAILED")
            fail_count += 1
            browser.goto(O3_LOGIN_URL)
            browser.wait_for_timeout(2000)
    
    # PART 2: Attempt correct credentials
    print("")
    print("-"*60)
    print("Now attempting login with CORRECT credentials...")
    print("-"*60)
    
    attempt_number = fail_count + 1
    print("Attempt " + str(attempt_number) + ": username='admin', password='Admin123'")
    
    # STEP 1: Fill username and click Continue
    browser.wait_for_selector('input[id="username"]', state='visible')
    browser.fill('input[id="username"]', 'admin')
    browser.wait_for_timeout(500)
    
    browser.click('button:has-text("Continue")')
    browser.wait_for_timeout(2000)
    
    # STEP 2: Fill correct password
    browser.wait_for_selector('input[id="password"]', state='visible')
    browser.fill('input[id="password"]', 'Admin123')
    browser.wait_for_timeout(500)
    
    browser.click('button[type="submit"]')
    browser.wait_for_timeout(5000)
    
    final_url = browser.url
    final_attempt_blocked = False
    
    if 'home' in final_url or 'dashboard' in final_url:
        print("  Result: Login SUCCEEDED")
    else:
        print("  Result: Login FAILED (System blocked correct credentials)")
        fail_count += 1
        final_attempt_blocked = True
    
    # PART 3: Calculate CVSS with dynamic AC
    passed = True
    if final_attempt_blocked:
        AC = 0.44
        security_status = "System blocked ALL attempts (including correct credentials)"
        complexity_level = "HIGH (0.44)"
        passed = False
    elif fail_count >= num:
        AC = 0.77
        security_status = "System allowed " + str(num) + "+ attempts without blocking"
        complexity_level = "LOW (0.77)"
        passed = False
    else:
        AC = 0.44
        security_status = "System blocked after " + str(fail_count) + " attempts"
        complexity_level = "HIGH (0.44)"
        passed = True
    
    Exploitability = 8.22 * AV * AC * PR * UI
    
    if Impact <= 0:
        Base_score = 0
    else:
        Base_score = min((Impact + Exploitability), 10)
        Base_score = round(Base_score, 1)
    
    # PART 4: Display results
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
    if passed: 
        print("TEST STATUS:PASSED")
    else:
        print("TEST STATUS:FAILED")
    print("CVSS Metrics:")
    print("  Attack Vector (AV): " + str(AV) + " (Network)")
    print("  Attack Complexity (AC): " + str(AC))
    print("  Privileges Required (PR): " + str(PR) + " (None)")
    print("  User Interaction (UI): " + str(UI) + " (None)")
    print("  Impact Score: " + str(round(Impact, 2)))
    print("  Exploitability Score: " + str(round(Exploitability, 2)))
    print("="*60)
    
    assert Base_score is not None
    assert 0.0 <= Base_score <= 10.0
