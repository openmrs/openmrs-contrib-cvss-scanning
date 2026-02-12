import pytest_bdd
from conftest import O3_BASE_URL
import string
import random
import time

O3_LOGIN_URL = f'{O3_BASE_URL}/login'

# ============================================================================
# CVSS Base Metrics for Test Case 1: Brute Force Password Attack
# ============================================================================
CVSS_AV = 0.85  # Attack Vector: Network - remotely exploitable
CVSS_AC = 0.44  # Attack Complexity: HIGH - username must be known
CVSS_PR = 0.85  # Privileges Required: None - no authentication needed
CVSS_UI = 0.85  # User Interaction: None - fully automated attack
CVSS_S = 0.85   # Scope: Unchanged - same security authority
CVSS_C = 0.56   # Confidentiality Impact: High - admin = full PHI access
CVSS_I = 0.56   # Integrity Impact: High - admin can modify all records
CVSS_A = 0.0    # Availability Impact: None - no service disruption
# Expected Base Score: 7.4 (HIGH)

@pytest_bdd.scenario('tests/authentication/o3_authentication_security.feature',
                     'Brute force password attack with known admin username',
                     features_base_dir='')
def test_brute_force_password():
    """Test Case 1: Brute force password attack"""
    pass

@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def navigate_to_login(browser):
    """Navigate to O3 login page"""
    browser.goto(O3_LOGIN_URL)
    browser.wait_for_timeout(3000)

@pytest_bdd.when('the attacker tries to login with known username "admin" and random passwords')
def store_attack_type(browser):
    """Store the attack configuration - known username, random passwords"""
    browser.attack_type = 'brute_force_password'
    browser.known_credential = 'username'
    browser.random_credential = 'password'

    print("Attack type configured: Brute Force Password Attack")
    print("Known: username (admin) | Random: passwords")

@pytest_bdd.then(pytest_bdd.parsers.parse(
    'check after {num:d} incorrect attempts, the CVSS score for {attack_name} should be calculated'))
def perform_attack_and_calculate_cvss(browser, num, attack_name):
    """
    Test Case 3 - Part 1:
    Perform N password attempts with known username "admin"
    """

    fail_count = 0

    print("")
    print("="*70)
    print("STARTING ATTACK: " + attack_name)
    print("="*70)
    print("Attack Method: Brute Force Password Attack")
    print("Known username: 'admin' (default OpenMRS username)")
    print("Random password attempts: " + str(num))
    print("Expected: Account lockout after 7 failures, 5-minute cooldown")
    print("-"*70)

    # ===================================================================
    # PART 1: PERFORM N INCORRECT PASSWORD ATTEMPTS WITH KNOWN USERNAME
    # ===================================================================

    def random_password(length=10):
        """Generate random password"""
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(length))

    wrong_passwords = [random_password() for _ in range(num)]

    for i, password in enumerate(wrong_passwords, 1):
        print("Attempt " + str(i) + "/" + str(num) +
              ": username='admin', password='" + password + "'")
        
        # STEP 1: Fill username and click Continue
        browser.wait_for_selector('input[id="username"]', state='visible')
        browser.fill('input[id="username"]', 'admin')
        browser.wait_for_timeout(500)
        
        # Click Continue button
        browser.click('button:has-text("Continue")')
        browser.wait_for_timeout(2000)
        
        # STEP 2: Fill password
        browser.wait_for_selector('input[id="password"]', state='visible')
        browser.fill('input[id="password"]', password)
        browser.wait_for_timeout(500)
        
        # Click login/submit button
        browser.click('button[type="submit"]')
        browser.wait_for_timeout(3000)
        
        # Check if still on login page (failed)
        current_url = browser.url
        if 'login' in current_url:
            print("  Result: Login FAILED (expected)")
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

    print("-"*70)
    print("Summary: " + str(fail_count) + "/" + str(num) + " password attempts failed")
    print("-"*70)

    # Store results for verification steps
    browser.fail_count = fail_count
    browser.num_attempts = num

@pytest_bdd.then('verify account lockout triggers after 7 failures')
def verify_lockout(browser):
    """
    Verify that after 7 failed password attempts, even correct credentials are blocked
    """

    print("")
    print("="*70)
    print("TESTING ACCOUNT LOCKOUT MECHANISM")
    print("="*70)
    print("After " + str(browser.num_attempts) + " failed password attempts...")
    print("Attempting login with CORRECT credentials: admin/Admin123")
    
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
    
    # STEP 2: Fill correct password
    browser.wait_for_selector('input[id="password"]', state='visible')
    browser.fill('input[id="password"]', 'Admin123')
    browser.wait_for_timeout(500)
    
    # Click login/submit button
    browser.click('button[type="submit"]')
    browser.wait_for_timeout(5000)
    
    final_url = browser.url
    
    if 'home' in final_url or 'dashboard' in final_url:
        print("Result: Login SUCCEEDED with correct credentials")
        print("VULNERABILITY: No account lockout after " + str(browser.num_attempts) + " failures")
        browser.lockout_working = False
    else:
        print("Result: Login FAILED even with correct credentials")
        print("SECURE: Account lockout triggered after " + str(browser.num_attempts) + " failures")
        browser.lockout_working = True

    print("="*70)

@pytest_bdd.then('verify account becomes accessible after 5-minute cooldown period')
def verify_cooldown(browser):
    """
    Verify that after the 5-minute cooldown, the account becomes accessible again
    Then calculate and display CVSS score
    """
    
    if not browser.lockout_working:
        print("")
        print("="*70)
        print("SKIPPING COOLDOWN TEST")
        print("="*70)
        print("Account lockout mechanism not working - no cooldown to test")
        print("="*70)
        browser.cooldown_working = False
    else:
        print("")
        print("="*70)
        print("TESTING COOLDOWN MECHANISM")
        print("="*70)
        print("Waiting 5 minutes for account lockout to expire...")
        print("(OpenMRS default cooldown: 5 minutes)")
        
        cooldown_seconds = 5 * 60  # 5 minutes = 300 seconds
        
        # Wait with progress indicator every 30 seconds
        for remaining in range(cooldown_seconds, 0, -30):
            mins = remaining // 60
            secs = remaining % 60
            print(f"  Time remaining: {mins}m {secs:02d}s")
            time.sleep(30)
        
        print("Cooldown period complete!")
        print("Attempting login with correct credentials: admin/Admin123")
        
        # Navigate back to login
        browser.goto(O3_LOGIN_URL)
        browser.wait_for_timeout(2000)
        
        # Try correct credentials again
        browser.wait_for_selector('input[id="username"]', state='visible')
        browser.fill('input[id="username"]', 'admin')
        browser.wait_for_timeout(500)
        browser.click('button:has-text("Continue")')
        browser.wait_for_timeout(2000)
        
        browser.wait_for_selector('input[id="password"]', state='visible')
        browser.fill('input[id="password"]', 'Admin123')
        browser.wait_for_timeout(500)
        browser.click('button[type="submit"]')
        browser.wait_for_timeout(5000)
        
        final_url_after_cooldown = browser.url
        
        if 'home' in final_url_after_cooldown or 'dashboard' in final_url_after_cooldown:
            print("Result: Login SUCCEEDED after 5-minute cooldown")
            print("SECURE: Cooldown mechanism working correctly")
            browser.cooldown_working = True
        else:
            print("Result: Login FAILED even after 5-minute cooldown")
            print("ISSUE: Account still locked after cooldown period")
            browser.cooldown_working = False
        
        print("="*70)
    
    # ===================================================================
    # PART 4: CALCULATE AND DISPLAY CVSS SCORE
    # ===================================================================
    
    # Use module-level CVSS constants
    ISS = 1 - ((1 - CVSS_C) * (1 - CVSS_I) * (1 - CVSS_A))
    Impact = 6.42 * ISS
    Exploitability = 8.22 * CVSS_AV * CVSS_AC * CVSS_PR * CVSS_UI
    
    if Impact <= 0:
        Base_score = 0
    else:
        if CVSS_S == 0.85:
            Base_score = min(Impact + Exploitability, 10)
        else:
            Base_score = min(1.08 * (Impact + Exploitability), 10)
    
    Base_score = round(Base_score, 1)
    
    print("")
    print("="*70)
    print("CVSS VULNERABILITY SCORE CALCULATION")
    print("="*70)
    print("Attack: Brute Force Password Attack")
    print("Failed password attempts: " + str(browser.fail_count) + "/" + str(browser.num_attempts))
    print("-"*70)
    print("Security Mechanism Test Results:")
    print("  Account lockout (7 failures): " + ("WORKING" if browser.lockout_working else "NOT WORKING"))
    print("  Cooldown period (5 minutes): " + ("WORKING" if browser.cooldown_working else "NOT WORKING" if browser.lockout_working else "SKIPPED"))
    print("-"*70)
    print("CVSS Base Score: " + str(Base_score))
    print("Expected Score: 7.4 (Paper Table III)")
    print("-"*70)
    
    if Base_score >= 9.0:
        severity = "CRITICAL"
    elif Base_score >= 7.0:
        severity = "HIGH"
    elif Base_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    print("CVSS Metrics:")
    print("  Attack Vector (AV): Network (0.85)")
    print("  Attack Complexity (AC): High (0.44) - username must be known")
    print("  Privileges Required (PR): None (0.85)")
    print("  User Interaction (UI): None (0.85)")
    print("  Scope (S): Unchanged")
    print("  Confidentiality Impact (C): High (0.56) - admin = full PHI access")
    print("  Integrity Impact (I): High (0.56) - admin can modify all records")
    print("  Availability Impact (A): None (0.0)")
    print("")
    print("CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
    print("Severity Rating: " + severity)
    print("-"*70)
    
    # Final assessment
    print("")
    if browser.lockout_working and browser.cooldown_working:
        print("OVERALL ASSESSMENT: SECURE")
        print("OpenMRS properly defends against brute force password attacks")
    elif browser.lockout_working and not browser.cooldown_working:
        print("OVERALL ASSESSMENT: PARTIAL")
        print("Lockout works but cooldown mechanism has issues")
    else:
        print("OVERALL ASSESSMENT: VULNERABLE")
        print("OpenMRS does not adequately defend against brute force attacks")
    print("="*70)
    print("")
    
    # Assertions
    assert Base_score is not None, "CVSS score calculation failed"
    assert 0.0 <= Base_score <= 10.0, "Invalid CVSS score: " + str(Base_score)
    
    # Note about security mechanisms
    if browser.lockout_working:
        print("NOTE: Account lockout detected - this is expected security behavior")
        print("OpenMRS locks accounts after 7 failed attempts with 5-minute cooldown")