import pytest_bdd
import string
import random
import time
import os

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, BaseMetrics

O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')
O3_LOGIN_URL = f'{O3_BASE_URL}/login'

# ============================================================================
# DYNAMIC PARAMETER DETECTION FUNCTIONS
# ============================================================================

def determine_attack_requirements(test_results):
    """
    Dynamically determine Attack Requirements based on observed lockout behavior.

    CVSS 4.0 Definition:
    - None (N): Attack can succeed without any special preconditions
    - Present (P): Attack depends on specific deployment/execution conditions

    Logic:
    - If no lockout detected: AT=N (attacker can freely exploit without knowing
      anything specific - any credentials work eventually)
    - If lockout detected: AT=P (attacker must know a valid username "admin"
      to repeatedly target the same account and trigger lockout)

    Args:
        test_results: Dictionary with observed defense mechanisms

    Returns:
        'N' or 'P'
    """
    if test_results.get('account_locked'):
        return BaseMetrics.AttackRequirements.PRESENT  # Present - valid username required to trigger/bypass lockout
    else:
        return BaseMetrics.AttackRequirements.NONE  # None - no special conditions needed


def determine_confidentiality_integrity_impact(test_results):
    """
    Dynamically determine VC and VI based on whether attacker can actually
    gain access to the system.

    CVSS 4.0 Definition:
    - High (H): Total loss of confidentiality/integrity
    - Low (L): Some loss but attacker does not have full control

    Logic:
    - If no lockout: attacker eventually succeeds -> VC:H, VI:H
      (full admin access = all PHI exposed, all records modifiable)
    - If lockout working: attacker is blocked -> VC:L, VI:L
      (partial exposure from error messages only, no actual access)

    Args:
        test_results: Dictionary with observed defense mechanisms

    Returns:
        tuple: (VC, VI) both 'H' or both 'L'
    """
    if test_results.get('account_locked'):
        return BaseMetrics.Confidentiality.VulnerableSystem.LOW, BaseMetrics.Integrity.VulnerableSystem.LOW  # Lockout blocks access - reduced impact
    else:
        return BaseMetrics.Confidentiality.VulnerableSystem.HIGH, BaseMetrics.Integrity.VulnerableSystem.HIGH  # No lockout - full admin access possible


def determine_availability_impact(test_results):
    """
    Dynamically determine Availability Impact based on account lockout duration.

    CVSS 4.0 Definition:
    - None (N): No availability impact
    - Low (L): Reduced performance or temporary unavailability
    - High (H): Total or sustained loss of availability

    Logic:
    - No lockout: VA=N (no availability impact from the attack)
    - Lockout 1-10 min: VA=L (temporary disruption, legitimate user locked out briefly)
    - Lockout >10 min: VA=H (prolonged denial of service to legitimate user)

    Args:
        test_results: Dictionary with lockout duration information

    Returns:
        'N', 'L', or 'H'
    """
    if not test_results.get('account_locked'):
        return BaseMetrics.Availability.VulnerableSystem.NONE  # No lockout = no availability impact

    lockout_duration = test_results.get('lockout_duration_seconds', 0)

    if lockout_duration > 600:
        return BaseMetrics.Availability.VulnerableSystem.HIGH  # High: prolonged lockout >10 minutes
    elif lockout_duration > 60:
        return BaseMetrics.Availability.VulnerableSystem.LOW  # Low: temporary lockout 1-10 minutes
    else:
        return BaseMetrics.Availability.VulnerableSystem.NONE  # None: brief lockout <1 minute

# ============================================================================
# TEST SCENARIO
# ============================================================================

@pytest_bdd.scenario('tests/authentication/o3_authentication_security.feature',
                     'Brute force password attack with known admin username',
                     features_base_dir='')
def test_brute_force_password():
    """
    Tests account lockout and cooldown after 7 failed login attempts with known username "admin". 
    Uses CVSS 4.0 with dynamic scoring based on observed security mechanisms.
    """
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

    print("\n" + "="*70)
    print("ATTACK CONFIGURATION")
    print("="*70)
    print("Attack Type: Brute Force Password Attack (CVSS 4.0)")
    print("Known Credential: username='admin' (default OpenMRS username)")
    print("Random Credential: passwords (10-character random strings)")
    print("="*70)

@pytest_bdd.then(pytest_bdd.parsers.parse(
    'check after {num:d} incorrect attempts, the CVSS score for {attack_name} should be calculated'))
def perform_attack_and_calculate_cvss(browser, num, attack_name):
    """
    Perform N password attempts with known username "admin"
    Track observations for dynamic CVSS parameter determination
    """
    
    # Initialize test results tracking
    browser.test_results = {
        'rate_limiting_detected': False,
        'lockout_at_attempt': None,
        'captcha_required': False,
        'progressive_delays': False,
        'account_locked': False,
        'lockout_duration_seconds': 0,
    }

    fail_count = 0

    print("")
    print("="*70)
    print(f"STARTING ATTACK: {attack_name}")
    print("="*70)
    print(f"Attack Method: Brute Force Password Attack")
    print(f"Known username: 'admin' (default OpenMRS username)")
    print(f"Random password attempts: {num}")
    print(f"Expected: Account lockout after {num} failures, 5-minute cooldown")
    print("-"*70)

    # Generate random passwords
    def random_password(length=10):
        """Generate random password"""
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(length))

    wrong_passwords = [random_password() for _ in range(num)]

    # Perform N incorrect password attempts
    for i, password in enumerate(wrong_passwords, 1):
        print(f"Attempt {i}/{num}: username='admin', password='{password}'")
        
        # STEP 1: Fill username and click Continue
        browser.wait_for_selector('input[id="username"]', state='visible')
        browser.fill('input[id="username"]', 'admin')
        browser.wait_for_timeout(500)
        browser.click('button:has-text("Continue")')
        browser.wait_for_timeout(2000)
        
        # STEP 2: Fill password
        browser.wait_for_selector('input[id="password"]', state='visible')
        browser.fill('input[id="password"]', password)
        browser.wait_for_timeout(500)
        browser.click('button[type="submit"]')
        browser.wait_for_timeout(3000)
        
        # Check result
        current_url = browser.url
        if 'login' in current_url:
            print(f"  Result: Login FAILED (expected)")
            fail_count += 1
            
            try:
                error_element = browser.locator('div[class*="error"], div[class*="notification"], [role="alert"]').first
                if error_element.is_visible():
                    error_text = error_element.inner_text()
                    print(f"  Error message: {error_text}")
            except:
                print(f"  No error message displayed")
        else:
            print(f"  Result: Login SUCCEEDED (unexpected!)")
        
        # Return to login page for next attempt
        browser.goto(O3_LOGIN_URL)
        browser.wait_for_timeout(2000)

    print("-"*70)
    print(f"Summary: {fail_count}/{num} password attempts failed")
    print("-"*70)

    # Store results for verification steps
    browser.fail_count = fail_count
    browser.num_attempts = num

@pytest_bdd.then('verify account lockout triggers after 7 failures')
def verify_lockout(browser):
    """
    Verify that after 7 failed password attempts, even correct credentials are blocked.
    This updates test_results for dynamic CVSS parameter calculation.
    """

    print("")
    print("="*70)
    print("TESTING ACCOUNT LOCKOUT MECHANISM")
    print("="*70)
    print(f"After {browser.num_attempts} failed password attempts...")
    print("Attempting login with CORRECT credentials: admin/Admin123")
    
    current_url = browser.url
    if 'login' not in current_url:
        browser.goto(O3_LOGIN_URL)
        browser.wait_for_timeout(2000)
    
    # Try correct credentials
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
    
    final_url = browser.url
    
    if 'home' in final_url or 'dashboard' in final_url:
        print("Result: Login SUCCEEDED with correct credentials")
        print(f"⚠️  VULNERABILITY: No account lockout after {browser.num_attempts} failures")
        browser.lockout_working = False
        browser.test_results['account_locked'] = False
        browser.test_results['rate_limiting_detected'] = False
    else:
        print("Result: Login FAILED even with correct credentials")
        print(f"✓ SECURE: Account lockout triggered after {browser.num_attempts} failures")
        browser.lockout_working = True
        browser.test_results['account_locked'] = True
        browser.test_results['rate_limiting_detected'] = True
        browser.test_results['lockout_at_attempt'] = browser.num_attempts

    print("="*70)

@pytest_bdd.then('verify account becomes accessible after 5-minute cooldown period')
def verify_cooldown_and_calculate_cvss(browser):
    """
    Verify 5-minute cooldown mechanism.
    Then calculate final CVSS 4.0 score with dynamic parameters.
    """
    
    if not browser.lockout_working:
        print("")
        print("="*70)
        print("SKIPPING COOLDOWN TEST")
        print("="*70)
        print("Account lockout mechanism not working - no cooldown to test")
        print("="*70)
        browser.cooldown_working = False
        browser.test_results['lockout_duration_seconds'] = 0
    else:
        print("")
        print("="*70)
        print("TESTING COOLDOWN MECHANISM")
        print("="*70)
        print("Waiting 5 minutes for account lockout to expire...")
        print("(OpenMRS default cooldown: 5 minutes / 300 seconds)")
        
        cooldown_seconds = 5 * 60  # 5 minutes = 300 seconds max wait
        lockout_start = time.time()  # Record when lockout was confirmed
        
        # Wait with progress indicator, polling every 30 seconds
        for remaining in range(cooldown_seconds, 0, -30):
            mins = remaining // 60
            secs = remaining % 60
            print(f"  Time remaining: {mins}m {secs:02d}s")
            time.sleep(30)
            
            # Try login after each 30-second interval
            browser.goto(O3_LOGIN_URL)
            browser.wait_for_timeout(2000)
            
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
                # Measure actual lockout duration
                actual_lockout_seconds = time.time() - lockout_start
                browser.test_results['lockout_duration_seconds'] = actual_lockout_seconds
                print(f"  Login SUCCEEDED - actual lockout duration: {actual_lockout_seconds:.0f}s")
                break
        else:
            # Loop completed without breaking - still locked after full wait
            browser.test_results['lockout_duration_seconds'] = cooldown_seconds
            final_url_after_cooldown = browser.url
        
        print("Cooldown period complete!")
        print("Attempting login with correct credentials: admin/Admin123")
        
        if 'home' in final_url_after_cooldown or 'dashboard' in final_url_after_cooldown:
            print("Result: Login SUCCEEDED after cooldown")
            print("✓ SECURE: Cooldown mechanism working correctly")
            browser.cooldown_working = True
        else:
            print("Result: Login FAILED even after 5-minute cooldown")
            print("⚠️  ISSUE: Account still locked after cooldown period")
            browser.cooldown_working = False
        
        print("="*70)
    
    # ========================================================================
    # CALCULATE CVSS 4.0 SCORE WITH DYNAMIC PARAMETERS
    # ========================================================================
    
    print("")
    print("="*70)
    print("CVSS 4.0 VULNERABILITY SCORE CALCULATION")
    print("="*70)
    
    # Determine dynamic parameters based on test observations
    AT = determine_attack_requirements(browser.test_results)
    VC, VI = determine_confidentiality_integrity_impact(browser.test_results)
    VA = determine_availability_impact(browser.test_results)

    # Calculate CVSS 4.0 score
    cvss_score = calculate_cvss_v4_score(
        AV = BaseMetrics.AttackVector.NETWORK,
        AC = BaseMetrics.AttackComplexity.LOW,
        AT = AT,
        PR = BaseMetrics.PriviledgesRequired.NONE,
        UI = BaseMetrics.UserInteraction.NONE,
        VC = VC,
        VI = VI,
        VA = VA,
        SC = BaseMetrics.Confidentiality.SubsequentSystem.NONE,
        SI = BaseMetrics.Integrity.SubsequentSystem.NONE,
        SA = BaseMetrics.Availability.SubsequentSystem.NONE,
    )

    severity = get_cvss_severity(cvss_score)
    
    # Display results
    print("Attack: Brute Force Password Attack")
    print(f"Failed password attempts: {browser.fail_count}/{browser.num_attempts}")
    print("-"*70)
    print("Security Mechanism Test Results:")
    print(f"  Account lockout (7 failures): {'✓ WORKING' if browser.lockout_working else '✗ NOT WORKING'}")
    print(f"  Cooldown period (5 minutes): {'✓ WORKING' if browser.cooldown_working else '✗ NOT WORKING' if browser.lockout_working else 'SKIPPED'}")
    print("-"*70)
    print(f"CVSS Base Score: {cvss_score}")
    print(f"Severity Rating: {severity}")
    
    # Final assessment
    print("")
    if browser.lockout_working and browser.cooldown_working:
        print("OVERALL ASSESSMENT: ✓ SECURE")
        print("OpenMRS properly defends against brute force password attacks")
    elif browser.lockout_working and not browser.cooldown_working:
        print("OVERALL ASSESSMENT: ⚠️  PARTIAL")
        print("Lockout works but cooldown mechanism has issues")
    else:
        print("OVERALL ASSESSMENT: ✗ VULNERABLE")
        print("OpenMRS does not adequately defend against brute force attacks")
    print("="*70)
    print("")
    
    # Assertions
    assert cvss_score is not None, "CVSS score calculation failed"
    assert 0.0 <= cvss_score <= 10.0, f"Invalid CVSS score: {cvss_score}"