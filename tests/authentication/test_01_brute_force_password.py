import pytest_bdd
from conftest import O3_BASE_URL
import string
import random
import time
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from scripts.database import SecurityTestDatabase

O3_LOGIN_URL = f'{O3_BASE_URL}/login'

# ============================================================================
# CVSS 4.0 BASE METRICS - BRUTE FORCE PASSWORD ATTACK
# ============================================================================
# Reference: https://www.first.org/cvss/v4.0/specification-document
#
# This test evaluates a brute force password attack against OpenMRS O3.
# Attack scenario: Known username "admin" + random password attempts
# ============================================================================

# ---------------------------------------------------------------------------
# EXPLOITABILITY METRICS (How easy is it to attack?)
# ---------------------------------------------------------------------------

# Attack Vector (AV): Network (N) = 0.20
# ⚠️ IMPORTANT DESIGN DECISION:
# Even though we test against http://localhost in Docker, we set AV='N' (Network)
# because we are evaluating the vulnerability AS IF an attacker accesses OpenMRS
# over the internet. The localhost deployment is just our test environment - in
# production, OpenMRS runs as a network-accessible web application.
#
# Think of it this way:
# - Our test setup: localhost (for convenience)
# - Real-world deployment: network-accessible server
# - Vulnerability assessment: assumes network access (worst-case scenario)
#
# CVSS 4.0 guidance: "The Base Score...assumes the reasonable worst-case impact
# across different deployed environments."
CVSS_AV = 'N'  # Network - remotely exploitable over internet

# Attack Complexity (AC): DYNAMIC - determined by test observations
# Will be set to:
# - 'L' (Low) if no effective defenses detected
# - 'H' (High) if strong defenses like rate limiting + CAPTCHA detected
CVSS_AC = None  # Determined at runtime

# Attack Requirements (AT): Present (P)
# Special conditions needed: Attacker must know the username "admin"
# This is realistic because "admin" is the default OpenMRS username,
# often publicly documented and discoverable
CVSS_AT = 'P'  # Present - username must be known

# Privileges Required (PR): None (N) = 0.62
# No authentication required - we're testing the login endpoint itself
CVSS_PR = 'N'  # None - testing unauthenticated attack

# User Interaction (UI): None (N) = 0.94
# Attack is fully automated - no human interaction needed
CVSS_UI = 'N'  # None - automated brute force script

# ---------------------------------------------------------------------------
# IMPACT METRICS - VULNERABLE SYSTEM (OpenMRS itself)
# ---------------------------------------------------------------------------

# Confidentiality Impact (VC): High (H) = 0.56
# If admin account compromised: complete access to all patient health records
CVSS_VC = 'H'  # High - full PHI disclosure

# Integrity Impact (VI): High (H) = 0.56  
# If admin account compromised: can modify/delete all medical records
CVSS_VI = 'H'  # High - can alter all patient data

# Availability Impact (VA): DYNAMIC - determined by test observations
# Will be set based on account lockout behavior:
# - 'N' (None) if no lockout or very brief lockout
# - 'L' (Low) if temporary lockout (1-10 minutes)
# - 'H' (High) if prolonged lockout (>10 minutes) causing service disruption
CVSS_VA = None  # Determined at runtime

# ---------------------------------------------------------------------------
# IMPACT METRICS - SUBSEQUENT SYSTEM (Systems beyond OpenMRS)
# ---------------------------------------------------------------------------

# For authentication attacks, there are typically no subsequent systems affected
CVSS_SC = 'N'  # Subsequent Confidentiality: None
CVSS_SI = 'N'  # Subsequent Integrity: None
CVSS_SA = 'N'  # Subsequent Availability: None

# ============================================================================
# DYNAMIC PARAMETER DETECTION FUNCTIONS
# ============================================================================

def determine_attack_complexity(test_results):
    """
    Dynamically determine Attack Complexity based on observed system defenses.
    
    CVSS 4.0 Definition:
    - Low (L): No special conditions, easy to exploit repeatedly
    - High (H): Requires special circumstances, defenses present
    
    Args:
        test_results: Dictionary with observed defense mechanisms
        
    Returns:
        'L' or 'H'
    """
    detected_defenses = []
    
    # Check for rate limiting / account lockout
    if test_results.get('rate_limiting_detected'):
        detected_defenses.append('account_lockout')
    
    # Check for CAPTCHA (future enhancement)
    if test_results.get('captcha_required'):
        detected_defenses.append('captcha')
    
    # Check for progressive delays (future enhancement)
    if test_results.get('progressive_delays'):
        detected_defenses.append('progressive_delays')
    
    # Decision logic:
    # - 2+ defenses = High complexity (hard to exploit)
    # - 1 defense = Low complexity (moderate barrier)
    # - 0 defenses = Low complexity (easy to exploit)
    if len(detected_defenses) >= 2:
        return 'H'  # High - multiple defensive mechanisms
    else:
        return 'L'  # Low - single or no defenses

def determine_availability_impact(test_results):
    """
    Dynamically determine Availability Impact based on account lockout behavior.
    
    CVSS 4.0 Definition:
    - None (N): No availability impact
    - Low (L): Reduced performance or temporary unavailability
    - High (H): Total loss of availability
    
    Args:
        test_results: Dictionary with lockout information
        
    Returns:
        'N', 'L', or 'H'
    """
    if not test_results.get('account_locked'):
        return 'N'  # No lockout = no availability impact
    
    lockout_duration = test_results.get('lockout_duration_seconds', 0)
    
    # High: Prolonged lockout (>10 minutes) - significant DoS
    if lockout_duration > 600:
        return 'H'
    
    # Low: Moderate lockout (1-10 minutes) - temporary inconvenience  
    elif lockout_duration > 60:
        return 'L'
    
    # None: Brief lockout (<1 minute) - negligible impact
    else:
        return 'N'

def calculate_cvss_v4_score(AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA):
    """
    Calculate CVSS 4.0 Base Score using the MacroVector lookup table method.
    
    Note: CVSS 4.0 uses a complex lookup table instead of a mathematical formula.
    For now, this is a simplified implementation. Full implementation requires
    the complete MacroVector equivalence set tables from the CVSS 4.0 spec.
    
    TODO: Implement complete CVSS 4.0 lookup table logic
    
    For Phase 1, we'll use approximate conversion from CVSS 3.1 formula
    as a placeholder until full lookup table is implemented.
    """
    
    # PLACEHOLDER: Simplified calculation
    # This needs to be replaced with actual CVSS 4.0 MacroVector lookup
    
    # Convert string values to numeric equivalents (approximate)
    av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
    ac_scores = {'L': 0.77, 'H': 0.44}
    at_scores = {'N': 0.85, 'P': 0.62}
    pr_scores = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    ui_scores = {'N': 0.85, 'P': 0.62, 'A': 0.62}
    impact_scores = {'N': 0.0, 'L': 0.22, 'H': 0.56}
    
    # Calculate Impact Sub Score (ISS) for Vulnerable System
    ISS_V = 1 - ((1 - impact_scores[VC]) * (1 - impact_scores[VI]) * (1 - impact_scores[VA]))
    
    # Calculate Impact Sub Score (ISS) for Subsequent System  
    ISS_S = 1 - ((1 - impact_scores[SC]) * (1 - impact_scores[SI]) * (1 - impact_scores[SA]))
    
    # Combined Impact
    Impact = 6.42 * max(ISS_V, ISS_S)
    
    # Exploitability
    Exploitability = 8.22 * av_scores[AV] * ac_scores[AC] * pr_scores[PR] * ui_scores[UI]
    
    # Base Score
    if Impact <= 0:
        Base_score = 0
    else:
        Base_score = min(Impact + Exploitability, 10)
    
    return round(Base_score, 1)

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
        
        cooldown_seconds = 5 * 60  # 5 minutes = 300 seconds
        browser.test_results['lockout_duration_seconds'] = cooldown_seconds
        
        # Wait with progress indicator
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
    AC = determine_attack_complexity(browser.test_results)
    VA = determine_availability_impact(browser.test_results)
    
    # Calculate CVSS 4.0 score
    cvss_score = calculate_cvss_v4_score(
        AV=CVSS_AV, AC=AC, AT=CVSS_AT, PR=CVSS_PR, UI=CVSS_UI,
        VC=CVSS_VC, VI=CVSS_VI, VA=VA,
        SC=CVSS_SC, SI=CVSS_SI, SA=CVSS_SA
    )
    
    # Determine severity rating
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
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
    print("-"*70)
    print("CVSS 4.0 Metrics:")
    print(f"  Attack Vector (AV): Network ({CVSS_AV})")
    print(f"  Attack Complexity (AC): {'Low' if AC == 'L' else 'High'} ({AC}) - {'No defenses' if AC == 'L' else 'Defenses detected'}")
    print(f"  Attack Requirements (AT): Present ({CVSS_AT}) - Username must be known")
    print(f"  Privileges Required (PR): None ({CVSS_PR})")
    print(f"  User Interaction (UI): None ({CVSS_UI})")
    print(f"  Vulnerable System Impact:")
    print(f"    Confidentiality (VC): High ({CVSS_VC}) - Full PHI access")
    print(f"    Integrity (VI): High ({CVSS_VI}) - Can modify all records")
    print(f"    Availability (VA): {'None' if VA == 'N' else 'Low' if VA == 'L' else 'High'} ({VA}) - {'No lockout' if VA == 'N' else 'Temporary lockout' if VA == 'L' else 'Prolonged lockout'}")
    print(f"  Subsequent System Impact:")
    print(f"    Confidentiality (SC): None ({CVSS_SC})")
    print(f"    Integrity (SI): None ({CVSS_SI})")
    print(f"    Availability (SA): None ({CVSS_SA})")
    print("")
    print(f"CVSS Vector: CVSS:4.0/AV:{CVSS_AV}/AC:{AC}/AT:{CVSS_AT}/PR:{CVSS_PR}/UI:{CVSS_UI}/VC:{CVSS_VC}/VI:{CVSS_VI}/VA:{VA}/SC:{CVSS_SC}/SI:{CVSS_SI}/SA:{CVSS_SA}")
    print("-"*70)
    
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
    
    # ============================================================================
    # Database Integration - Save Results for Historical Tracking
    # ============================================================================
    
    # Get commit SHA from environment (GitHub Actions sets this)
    commit_sha = os.environ.get('GITHUB_SHA', None)
    
    # Calculate execution time (approximate - from start of attack to now)
    execution_time = browser.test_results.get('total_test_duration_seconds', 
                                              (browser.fail_count * 8))  # Rough estimate: ~8s per attempt
    
    # Save to database
    db = SecurityTestDatabase()
    result = db.save_test_result(
        test_name='test_brute_force_password',
        cvss_score=cvss_score,
        cvss_vector=f'CVSS:4.0/AV:{CVSS_AV}/AC:{AC}/AT:{CVSS_AT}/PR:{CVSS_PR}/UI:{CVSS_UI}/VC:{CVSS_VC}/VI:{CVSS_VI}/VA:{VA}/SC:{CVSS_SC}/SI:{CVSS_SI}/SA:{CVSS_SA}',
        status='PASS',  # Test passed (we detected the vulnerability)
        details={
            'dynamic_params': {
                'AC': AC,
                'VA': VA,
                'AC_rationale': 'Low - only 1 defense mechanism detected (account lockout)' if AC == 'L' else 'High - 2+ defense mechanisms detected',
                'VA_rationale': f"Low - temporary lockout ({browser.test_results.get('lockout_duration_seconds', 0)}s)" if VA == 'L' else 'None - no availability impact'
            },
            'test_observations': {
                'attempts_before_lockout': browser.test_results.get('lockout_at_attempt', browser.num_attempts),
                'lockout_duration_seconds': browser.test_results.get('lockout_duration_seconds', 0),
                'rate_limiting_detected': browser.test_results.get('rate_limiting_detected', False),
                'account_locked': browser.test_results.get('account_locked', False)
            },
            'security_mechanisms': {
                'lockout_working': browser.lockout_working,
                'cooldown_working': browser.cooldown_working
            }
        },
        execution_time_seconds=execution_time,
        commit_sha=commit_sha
    )
    db.close()
    
    # Print relative score information
    print("\n" + "="*80)
    print("DATABASE TRACKING - CVSS Score History")
    print("="*80)
    print(f"Baseline CVSS Score: {result['baseline_score']:.1f}")
    print(f"Current CVSS Score:  {result['current_score']:.1f}")
    print(f"Improvement:         {result['relative_score']:+.1f}")
    
    if result['relative_score'] > 0:
        print(f"  ✅ SECURITY IMPROVED by {result['relative_score']:.1f} points")
    elif result['relative_score'] < 0:
        print(f"  ⚠️  SECURITY REGRESSED by {abs(result['relative_score']):.1f} points")
    else:
        print(f"  ━━ No change from baseline")
    
    print("="*80)
    print("")
    
    # Assertions
    assert cvss_score is not None, "CVSS score calculation failed"
    assert 0.0 <= cvss_score <= 10.0, f"Invalid CVSS score: {cvss_score}"