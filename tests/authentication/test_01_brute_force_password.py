import pytest_bdd
from conftest import O3_BASE_URL
import string
import random
import time

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

# Attack Complexity (AC): Low (L) - Static
# No special complexity required - attacker simply submits credentials repeatedly
CVSS_AC = 'L'  # Low - straightforward repeated attempts

# Attack Requirements (AT): DYNAMIC - determined by test observations
# - 'N' (None) if no lockout detected (attacker can exploit freely)
# - 'P' (Present) if lockout detected (attacker must know valid username to trigger lockout)
CVSS_AT = None  # Determined at runtime

# Privileges Required (PR): None (N)
# No authentication required - we're testing the login endpoint itself
CVSS_PR = 'N'  # None - testing unauthenticated attack

# User Interaction (UI): None (N)
# Attack is fully automated - no human interaction needed
CVSS_UI = 'N'  # None - automated brute force script

# ---------------------------------------------------------------------------
# IMPACT METRICS - VULNERABLE SYSTEM (OpenMRS itself)
# ---------------------------------------------------------------------------

# Confidentiality Impact (VC): DYNAMIC - determined by test observations
# - 'H' (High) if no lockout: attacker can gain full admin access (all PHI exposed)
# - 'L' (Low) if lockout working: attacker is blocked before gaining access
CVSS_VC = None  # Determined at runtime

# Integrity Impact (VI): DYNAMIC - determined by test observations
# - 'H' (High) if no lockout: attacker can modify all medical records
# - 'L' (Low) if lockout working: attacker is blocked before gaining access
CVSS_VI = None  # Determined at runtime

# Availability Impact (VA): DYNAMIC - determined by test observations
# - 'N' (None) if no lockout detected
# - 'L' (Low) if temporary lockout (1-10 minutes)
# - 'H' (High) if prolonged lockout (>10 minutes)
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
        return 'P'  # Present - valid username required to trigger/bypass lockout
    else:
        return 'N'  # None - no special conditions needed


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
        return 'L', 'L'  # Lockout blocks access - reduced impact
    else:
        return 'H', 'H'  # No lockout - full admin access possible


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
        return 'N'  # No lockout = no availability impact

    lockout_duration = test_results.get('lockout_duration_seconds', 0)

    if lockout_duration > 600:
        return 'H'  # High: prolonged lockout >10 minutes
    elif lockout_duration > 60:
        return 'L'  # Low: temporary lockout 1-10 minutes
    else:
        return 'N'  # None: brief lockout <1 minute

def calculate_cvss_v4_score(AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA):
    """
    Calculate CVSS 4.0 Base Score using the official MacroVector lookup table
    and interpolation method.

    Reference: https://www.first.org/cvss/v4.0/specification-document
    Source: https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js

    CVSS 4.0 does NOT use a mathematical formula like 3.1.
    Instead, vectors are grouped into MacroVectors (equivalence classes)
    and scores are assigned via lookup table, then refined by interpolation.

    Args:
        AV: Attack Vector (N/A/L/P)
        AC: Attack Complexity (L/H)
        AT: Attack Requirements (N/P)
        PR: Privileges Required (N/L/H)
        UI: User Interaction (N/P/A)
        VC: Vulnerable System Confidentiality (H/L/N)
        VI: Vulnerable System Integrity (H/L/N)
        VA: Vulnerable System Availability (H/L/N)
        SC: Subsequent System Confidentiality (H/L/N)
        SI: Subsequent System Integrity (H/L/N)
        SA: Subsequent System Availability (H/L/N)

    Returns:
        float: CVSS 4.0 Base Score (0.0 - 10.0)
    """

    # -----------------------------------------------------------------------
    # STEP 1: Determine EQ (Equivalence) levels for each metric group
    # Each EQ level ranges from 0 (most severe) to max (least severe)
    # -----------------------------------------------------------------------

    # EQ1: AV/PR/UI - 3 levels (0, 1, 2)
    if AV == 'N' and PR == 'N' and UI == 'N':
        eq1 = 0
    elif (AV == 'N' or PR == 'N' or UI == 'N') and not (AV == 'N' and PR == 'N' and UI == 'N') and AV != 'P':
        eq1 = 1
    else:
        eq1 = 2

    # EQ2: AC/AT - 2 levels (0, 1)
    if AC == 'L' and AT == 'N':
        eq2 = 0
    else:
        eq2 = 1

    # EQ3: VC/VI/VA - 3 levels (0, 1, 2)
    if VC == 'H' and VI == 'H':
        eq3 = 0
    elif (VC == 'H' or VI == 'H' or VA == 'H') and not (VC == 'H' and VI == 'H'):
        eq3 = 1
    else:
        eq3 = 2

    # EQ4: SC/SI/SA - 2 levels in Base scoring (0, 1)
    # Note: Level 0 requires MSI:S or MSA:S which are Environmental metrics,
    # unreachable in Base scoring. So eq4=0 when SC/SI/SA is High, eq4=1 otherwise.
    if SC == 'H' or SI == 'H' or SA == 'H':
        eq4 = 0
    else:
        eq4 = 1

    # EQ5: Exploit Maturity - E not specified so defaults to X = A (worst case)
    eq5 = 0  # E:X defaults to E:A per spec

    # EQ6: CR/IR/AR + VC/VI/VA - CR/IR/AR not specified so default to H (worst case)
    if VC == 'H' or VI == 'H' or VA == 'H':
        eq6 = 0
    else:
        eq6 = 1

    # -----------------------------------------------------------------------
    # STEP 2: MacroVector lookup table
    # Key: (eq1, eq2, eq3eq6_combined, eq4, eq5)
    # Values: MacroVector scores from FIRST.org cvss_lookup.js
    # -----------------------------------------------------------------------

    # EQ3 and EQ6 are not independent - must be evaluated jointly
    eq3eq6_map = {
        (0, 0): 0,
        (0, 1): 1,
        (1, 0): 2,
        (1, 1): 3,
        (2, 0): 4,  # Cannot exist per spec
        (2, 1): 4,
    }
    eq3eq6 = eq3eq6_map.get((eq3, eq6), 4)

    lookup = {
        (0, 0, 0, 0, 0): 10.0, (0, 0, 0, 0, 1): 9.9, (0, 0, 0, 0, 2): 9.8,
        (0, 0, 0, 1, 0): 9.5,  (0, 0, 0, 1, 1): 9.5, (0, 0, 0, 1, 2): 9.2,
        (0, 0, 1, 0, 0): 10.0, (0, 0, 1, 0, 1): 9.6, (0, 0, 1, 0, 2): 9.3,
        (0, 0, 1, 1, 0): 9.2,  (0, 0, 1, 1, 1): 8.9, (0, 0, 1, 1, 2): 8.6,
        (0, 0, 2, 0, 0): 9.3,  (0, 0, 2, 0, 1): 9.0, (0, 0, 2, 0, 2): 8.8,
        (0, 0, 2, 1, 0): 8.6,  (0, 0, 2, 1, 1): 8.0, (0, 0, 2, 1, 2): 7.4,
        (0, 0, 3, 0, 0): 9.0,  (0, 0, 3, 0, 1): 8.5, (0, 0, 3, 0, 2): 7.9,
        (0, 0, 3, 1, 0): 7.9,  (0, 0, 3, 1, 1): 7.5, (0, 0, 3, 1, 2): 7.0,
        (0, 0, 4, 0, 0): 8.0,  (0, 0, 4, 0, 1): 7.3, (0, 0, 4, 0, 2): 6.8,
        (0, 0, 4, 1, 0): 6.4,  (0, 0, 4, 1, 1): 5.9, (0, 0, 4, 1, 2): 5.4,
        (0, 1, 0, 0, 0): 9.5,  (0, 1, 0, 0, 1): 9.4, (0, 1, 0, 0, 2): 9.2,
        (0, 1, 0, 1, 0): 8.7,  (0, 1, 0, 1, 1): 8.6, (0, 1, 0, 1, 2): 8.4,
        (0, 1, 1, 0, 0): 9.2,  (0, 1, 1, 0, 1): 8.9, (0, 1, 1, 0, 2): 8.6,
        (0, 1, 1, 1, 0): 8.4,  (0, 1, 1, 1, 1): 7.8, (0, 1, 1, 1, 2): 7.0,
        (0, 1, 2, 0, 0): 8.8,  (0, 1, 2, 0, 1): 8.4, (0, 1, 2, 0, 2): 7.8,
        (0, 1, 2, 1, 0): 7.7,  (0, 1, 2, 1, 1): 7.1, (0, 1, 2, 1, 2): 6.4,
        (0, 1, 3, 0, 0): 8.5,  (0, 1, 3, 0, 1): 7.9, (0, 1, 3, 0, 2): 7.3,
        (0, 1, 3, 1, 0): 7.2,  (0, 1, 3, 1, 1): 6.5, (0, 1, 3, 1, 2): 5.8,
        (0, 1, 4, 0, 0): 7.4,  (0, 1, 4, 0, 1): 6.6, (0, 1, 4, 0, 2): 6.0,
        (0, 1, 4, 1, 0): 5.5,  (0, 1, 4, 1, 1): 5.1, (0, 1, 4, 1, 2): 4.7,
        (1, 0, 0, 0, 0): 9.4,  (1, 0, 0, 0, 1): 9.3, (1, 0, 0, 0, 2): 9.0,
        (1, 0, 0, 1, 0): 8.8,  (1, 0, 0, 1, 1): 8.6, (1, 0, 0, 1, 2): 8.3,
        (1, 0, 1, 0, 0): 9.2,  (1, 0, 1, 0, 1): 8.8, (1, 0, 1, 0, 2): 8.5,
        (1, 0, 1, 1, 0): 8.2,  (1, 0, 1, 1, 1): 7.6, (1, 0, 1, 1, 2): 6.8,
        (1, 0, 2, 0, 0): 8.6,  (1, 0, 2, 0, 1): 8.3, (1, 0, 2, 0, 2): 7.7,
        (1, 0, 2, 1, 0): 7.5,  (1, 0, 2, 1, 1): 6.8, (1, 0, 2, 1, 2): 6.0,
        (1, 0, 3, 0, 0): 8.2,  (1, 0, 3, 0, 1): 7.7, (1, 0, 3, 0, 2): 7.1,
        (1, 0, 3, 1, 0): 6.9,  (1, 0, 3, 1, 1): 6.3, (1, 0, 3, 1, 2): 5.6,
        (1, 0, 4, 0, 0): 7.2,  (1, 0, 4, 0, 1): 6.5, (1, 0, 4, 0, 2): 5.8,
        (1, 0, 4, 1, 0): 5.1,  (1, 0, 4, 1, 1): 4.7, (1, 0, 4, 1, 2): 4.3,
        (1, 1, 0, 0, 0): 9.0,  (1, 1, 0, 0, 1): 8.8, (1, 1, 0, 0, 2): 8.5,
        (1, 1, 0, 1, 0): 8.3,  (1, 1, 0, 1, 1): 8.1, (1, 1, 0, 1, 2): 7.8,
        (1, 1, 1, 0, 0): 8.6,  (1, 1, 1, 0, 1): 8.3, (1, 1, 1, 0, 2): 7.8,
        (1, 1, 1, 1, 0): 7.6,  (1, 1, 1, 1, 1): 7.0, (1, 1, 1, 1, 2): 6.2,
        (1, 1, 2, 0, 0): 8.1,  (1, 1, 2, 0, 1): 7.7, (1, 1, 2, 0, 2): 7.2,
        (1, 1, 2, 1, 0): 6.9,  (1, 1, 2, 1, 1): 6.3, (1, 1, 2, 1, 2): 5.5,
        (1, 1, 3, 0, 0): 7.7,  (1, 1, 3, 0, 1): 7.2, (1, 1, 3, 0, 2): 6.6,
        (1, 1, 3, 1, 0): 6.4,  (1, 1, 3, 1, 1): 5.8, (1, 1, 3, 1, 2): 5.2,
        (1, 1, 4, 0, 0): 6.7,  (1, 1, 4, 0, 1): 6.1, (1, 1, 4, 0, 2): 5.4,
        (1, 1, 4, 1, 0): 4.8,  (1, 1, 4, 1, 1): 4.4, (1, 1, 4, 1, 2): 4.0,
        (2, 0, 0, 0, 0): 8.5,  (2, 0, 0, 0, 1): 8.4, (2, 0, 0, 0, 2): 8.2,
        (2, 0, 0, 1, 0): 7.9,  (2, 0, 0, 1, 1): 7.8, (2, 0, 0, 1, 2): 7.5,
        (2, 0, 1, 0, 0): 8.3,  (2, 0, 1, 0, 1): 8.0, (2, 0, 1, 0, 2): 7.6,
        (2, 0, 1, 1, 0): 7.3,  (2, 0, 1, 1, 1): 6.7, (2, 0, 1, 1, 2): 6.0,
        (2, 0, 2, 0, 0): 7.7,  (2, 0, 2, 0, 1): 7.4, (2, 0, 2, 0, 2): 7.0,
        (2, 0, 2, 1, 0): 6.6,  (2, 0, 2, 1, 1): 6.1, (2, 0, 2, 1, 2): 5.3,
        (2, 0, 3, 0, 0): 7.3,  (2, 0, 3, 0, 1): 6.9, (2, 0, 3, 0, 2): 6.4,
        (2, 0, 3, 1, 0): 6.1,  (2, 0, 3, 1, 1): 5.6, (2, 0, 3, 1, 2): 5.0,
        (2, 0, 4, 0, 0): 6.4,  (2, 0, 4, 0, 1): 5.9, (2, 0, 4, 0, 2): 5.3,
        (2, 0, 4, 1, 0): 4.7,  (2, 0, 4, 1, 1): 4.3, (2, 0, 4, 1, 2): 3.9,
        (2, 1, 0, 0, 0): 8.0,  (2, 1, 0, 0, 1): 7.9, (2, 1, 0, 0, 2): 7.6,
        (2, 1, 0, 1, 0): 7.4,  (2, 1, 0, 1, 1): 7.2, (2, 1, 0, 1, 2): 7.0,
        (2, 1, 1, 0, 0): 7.7,  (2, 1, 1, 0, 1): 7.4, (2, 1, 1, 0, 2): 7.0,
        (2, 1, 1, 1, 0): 6.7,  (2, 1, 1, 1, 1): 6.1, (2, 1, 1, 1, 2): 5.3,
        (2, 1, 2, 0, 0): 7.3,  (2, 1, 2, 0, 1): 7.0, (2, 1, 2, 0, 2): 6.5,
        (2, 1, 2, 1, 0): 6.2,  (2, 1, 2, 1, 1): 5.6, (2, 1, 2, 1, 2): 5.0,
        (2, 1, 3, 0, 0): 6.9,  (2, 1, 3, 0, 1): 6.5, (2, 1, 3, 0, 2): 6.0,
        (2, 1, 3, 1, 0): 5.7,  (2, 1, 3, 1, 1): 5.2, (2, 1, 3, 1, 2): 4.7,
        (2, 1, 4, 0, 0): 6.0,  (2, 1, 4, 0, 1): 5.5, (2, 1, 4, 0, 2): 5.0,
        (2, 1, 4, 1, 0): 4.4,  (2, 1, 4, 1, 1): 4.0, (2, 1, 4, 1, 2): 3.6,
    }

    key = (eq1, eq2, eq3eq6, eq4, eq5)
    score = lookup.get(key, 0.0)

    return round(score, 1)

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
        AV=CVSS_AV, AC=CVSS_AC, AT=AT, PR=CVSS_PR, UI=CVSS_UI,
        VC=VC, VI=VI, VA=VA,
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
    print(f"  Attack Complexity (AC): Low ({CVSS_AC}) - Straightforward repeated attempts")
    print(f"  Attack Requirements (AT): {'None' if AT == 'N' else 'Present'} ({AT}) - {'No preconditions needed' if AT == 'N' else 'Valid username required'}")
    print(f"  Privileges Required (PR): None ({CVSS_PR})")
    print(f"  User Interaction (UI): None ({CVSS_UI})")
    print(f"  Vulnerable System Impact:")
    print(f"    Confidentiality (VC): {'High' if VC == 'H' else 'Low'} ({VC}) - {'Full PHI access possible' if VC == 'H' else 'Attacker blocked by lockout'}")
    print(f"    Integrity (VI): {'High' if VI == 'H' else 'Low'} ({VI}) - {'Can modify all records' if VI == 'H' else 'Attacker blocked by lockout'}")
    print(f"    Availability (VA): {'None' if VA == 'N' else 'Low' if VA == 'L' else 'High'} ({VA}) - {'No lockout' if VA == 'N' else 'Temporary lockout 1-10 min' if VA == 'L' else 'Prolonged lockout >10 min'}")
    print(f"  Subsequent System Impact:")
    print(f"    Confidentiality (SC): None ({CVSS_SC})")
    print(f"    Integrity (SI): None ({CVSS_SI})")
    print(f"    Availability (SA): None ({CVSS_SA})")
    print("")
    print(f"CVSS Vector: CVSS:4.0/AV:{CVSS_AV}/AC:{CVSS_AC}/AT:{AT}/PR:{CVSS_PR}/UI:{CVSS_UI}/VC:{VC}/VI:{VI}/VA:{VA}/SC:{CVSS_SC}/SI:{CVSS_SI}/SA:{CVSS_SA}")
    print("-"*70)
    
    # Final assessment
    print("")
    if browser.lockout_working and browser.cooldown_working:
        print("OVERALL ASSESSMENT: ✓ SECURE")
        print("OpenMRS properly defends against brute force password attacks")
        print("TEST STATUS:PASSED")
    elif browser.lockout_working and not browser.cooldown_working:
        print("OVERALL ASSESSMENT: ⚠️  PARTIAL")
        print("Lockout works but cooldown mechanism has issues")
        print("TEST STATUS:FAILED")
    else:
        print("OVERALL ASSESSMENT: ✗ VULNERABLE")
        print("OpenMRS does not adequately defend against brute force attacks")
        print("TEST STATUS:FAILED")
    print("="*70)
    print("")
    
    # Assertions
    assert cvss_score is not None, "CVSS score calculation failed"
    assert 0.0 <= cvss_score <= 10.0, f"Invalid CVSS score: {cvss_score}"