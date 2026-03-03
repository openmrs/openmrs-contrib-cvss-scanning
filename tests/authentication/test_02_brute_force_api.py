import pytest_bdd
import string
import random
import time
import requests
import base64

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, BaseMetrics, O3_BASE_URL

O3_API_URL = f'{O3_BASE_URL}/openmrs/ws/rest/v1/session'

# ============================================================================
# CVSS 4.0 BASE METRICS - BRUTE FORCE API PASSWORD ATTACK
# ============================================================================
# Reference: https://www.first.org/cvss/v4.0/specification-document
#
# This test evaluates a brute force password attack against OpenMRS O3
# REST API endpoint directly, bypassing the frontend UI entirely.
#
# Attack scenario: Known username "admin" + random password attempts
# sent as HTTP Basic Auth to POST /openmrs/ws/rest/v1/session
#
# Academic purpose: Compare API-layer defenses vs UI-layer defenses.
# If API lockout behavior differs from frontend, CVSS scores will differ,
# revealing inconsistent defense application across attack surfaces.
# ============================================================================

# ---------------------------------------------------------------------------
# STATIC EXPLOITABILITY METRICS
# ---------------------------------------------------------------------------

# Attack Vector (AV): Network (N)
# API endpoint is network-accessible in production deployments.
# Same rationale as frontend test - assess real-world attack scenario.
CVSS_AV = BaseMetrics.AttackVector.NETWORK  # Network - remotely exploitable

# Attack Complexity (AC): Low (L)
# API attacks require no special complexity - simple HTTP requests.
# No CAPTCHA, no JavaScript rendering, no browser required.
# API attacks are typically EASIER than UI attacks.
CVSS_AC = BaseMetrics.AttackComplexity.LOW  # Low - straightforward HTTP requests

# Privileges Required (PR): None (N)
# No authentication required to attempt login via API
CVSS_PR = BaseMetrics.PriviledgesRequired.NONE  # None - unauthenticated attack

# User Interaction (UI): None (N)
# Fully automated - no human interaction needed
CVSS_UI = BaseMetrics.UserInteraction.NONE  # None - automated API requests

# ---------------------------------------------------------------------------
# DYNAMIC PARAMETERS (determined at runtime)
# ---------------------------------------------------------------------------

# Attack Requirements (AT): DYNAMIC
# - 'N' if no lockout (attacker can freely exploit without preconditions)
# - 'P' if lockout detected (valid username required to target same account)
CVSS_AT = None

# Confidentiality Impact (VC): DYNAMIC
# - 'H' if no lockout (full admin API access = all PHI exposed via REST)
# - 'L' if lockout blocks API access
CVSS_VC = None

# Integrity Impact (VI): DYNAMIC
# - 'H' if no lockout (can modify all data via REST API)
# - 'L' if lockout blocks API access
CVSS_VI = None

# Availability Impact (VA): DYNAMIC
# - 'N' if no lockout
# - 'L' if temporary lockout (1-10 minutes)
# - 'H' if prolonged lockout (>10 minutes)
CVSS_VA = None

# ---------------------------------------------------------------------------
# SUBSEQUENT SYSTEM IMPACT (Static - no subsequent systems affected)
# ---------------------------------------------------------------------------
CVSS_SC = BaseMetrics.Confidentiality.SubsequentSystem.NONE
CVSS_SI = BaseMetrics.Integrity.SubsequentSystem.NONE
CVSS_SA = BaseMetrics.Availability.SubsequentSystem.NONE

# ============================================================================
# DYNAMIC PARAMETER DETECTION FUNCTIONS
# ============================================================================

def determine_attack_requirements(test_results):
    """
    Dynamically determine AT based on observed API lockout behavior.
    - P if lockout detected (valid username required to trigger lockout)
    - N if no lockout (no preconditions needed)
    """
    if test_results.get('account_locked'):
        return BaseMetrics.AttackRequirements.PRESENT  # Present - valid username required to trigger/bypass lockout
    else:
        return BaseMetrics.AttackRequirements.NONE  # None - no special conditions needed


def determine_confidentiality_integrity_impact(test_results):
    """
    Dynamically determine VC and VI based on whether API access is blocked.
    - H/H if no lockout (attacker can gain full REST API access)
    - L/L if lockout blocks API access
    """
    if test_results.get('account_locked'):
        return BaseMetrics.Confidentiality.VulnerableSystem.LOW, BaseMetrics.Integrity.VulnerableSystem.LOW  # Lockout blocks access - reduced impact
    else:
        return BaseMetrics.Confidentiality.VulnerableSystem.HIGH, BaseMetrics.Integrity.VulnerableSystem.HIGH  # No lockout - full admin access possible


def determine_availability_impact(test_results):
    """
    Dynamically determine VA based on observed API lockout duration.
    - N if no lockout
    - L if 1-10 minute lockout
    - H if >10 minute lockout
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
                     'Brute force password attack via REST API with known admin username',
                     features_base_dir='')
def test_brute_force_api_password():
    """
    Tests account lockout and cooldown after 7 failed API login attempts with known
    username "admin". Uses CVSS 4.0 with dynamic scoring based on observed API-layer
    security mechanisms. Compares defense consistency with frontend brute force test.
    """
    pass


@pytest_bdd.given('the OpenMRS 3 login page is displayed')
def navigate_to_login(browser):
    """Navigate to O3 login page - required by Background step"""
    browser.goto(f'{O3_BASE_URL}/login')
    browser.wait_for_timeout(2000)


@pytest_bdd.when('the attacker sends 7 API login requests with known username "admin" and random passwords')
def perform_api_attack(browser):
    """
    Send 7 POST requests to /openmrs/ws/rest/v1/session with Basic Auth.
    Track HTTP response codes to detect lockout behavior.
    """
    browser.api_test_results = {
        'rate_limiting_detected': False,
        'lockout_at_attempt': None,
        'account_locked': False,
        'lockout_duration_seconds': 0,
    }
    browser.api_responses = []

    def random_password(length=10):
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for _ in range(length))

    wrong_passwords = [random_password() for _ in range(7)]

    print("\n" + "="*70)
    print("ATTACK CONFIGURATION")
    print("="*70)
    print("Attack Type: Brute Force API Password Attack (CVSS 4.0)")
    print(f"Target: POST {O3_API_URL}")
    print("Known Credential: username='admin'")
    print("Random Credential: passwords (10-character random strings)")
    print("="*70)

    print("")
    print("="*70)
    print("STARTING ATTACK: brute force API password attack")
    print("="*70)

    for i, password in enumerate(wrong_passwords, 1):
        credentials = base64.b64encode(f'admin:{password}'.encode()).decode()
        headers = {
            'Authorization': f'Basic {credentials}',
            'Content-Type': 'application/json'
        }

        print(f"Attempt {i}/7: username='admin', password='{password}'")

        try:
            response = requests.get(O3_API_URL, headers=headers, timeout=10)
            status_code = response.status_code
            browser.api_responses.append(status_code)

            if status_code == 200:
                try:
                    data = response.json()
                    authenticated = data.get('authenticated', False)
                    if authenticated:
                        print(f"  Result: Login SUCCEEDED (unexpected!) HTTP {status_code}")
                    else:
                        print(f"  Result: Login FAILED (expected) HTTP {status_code}")
                except:
                    print(f"  Result: HTTP {status_code} (could not parse response)")
            elif status_code == 401:
                print(f"  Result: Login FAILED - Unauthorized HTTP {status_code}")
            elif status_code == 403:
                print(f"  Result: Login BLOCKED - Forbidden HTTP {status_code} (possible lockout)")
                browser.api_test_results['rate_limiting_detected'] = True
            else:
                print(f"  Result: HTTP {status_code}")

        except requests.exceptions.RequestException as e:
            print(f"  Result: Request failed - {e}")
            browser.api_responses.append(0)

        time.sleep(1)  # Brief pause between attempts

    print("-"*70)
    print(f"API responses: {browser.api_responses}")
    print("-"*70)


@pytest_bdd.then('the CVSS score for brute force API password attack should be calculated')
def store_api_attack_name(browser):
    """Store attack name for reference"""
    browser.api_attack_name = 'brute force API password attack'


@pytest_bdd.then('verify API account lockout triggers after 7 failures')
def verify_api_lockout(browser):
    """
    Verify that after 7 failed API attempts, even correct credentials are blocked.
    """
    print("")
    print("="*70)
    print("TESTING API ACCOUNT LOCKOUT MECHANISM")
    print("="*70)
    print("After 7 failed API attempts...")
    print("Attempting API login with CORRECT credentials: admin/Admin123")

    credentials = base64.b64encode(b'admin:Admin123').decode()
    headers = {
        'Authorization': f'Basic {credentials}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(O3_API_URL, headers=headers, timeout=10)
        status_code = response.status_code

        if status_code == 200:
            try:
                data = response.json()
                authenticated = data.get('authenticated', False)
                if authenticated:
                    print("Result: Login SUCCEEDED with correct credentials")
                    print(f"⚠️  VULNERABILITY: No API lockout after 7 failures")
                    browser.api_lockout_working = False
                    browser.api_test_results['account_locked'] = False
                else:
                    print("Result: Login FAILED even with correct credentials (authenticated=false)")
                    print(f"✓ SECURE: API account lockout triggered after 7 failures")
                    browser.api_lockout_working = True
                    browser.api_test_results['account_locked'] = True
                    browser.api_test_results['lockout_at_attempt'] = 7
            except:
                print(f"  Could not parse response body, HTTP {status_code}")
                browser.api_lockout_working = False
                browser.api_test_results['account_locked'] = False
        elif status_code == 401:
            print("Result: HTTP 401 - credentials rejected")
            # Could be lockout or just wrong credentials - check response body
            try:
                data = response.json()
                authenticated = data.get('authenticated', False)
                if not authenticated:
                    print("✓ SECURE: API lockout triggered (authenticated=false)")
                    browser.api_lockout_working = True
                    browser.api_test_results['account_locked'] = True
                    browser.api_test_results['lockout_at_attempt'] = 7
            except:
                browser.api_lockout_working = False
                browser.api_test_results['account_locked'] = False
        elif status_code == 403:
            print("Result: HTTP 403 - Forbidden (lockout confirmed)")
            print("✓ SECURE: API account lockout triggered after 7 failures")
            browser.api_lockout_working = True
            browser.api_test_results['account_locked'] = True
            browser.api_test_results['lockout_at_attempt'] = 7
        else:
            print(f"Result: HTTP {status_code} - unexpected response")
            browser.api_lockout_working = False
            browser.api_test_results['account_locked'] = False

    except requests.exceptions.RequestException as e:
        print(f"Result: Request failed - {e}")
        browser.api_lockout_working = False
        browser.api_test_results['account_locked'] = False

    print("="*70)


@pytest_bdd.then('verify API account becomes accessible after 5-minute cooldown period')
def verify_api_cooldown_and_calculate_cvss(browser):
    """
    Verify 5-minute cooldown for API access.
    Then calculate final CVSS 4.0 score with dynamic parameters.
    """
    if not browser.api_lockout_working:
        print("")
        print("="*70)
        print("SKIPPING API COOLDOWN TEST")
        print("="*70)
        print("API lockout not working - no cooldown to test")
        browser.api_cooldown_working = False
        browser.api_test_results['lockout_duration_seconds'] = 0
    else:
        print("")
        print("="*70)
        print("TESTING API COOLDOWN MECHANISM")
        print("="*70)
        print("Waiting for API lockout to expire (max 5 minutes)...")

        cooldown_seconds = 5 * 60
        lockout_start = time.time()
        final_authenticated = False

        credentials = base64.b64encode(b'admin:Admin123').decode()
        headers = {
            'Authorization': f'Basic {credentials}',
            'Content-Type': 'application/json'
        }

        for remaining in range(cooldown_seconds, 0, -30):
            mins = remaining // 60
            secs = remaining % 60
            print(f"  Time remaining: {mins}m {secs:02d}s")
            time.sleep(30)

            try:
                response = requests.get(O3_API_URL, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('authenticated', False):
                        actual_lockout_seconds = time.time() - lockout_start
                        browser.api_test_results['lockout_duration_seconds'] = actual_lockout_seconds
                        print(f"  API Login SUCCEEDED - actual lockout: {actual_lockout_seconds:.0f}s")
                        final_authenticated = True
                        break
            except requests.exceptions.RequestException as e:
                print(f"  Request failed: {e}")
        else:
            browser.api_test_results['lockout_duration_seconds'] = cooldown_seconds

        print("Cooldown period complete!")

        if final_authenticated:
            print("Result: API Login SUCCEEDED after cooldown")
            print("✓ SECURE: API cooldown mechanism working correctly")
            browser.api_cooldown_working = True
        else:
            print("Result: API Login FAILED even after 5-minute cooldown")
            print("⚠️  ISSUE: API account still locked after cooldown period")
            browser.api_cooldown_working = False

        print("="*70)

    # ========================================================================
    # CALCULATE CVSS 4.0 SCORE WITH DYNAMIC PARAMETERS
    # ========================================================================

    print("")
    print("="*70)
    print("CVSS 4.0 VULNERABILITY SCORE CALCULATION")
    print("="*70)

    AT = determine_attack_requirements(browser.api_test_results)
    VC, VI = determine_confidentiality_integrity_impact(browser.api_test_results)
    VA = determine_availability_impact(browser.api_test_results)

    cvss_score = calculate_cvss_v4_score(
        AV=CVSS_AV,
        AC=CVSS_AC,
        AT=AT,
        PR=CVSS_PR,
        UI=CVSS_UI,
        VC=VC,
        VI=VI,
        VA=VA,
        SC=CVSS_SC,
        SI=CVSS_SI,
        SA=CVSS_SA
    )

    severity = get_cvss_severity(cvss_score)

    print("Attack: Brute Force API Password Attack")
    print(f"API responses during attack: {browser.api_responses}")
    print("-"*70)
    print("Security Mechanism Test Results:")
    print(f"  API account lockout (7 failures): {'✓ WORKING' if browser.api_lockout_working else '✗ NOT WORKING'}")
    print(f"  API cooldown period (5 minutes):  {'✓ WORKING' if browser.api_cooldown_working else '✗ NOT WORKING' if browser.api_lockout_working else 'SKIPPED'}")
    print("-"*70)
    print(f"CVSS Base Score: {cvss_score}")
    print(f"Severity Rating: {severity}")
    print("-"*70)
    print("CVSS 4.0 Metrics:")
    print(f"  Attack Vector (AV): Network ({CVSS_AV})")
    print(f"  Attack Complexity (AC): Low ({CVSS_AC}) - Simple HTTP requests, no browser needed")
    print(f"  Attack Requirements (AT): {'None' if AT == 'N' else 'Present'} ({AT}) - {'No preconditions' if AT == 'N' else 'Valid username required'}")
    print(f"  Privileges Required (PR): None ({CVSS_PR})")
    print(f"  User Interaction (UI): None ({CVSS_UI})")
    print(f"  Vulnerable System Impact:")
    print(f"    Confidentiality (VC): {'High' if VC == 'H' else 'Low'} ({VC}) - {'Full REST API access possible' if VC == 'H' else 'Blocked by lockout'}")
    print(f"    Integrity (VI): {'High' if VI == 'H' else 'Low'} ({VI}) - {'Can modify all data via API' if VI == 'H' else 'Blocked by lockout'}")
    print(f"    Availability (VA): {'None' if VA == 'N' else 'Low' if VA == 'L' else 'High'} ({VA}) - {'No lockout' if VA == 'N' else 'Temporary lockout 1-10 min' if VA == 'L' else 'Prolonged lockout >10 min'}")
    print(f"  Subsequent System Impact:")
    print(f"    Confidentiality (SC): None ({CVSS_SC})")
    print(f"    Integrity (SI): None ({CVSS_SI})")
    print(f"    Availability (SA): None ({CVSS_SA})")
    print("")
    print(f"CVSS Vector: CVSS:4.0/AV:{CVSS_AV}/AC:{CVSS_AC}/AT:{AT}/PR:{CVSS_PR}/UI:{CVSS_UI}/VC:{VC}/VI:{VI}/VA:{VA}/SC:{CVSS_SC}/SI:{CVSS_SI}/SA:{CVSS_SA}")
    print("-"*70)

    print("")
    if browser.api_lockout_working and browser.api_cooldown_working:
        print("OVERALL ASSESSMENT: ✓ SECURE")
        print("OpenMRS API properly defends against brute force password attacks")
    elif browser.api_lockout_working and not browser.api_cooldown_working:
        print("OVERALL ASSESSMENT: ⚠️  PARTIAL")
        print("API lockout works but cooldown mechanism has issues")
    else:
        print("OVERALL ASSESSMENT: ✗ VULNERABLE")
        print("OpenMRS API does not adequately defend against brute force attacks")
    print("="*70)
    print("")

    assert cvss_score is not None, "CVSS score calculation failed"
    assert 0.0 <= cvss_score <= 10.0, f"Invalid CVSS score: {cvss_score}"