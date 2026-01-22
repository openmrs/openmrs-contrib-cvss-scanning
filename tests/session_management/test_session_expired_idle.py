"""
Test 2: Session Timeout After Idle Period
==========================================

WHAT THIS TESTS:
Does the session expire after a period of inactivity?

WHY IT MATTERS:
If sessions never expire, an attacker has unlimited time to:
- Use stolen sessions
- Access unlocked computers
- Exploit unattended devices

HOW IT WORKS:
1. Login to establish a session
2. Wait X minutes without making any requests (idle)
3. Try to access a protected page
4. Check if session has expired

EXPECTED SECURE BEHAVIOR:
- Session should expire after 15-30 minutes of inactivity
- Server should redirect to login or return 401/403
- Should NOT allow access after idle timeout

MINIMAL DEPENDENCIES:
- pytest-bdd (for Gherkin scenarios)
- requests (for HTTP requests)
- time (built-in, for waiting)

RUN WITH: pytest tests/session_management/session_expired_idle.py -v -s
"""

import pytest
import requests
import time
import os

# Test configuration
LOGIN_URL = 'https://o3.openmrs.org/openmrs/spa/login'
HOME_URL = 'https://o3.openmrs.org/openmrs/spa/home'
USERNAME = 'admin'
PASSWORD = 'Admin123'

# Configuration for idle timeout testing
IDLE_CHECK_INTERVAL_MINUTES = 5  # Check every 5 minutes


@pytest.fixture
def session_data():
    """
    Fixture to store session data across test steps
    """
    return {
        'session': requests.Session(),
        'cookies': {},
        'idle_start': None,
        'idle_end': None,
        'responses': {},
        'check_count': 0,
        'session_expired': False
    }


def perform_login(session_obj, username=USERNAME, password=PASSWORD):
    """
    Perform login using requests library
    
    Returns: tuple (success: bool, session_cookies: dict)
    """
    print("\n" + "="*60)
    print("PERFORMING LOGIN")
    print("="*60)
    
    session = session_obj
    
    try:
        print("Accessing login page...")
        response = session.get(LOGIN_URL)
        
        print("Submitting credentials...")
        login_data = {
            'username': username,
            'password': password
        }
        
        response = session.post(
            LOGIN_URL,
            data=login_data,
            allow_redirects=True
        )
        
        print(f"  Status: {response.status_code}")
        print(f"  Final URL: {response.url}")
        
        # Check if login successful
        success = (
            HOME_URL in response.url or 
            response.status_code == 200 and 'JSESSIONID' in session.cookies
        )
        
        if success:
            print("\n✓ Login successful!")
            
            cookies = {}
            for cookie in session.cookies:
                cookies[cookie.name] = cookie.value
                print(f"  Cookie: {cookie.name} = {cookie.value[:20]}...")
            
            return True, cookies
        else:
            print("\n✗ Login failed!")
            return False, {}
            
    except Exception as e:
        print(f"\n✗ Login error: {e}")
        return False, {}


def check_session_status(session_obj):
    """
    Check if session is still active by making a request
    
    Returns: tuple (is_active: bool, status_code: int, redirected: bool)
    """
    try:
        response = session_obj.get(HOME_URL, allow_redirects=False)
        
        is_active = response.status_code == 200
        redirected_to_login = False
        
        if response.is_redirect:
            redirect_location = response.headers.get('Location', '')
            redirected_to_login = 'login' in redirect_location.lower()
        
        return is_active, response.status_code, redirected_to_login
        
    except Exception as e:
        print(f"Error checking session: {e}")
        return False, 0, False


# =============================================================================
# BDD STEP DEFINITIONS - Import after defining helper functions
# =============================================================================

from pytest_bdd import given, when, then, scenarios

# Load scenarios - placed after imports to avoid config issues
# Get the directory where this file is located
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURE_PATH = os.path.join(CURRENT_DIR, 'session_management.feature')
scenarios(FEATURE_PATH)


# =============================================================================
# BACKGROUND STEP
# =============================================================================

@given('the OpenMRS 3 home page is show after login')
def user_has_active_session(session_data):
    """
    BACKGROUND: Establish an active authenticated session
    
    This creates a logged-in session that we'll test for timeout.
    """
    print("\n" + "="*60)
    print("BACKGROUND: Establishing Active Session")
    print("="*60)
    
    success, cookies = perform_login(session_data['session'])
    
    assert success, "Failed to login - cannot proceed with test"
    assert cookies, "No session cookies found"
    
    session_data['cookies'] = cookies
    
    print("\n✓ Active session established")
    print("="*60)


# =============================================================================
# WHEN STEP: User Stays Idle
# =============================================================================

@when('the user stays idle')
def user_stays_idle(session_data):
    """
    ACTION: User remains idle (no activity)
    
    This step simply marks that the user is now in an idle state.
    The actual timeout checking happens in the THEN step.
    """
    print("\n" + "-"*60)
    print("ACTION: User Stays Idle")
    print("-"*60)
    
    # Record when idle period starts
    session_data['idle_start'] = time.time()
    
    print("User has stopped making requests (idle state)")
    print("Session timeout monitoring will begin...")
    print("-"*60)


# =============================================================================
# THEN STEP: Check Session Every 5 Minutes
# =============================================================================

@then('the session should be checked if it is idle after every five minutes')
def check_session_every_five_minutes(session_data):
    """
    VERIFICATION: Monitor session and check for idle timeout every 5 minutes
    
    WHAT THIS DOES:
    - Waits 5 minutes
    - Checks if session is still active
    - If expired, records when it happened
    - If active, waits another 5 minutes and checks again
    - Continues until session expires or we hit a maximum time limit
    
    EXPECTED BEHAVIOR:
    - Session should expire within 15-30 minutes of inactivity
    - When expired, should get 401/403 or redirect to login
    
    PRACTICAL NOTE:
    - This test will run for real time (5, 10, 15 minutes etc.)
    - For development, you may want to reduce the check interval
    - Or mock the timeout for faster testing
    """
    print("\n" + "="*60)
    print("VERIFICATION: Periodic Session Timeout Check")
    print("="*60)
    
    session = session_data['session']
    check_interval_seconds = IDLE_CHECK_INTERVAL_MINUTES * 60
    max_checks = 12  # Check for up to 1 hour (12 x 5 minutes)
    
    print(f"Configuration:")
    print(f"  Check interval: {IDLE_CHECK_INTERVAL_MINUTES} minutes")
    print(f"  Maximum duration: {max_checks * IDLE_CHECK_INTERVAL_MINUTES} minutes")
    print(f"  Expected timeout: 15-30 minutes\n")
    
    for check_num in range(1, max_checks + 1):
        print(f"\n[Check {check_num}/{max_checks}]")
        print(f"Waiting {IDLE_CHECK_INTERVAL_MINUTES} minutes...")
        
        # Wait for the check interval
        time.sleep(check_interval_seconds)
        
        # Calculate elapsed time
        elapsed_minutes = (time.time() - session_data['idle_start']) / 60
        print(f"  Elapsed idle time: {elapsed_minutes:.1f} minutes")
        
        # Check session status
        print(f"  Checking session status...")
        is_active, status_code, redirected = check_session_status(session)
        
        session_data['check_count'] = check_num
        
        print(f"    Status code: {status_code}")
        print(f"    Session active: {is_active}")
        print(f"    Redirected to login: {redirected}")
        
        # Determine if session has expired
        if not is_active or redirected or status_code in [401, 403]:
            session_data['session_expired'] = True
            session_data['idle_end'] = time.time()
            session_data['expiry_time'] = elapsed_minutes
            
            print(f"\n✓ Session EXPIRED after {elapsed_minutes:.1f} minutes")
            print(f"  Status: {status_code}")
            if redirected:
                print(f"  Action: Redirected to login")
            
            # Session expired - test successful
            break
        else:
            print(f"  → Session still active")
    
    else:
        # Loop completed without break - session never expired
        session_data['session_expired'] = False
        session_data['idle_end'] = time.time()
        total_time = (session_data['idle_end'] - session_data['idle_start']) / 60
        
        print(f"\n⚠ Session did NOT expire after {total_time:.1f} minutes")
    
    # Generate final assessment
    print("\n" + "="*60)
    print("TEST RESULT: Session Idle Timeout")
    print("="*60)
    
    if session_data['session_expired']:
        expiry_time = session_data.get('expiry_time', 0)
        checks_made = session_data['check_count']
        
        print(f"Checks performed: {checks_made}")
        print(f"Session expired after: {expiry_time:.1f} minutes")
        
        if 15 <= expiry_time <= 30:
            print("\n✓ PASS: Session timeout working optimally")
            print("  Security Status: SECURE")
            print("  Finding: Session expired within recommended 15-30 minute window")
            print("  Timeout value: Appropriate for security/usability balance")
        elif expiry_time < 15:
            print("\n⚠ PASS: Session timeout working (but aggressive)")
            print("  Security Status: SECURE (overly cautious)")
            print("  Finding: Session expired quickly (< 15 minutes)")
            print("  Note: Very secure but may impact user experience")
            print("  Recommendation: Consider extending to 15-30 minutes")
        else:  # > 30 minutes
            print("\n⚠ PARTIAL PASS: Session timeout working (but lenient)")
            print("  Security Status: MOSTLY SECURE")
            print("  Finding: Session expired after > 30 minutes")
            print("  Note: Functional but longer than recommended")
            print("  Recommendation: Consider reducing to 15-30 minutes")
        
        print(f"  Evidence: Session invalidated after {expiry_time:.1f} min of inactivity")
        
    else:
        total_time = (session_data['idle_end'] - session_data['idle_start']) / 60
        
        print(f"Checks performed: {session_data['check_count']}")
        print(f"Total idle time tested: {total_time:.1f} minutes")
        print(f"Session status: Still active")
        
        print("\n✗ FAIL: Session timeout not working")
        print("  Security Status: VULNERABLE")
        print("  Severity: MEDIUM to HIGH")
        print("  Finding: Session did not expire after extended idle period")
        print("  Impact: Increases window for session hijacking/theft")
        print("  CWE: CWE-613 (Insufficient Session Expiration)")
        print("  OWASP: A07:2021 - Identification and Authentication Failures")
        print("  Recommendations:")
        print("    - Implement idle timeout (15-30 minutes recommended)")
        print("    - Track last activity timestamp server-side")
        print("    - Invalidate sessions after timeout period")
        print("    - Consider absolute session timeout as well")
    
    print("="*60 + "\n")
    
    # Assertion for test framework
    assert session_data['session_expired'], \
        f"Session did not expire after {session_data['check_count']} checks " \
        f"({session_data['check_count'] * IDLE_CHECK_INTERVAL_MINUTES} minutes)"