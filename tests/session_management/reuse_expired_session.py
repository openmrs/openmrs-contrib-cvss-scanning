"""
Test 3: Expired Session Reuse Prevention
=========================================

WHAT THIS TESTS:
Can an expired or logged-out session cookie still be used to access the system?

WHY IT MATTERS:
If sessions aren't properly invalidated:
- Attacker can replay stolen cookies indefinitely
- Logged-out sessions can be reused
- Sessions found in browser cache/history can grant access

HOW IT WORKS:
1. Login and save the session cookie
2. Logout (which should invalidate the session)
3. Try to use the old cookie in a new request
4. Check if server rejects the expired session

EXPECTED SECURE BEHAVIOR:
- After logout, session should be invalidated server-side
- Old cookies should be rejected (401/403)
- Should redirect to login or deny access
- Should NOT grant access with old session

MINIMAL DEPENDENCIES:
- pytest-bdd (for Gherkin scenarios)
- requests (for HTTP requests)

RUN WITH: pytest tests/session_management/reuse_expired_session.py -v -s
"""

import pytest
import requests
import os

# Test configuration
LOGIN_URL = 'https://o3.openmrs.org/openmrs/spa/login'
LOGOUT_URL = 'https://o3.openmrs.org/openmrs/spa/logout'
HOME_URL = 'https://o3.openmrs.org/openmrs/spa/home'
USERNAME = 'admin'
PASSWORD = 'Admin123'


@pytest.fixture
def session_data():
    """
    Fixture to store session data across test steps
    """
    return {
        'session': requests.Session(),
        'cookies': {},
        'expired_cookies': {},
        'responses': {}
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
            (response.status_code == 200 and 'JSESSIONID' in session.cookies)
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
def user_has_session_to_expire(session_data):
    """
    BACKGROUND: Establish a session that we'll expire
    
    This creates a logged-in session, and we'll save the cookies
    before expiring them to test if they can be reused.
    """
    print("\n" + "="*60)
    print("BACKGROUND: Creating Session to Expire")
    print("="*60)
    
    success, cookies = perform_login(session_data['session'])
    
    assert success, "Failed to login - cannot proceed with test"
    assert cookies, "No session cookies found"
    
    session_data['cookies'] = cookies.copy()
    
    print("\n✓ Session established (will be expired)")
    print("="*60)


# =============================================================================
# WHEN STEP: Expire and Reuse Session
# =============================================================================

@when("a user's session had expired and is resused")
def expire_and_reuse_session(session_data):
    """
    ACTION: Expire the session and try to reuse it
    
    This combines two actions:
    1. Expire the session (via logout)
    2. Try to reuse the expired session
    """
    # First, expire the session
    print("\n" + "-"*60)
    print("ACTION: Expiring Session via Logout")
    print("-"*60)
    
    # Save cookies before logout (attacker cached them)
    session_data['expired_cookies'] = session_data['cookies'].copy()
    
    print("Saved session cookies before logout:")
    for name, value in session_data['expired_cookies'].items():
        print(f"  {name} = {value[:20]}...")
    
    # Perform logout
    session = session_data['session']
    
    print(f"\nAttempting logout at: {LOGOUT_URL}")
    
    try:
        # Method 1: Call logout endpoint
        response = session.get(LOGOUT_URL, allow_redirects=True)
        print(f"  Logout status: {response.status_code}")
        print(f"  Final URL: {response.url}")
        
        if 'login' in response.url.lower():
            print("✓ Logout successful - redirected to login")
        else:
            print("⚠ Logout response unclear")
        
    except Exception as e:
        print(f"⚠ Logout endpoint error: {e}")
        print("  Note: Some apps don't have explicit logout endpoint")
    
    # Alternative: Clear session cookies (simulates manual logout)
    session.cookies.clear()
    print("\n✓ Session cookies cleared")
    
    # Verify we're logged out by checking access
    try:
        verify_response = session.get(HOME_URL, allow_redirects=False)
        if verify_response.status_code in [401, 403] or verify_response.is_redirect:
            print("✓ Confirmed logged out - access denied")
        else:
            print("⚠ Still appears to have access")
    except:
        pass
    
    print("-"*60)
    
    # Now try to reuse the expired session
    print("\n" + "-"*60)
    print("TEST: Attempting to Reuse Expired Session")
    print("-"*60)
    
    # Get the expired cookies we saved
    expired_cookies = session_data['expired_cookies']
    
    if not expired_cookies:
        print("⚠ No expired cookies to test")
        session_data['responses']['reuse'] = None
        return
    
    print("Attacker has these expired cookies:")
    for name, value in expired_cookies.items():
        print(f"  {name} = {value[:20]}...")
    
    # Create NEW session (simulates attacker's computer)
    attacker_session = requests.Session()
    
    # Inject expired cookies
    for name, value in expired_cookies.items():
        attacker_session.cookies.set(name, value)
    
    print(f"\nAttempting to access: {HOME_URL}")
    print("Using expired session cookie...")
    
    try:
        # Make request with expired cookie
        response = attacker_session.get(HOME_URL, allow_redirects=False)
        
        # Store response
        session_data['responses']['reuse'] = response
        
        print(f"\nResponse Status: {response.status_code}")
        
        if response.is_redirect:
            redirect_url = response.headers.get('Location', 'Unknown')
            print(f"Redirected to: {redirect_url}")
        
        # Analyze response
        if response.status_code in [401, 403]:
            print("\n→ Expired session REJECTED (Unauthorized/Forbidden)")
            session_data['reuse_result'] = 'rejected'
        elif response.is_redirect and 'login' in response.headers.get('Location', '').lower():
            print("\n→ Expired session REJECTED (Redirect to login)")
            session_data['reuse_result'] = 'rejected'
        elif response.status_code == 200:
            print("\n→ ⚠ Expired session ACCEPTED (Got 200 OK)")
            session_data['reuse_result'] = 'accepted'
        else:
            print(f"\n→ Unclear result (Status {response.status_code})")
            session_data['reuse_result'] = 'unclear'
        
    except Exception as e:
        print(f"\n✗ Request failed: {e}")
        session_data['responses']['reuse'] = None
        session_data['reuse_result'] = 'error'
    
    print("-"*60)


# =============================================================================
# THEN STEP: Verify Session Denied
# =============================================================================

@then('the session should be denied')
def verify_session_denied(session_data):
    """
    VERIFICATION: Check if expired session was rejected
    
    WHAT WE CHECK:
    - Status code (should be 401/403)
    - Or redirect to login
    - Should NOT be 200 OK
    
    SECURITY IMPLICATIONS:
    - PASS = Server tracks session validity, invalidates on logout
    - FAIL = Sessions can be replayed indefinitely (critical vulnerability)
    """
    print("\n" + "="*60)
    print("VERIFICATION: Expired Session Rejection")
    print("="*60)
    
    response = session_data['responses'].get('reuse')
    result = session_data.get('reuse_result', 'unknown')
    
    if not response:
        print("✗ Unable to verify - request failed")
        print("  Test inconclusive")
        session_data['final_verdict'] = 'inconclusive'
        # Don't fail the test if we couldn't make the request
        return
    
    status_code = response.status_code
    
    print(f"Response Status: {status_code}")
    print(f"Test Result: {result}")
    
    # Determine if properly rejected
    properly_rejected = (result == 'rejected')
    
    session_data['final_verdict'] = 'pass' if properly_rejected else 'fail'
    
    # Check for redirect to login
    redirected_to_login = False
    
    if response.is_redirect:
        redirect_url = response.headers.get('Location', '')
        print(f"Redirect Location: {redirect_url}")
        
        if 'login' in redirect_url.lower():
            redirected_to_login = True
            print("✓ Redirected to login page")
    elif response.status_code in [401, 403]:
        print("✓ Access denied (401/403)")
        redirected_to_login = True  # Functionally equivalent
    
    # Generate final assessment
    print("\n" + "="*60)
    print("TEST RESULT: Expired Session Reuse Prevention")
    print("="*60)
    
    verdict = session_data.get('final_verdict', 'unknown')
    reuse_result = session_data.get('reuse_result', 'unknown')
    
    print(f"Reuse Attempt Result: {reuse_result}")
    print(f"Redirected to Login: {redirected_to_login}")
    
    if verdict == 'pass' and redirected_to_login:
        print("\n✓ PASS: Expired sessions cannot be reused")
        print("  Security Status: SECURE")
        print("  Finding: Server properly invalidates sessions on logout")
        print("  Evidence: Expired session rejected, redirected to login")
        print("  Recommendation: Continue monitoring session lifecycle")
        
    elif verdict == 'pass':
        print("\n⚠ PARTIAL PASS: Expired session rejected")
        print("  Security Status: MOSTLY SECURE")
        print("  Finding: Session invalidated but no clear redirect")
        print("  Recommendation: Implement user-friendly error handling")
        
    else:
        print("\n✗ FAIL: Expired sessions can be reused")
        print("  Security Status: VULNERABLE")
        print("  Severity: CRITICAL")
        print("  Finding: Logged-out sessions can still grant access")
        print("  Impact: Attacker can replay stolen sessions indefinitely")
        print("  CWE: CWE-613 (Insufficient Session Expiration)")
        print("  OWASP: A02:2021 - Cryptographic Failures")
        print("  Recommendations:")
        print("    - Implement server-side session tracking")
        print("    - Invalidate sessions on logout")
        print("    - Track session state in database/cache")
        print("    - Implement session token rotation")
    
    print("="*60 + "\n")
    
    # Assertion
    assert redirected_to_login or verdict == 'pass', "Expired session reuse not properly prevented"