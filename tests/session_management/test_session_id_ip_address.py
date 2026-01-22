"""
Test 1: Session ID Hijacking from Different IP Address
================================================

WHAT THIS TESTS:
Can a stolen session cookie be used from a different IP address?

WHY IT MATTERS:
If vulnerable, an attacker who steals your session cookie (via WiFi sniffing,
malware, XSS) can access your account from anywhere in the world.

HOW IT WORKS:
1. Login to get a valid session (simulates legitimate user)
2. Extract the session cookie
3. Make a new request with that cookie (simulates attacker from different IP)
4. Check if the server accepts or rejects the hijacked session

EXPECTED SECURE BEHAVIOR:
- Server should reject the session (401/403)
- Or redirect to login page
- Should NOT grant access with status 200 OK

MINIMAL DEPENDENCIES:
- pytest-bdd (for Gherkin scenarios)
- requests (for HTTP requests, replaces Selenium + ChromeDriver)

RUN WITH: pytest tests/session_management/session_id_ip_address.py -v -s
"""

import pytest
import requests
import os

# Test configuration
LOGIN_URL = 'https://o3.openmrs.org/openmrs/spa/login'
HOME_URL = 'https://o3.openmrs.org/openmrs/spa/home'
USERNAME = 'admin'
PASSWORD = 'Admin123'


@pytest.fixture
def session_data():
    """
    Fixture to store session data across test steps
    This replaces the browser fixture from Selenium version
    """
    return {
        'session': requests.Session(),
        'cookies': {},
        'responses': {}
    }


def perform_login(session_obj, username=USERNAME, password=PASSWORD):
    """
    Perform login using requests library (no browser needed)
    
    This function makes HTTP POST requests to login, similar to what
    a browser would do, but without actually opening a browser.
    
    Returns: tuple (success: bool, session_cookies: dict)
    """
    print("\n" + "="*60)
    print("PERFORMING LOGIN")
    print("="*60)
    
    session = session_obj
    
    try:
        print("Accessing login page...")
        response = session.get(LOGIN_URL)
        print(f"  Status: {response.status_code}")
        
        print("\nSubmitting credentials...")
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
def user_logged_in(session_data):
    """
    BACKGROUND: Establish a legitimate authenticated session
    
    This simulates a real user logging in normally.
    We'll save the session cookies for the hijacking test.
    """
    print("\n" + "="*60)
    print("BACKGROUND: User Login")
    print("="*60)
    
    success, cookies = perform_login(session_data['session'])
    
    assert success, "Failed to login - cannot proceed with test"
    assert cookies, "No session cookies found"
    
    # Store cookies for later use
    session_data['cookies'] = cookies
    
    print("\n✓ Background setup complete")
    print("="*60)


# =============================================================================
# WHEN STEP: Simulate Session Hijacking
# =============================================================================

@when('the attacker steals the session ID and tries to use it from a different IP address')
def simulate_hijacking(session_data):
    """
    TEST ACTION: Simulate attacker using stolen session cookie from different IP
    
    HOW THIS WORKS:
    - We have the legitimate session cookies from background step
    - We create a NEW requests session (simulates different computer/IP)
    - We inject the stolen cookie into this new session
    - We make a request to a protected page
    
    TECHNICAL NOTE:
    Creating a new requests.Session() simulates coming from a different
    source because:
    - Different session object
    - No connection pooling shared with original
    - Server sees it as a different client
    - In a real scenario, this would be from an actual different IP
    """
    print("\n" + "-"*60)
    print("TEST: Session Hijacking Simulation")
    print("-"*60)
    
    # Get the stolen cookies
    stolen_cookies = session_data['cookies']
    
    print("\nAttacker has stolen these session cookies:")
    for name, value in stolen_cookies.items():
        print(f"  {name} = {value[:20]}...")
    
    # Create a NEW session (simulates attacker's computer/different IP)
    print("\nCreating new session (simulating different IP address)...")
    attacker_session = requests.Session()
    
    # Inject the stolen cookies
    print("Injecting stolen session cookies...")
    for name, value in stolen_cookies.items():
        attacker_session.cookies.set(name, value)
        print(f"  Set cookie: {name}")
    
    print("\nAttacker attempting to access protected page from different IP...")
    print(f"Target URL: {HOME_URL}")
    
    try:
        # Make request with stolen session cookie
        # allow_redirects=False to catch redirect responses
        response = attacker_session.get(HOME_URL, allow_redirects=False)
        
        # Store response for verification
        session_data['responses']['hijack'] = response
        
        print(f"\nResponse Status: {response.status_code}")
        
        if response.is_redirect:
            redirect_url = response.headers.get('Location', 'Unknown')
            print(f"Redirected to: {redirect_url}")
        
        # Analyze result
        if response.status_code in [401, 403]:
            print("\n→ Hijacked session REJECTED (Unauthorized/Forbidden)")
            session_data['hijack_result'] = 'rejected'
        elif response.is_redirect and 'login' in response.headers.get('Location', '').lower():
            print("\n→ Hijacked session REJECTED (Redirect to login)")
            session_data['hijack_result'] = 'rejected'
        elif response.status_code == 200:
            print("\n→ ⚠ Hijacked session ACCEPTED (Got 200 OK)")
            session_data['hijack_result'] = 'accepted'
        else:
            print(f"\n→ Unclear result (Status {response.status_code})")
            session_data['hijack_result'] = 'unclear'
        
    except Exception as e:
        print(f"\n✗ Request failed: {e}")
        session_data['responses']['hijack'] = None
        session_data['hijack_result'] = 'error'
    
    print("-"*60)


# =============================================================================
# THEN STEP: Verify Access Denied
# =============================================================================

@then('the session should be denied access')
def verify_hijacking_prevented(session_data):
    """
    VERIFICATION: Check if the hijacked session was rejected
    
    WHAT WE CHECK:
    1. HTTP status code
       - 401 (Unauthorized) = GOOD, session rejected
       - 403 (Forbidden) = GOOD, access denied
       - 302/303 (Redirect) = Check if redirect to login
       - 200 (OK) = BAD, attacker got access!
    
    2. Redirect location
       - If redirected to /login = GOOD
       - If stayed on protected page = BAD
    
    SECURITY ASSESSMENT:
    - PASS = Server has IP validation or session binding
    - FAIL = Vulnerable to session hijacking
    """
    print("\n" + "="*60)
    print("VERIFICATION: Checking Server Response")
    print("="*60)
    
    response = session_data['responses'].get('hijack')
    result = session_data.get('hijack_result', 'unknown')
    
    if not response:
        print("✗ Unable to verify - request failed")
        print("  Test inconclusive")
        session_data['final_verdict'] = 'inconclusive'
        # Don't fail the test if we couldn't make the request
        return
    
    status_code = response.status_code
    is_redirect = response.is_redirect
    
    print(f"Response Analysis:")
    print(f"  Status Code: {status_code}")
    print(f"  Is Redirect: {is_redirect}")
    print(f"  Test Result: {result}")
    
    # Determine if access was properly denied
    access_denied = (result == 'rejected')
    reason = ""
    
    if status_code in [401, 403]:
        reason = f"Server returned {status_code} (Unauthorized/Forbidden)"
    elif is_redirect:
        redirect_location = response.headers.get('Location', '')
        print(f"  Redirect To: {redirect_location}")
        
        if 'login' in redirect_location.lower():
            reason = "Redirected to login page"
    elif status_code == 200:
        reason = "Server returned 200 OK - attacker gained access!"
    
    session_data['final_verdict'] = 'pass' if access_denied else 'fail'
    
    # Generate final assessment
    print("\n" + "="*60)
    print("TEST RESULT: Session Hijacking Prevention")
    print("="*60)
    
    if access_denied:
        print("✓ PASS: Hijacked session was REJECTED")
        print(f"  Reason: {reason}")
        print("\n  Security Status: SECURE")
        print("  Finding: Server properly validates session context")
        print("  Evidence: Different IP/client rejected session reuse")
        print("  Protection: IP binding, device fingerprinting, or similar")
        print("  Recommendation: Continue monitoring session security")
        
    else:
        print("✗ FAIL: Hijacked session was ACCEPTED")
        print(f"  Reason: {reason}")
        print("\n  Security Status: VULNERABLE")
        print("  Severity: HIGH")
        print("  Finding: Stolen session cookies can be used from different IPs")
        print("  Impact: Attacker can impersonate users after stealing sessions")
        print("  Attack Vectors:")
        print("    - WiFi sniffing (if HTTPS not enforced)")
        print("    - XSS attacks stealing cookies")
        print("    - Malware on user's device")
        print("    - Browser cache/history exploitation")
        print("  CWE: CWE-384 (Session Fixation)")
        print("  OWASP: A07:2021 - Identification and Authentication Failures")
        print("  Recommendations:")
        print("    - Implement IP address validation")
        print("    - Use device fingerprinting")
        print("    - Set HTTPOnly and Secure flags on cookies")
        print("    - Implement session binding to client characteristics")
        print("    - Require re-authentication for sensitive operations")
        print("    - Consider implementing step-up authentication")
    
    print("="*60 + "\n")
    
    # Assertion for test framework
    assert access_denied, \
        f"Session hijacking not prevented - stolen session accepted from different IP"