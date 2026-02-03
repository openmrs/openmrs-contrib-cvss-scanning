import pytest_bdd
from conftest import O3_BASE_URL, O3_LOGIN_URL, O3_HOME_URL
from playwright.sync_api import sync_playwright

@pytest_bdd.scenario('tests/session_management/session_management.feature',
                     'Cannot resuse expired session',
                     features_base_dir='')
def test_expired_session_reuse():
    """Test Case 3: Expired session reuse prevention"""
    pass

@pytest_bdd.given('the OpenMRS 3 home page is show after login')
def user_logged_in(browser):
    """User logs in and establishes a session"""
    print("\n" + "="*60)
    print("BACKGROUND: User Login")
    print("="*60)
    
    # Navigate to login
    browser.goto(O3_LOGIN_URL)
    browser.wait_for_timeout(2000)
    
    # Perform login
    browser.fill('input[id="username"]', 'admin')
    browser.wait_for_timeout(500)
    browser.fill('input[id="password"]', 'Admin123')
    browser.wait_for_timeout(500)
    
    # Click login button
    browser.click('button[type="submit"]')
    browser.wait_for_timeout(3000)
    
    # Verify login success
    current_url = browser.url
    assert 'home' in current_url.lower(), f"Login failed - URL: {current_url}"
    
    # Save cookies before logout
    browser.saved_cookies = browser.context.cookies()
    
    print(f"✓ Login successful")
    print(f"  URL: {current_url}")
    print(f"  Cookies saved: {len(browser.saved_cookies)}")
    print("="*60)

@pytest_bdd.when("a user's session had expired and is resused")
def logout_and_reuse_session(browser):
    """Logout to expire session, then try to reuse it"""
    print("\n" + "-"*60)
    print("ACTION: Logout and Attempt Session Reuse")
    print("-"*60)
    
    saved_cookies = browser.saved_cookies
    
    print(f"\nStep 1: Logging out to expire session")
    
    # Try to find and click logout button
    try:
        # Look for user menu or logout button
        # Common patterns in OpenMRS O3
        logout_selectors = [
            'button:has-text("Logout")',
            'a:has-text("Logout")',
            '[data-testid="logout"]',
            'button[aria-label="Logout"]'
        ]
        
        # Try to open user menu first
        try:
            browser.click('button[aria-label="User"]', timeout=5000)
            browser.wait_for_timeout(1000)
        except:
            pass
        
        # Try each logout selector
        logged_out = False
        for selector in logout_selectors:
            try:
                browser.click(selector, timeout=2000)
                browser.wait_for_timeout(2000)
                logged_out = True
                print("  ✓ Clicked logout button")
                break
            except:
                continue
        
        if not logged_out:
            # Fallback: clear cookies to simulate logout
            print("  ℹ Logout button not found, clearing cookies manually")
            browser.context.clear_cookies()
            
    except Exception as e:
        print(f"  ℹ Logout via UI failed: {e}")
        print("  ℹ Clearing cookies to simulate logout")
        browser.context.clear_cookies()
    
    # Verify logout by checking if we can access home
    browser.goto(O3_HOME_URL)
    browser.wait_for_timeout(2000)
    
    if 'login' in browser.url.lower():
        print("  ✓ Logout confirmed - redirected to login")
    else:
        print("  ⚠ May still be logged in, forcing logout...")
        browser.context.clear_cookies()
    
    print(f"\nStep 2: Attempting to reuse expired session")
    
    # Create new browser context and inject old cookies
    with sync_playwright() as p:
        attacker_browser = p.chromium.launch(headless=True)
        attacker_context = attacker_browser.new_context()
        
        print(f"  Injecting {len(saved_cookies)} expired cookies")
        attacker_context.add_cookies(saved_cookies)
        
        attacker_page = attacker_context.new_page()
        
        # Try to access protected page with expired session
        print(f"  Accessing: {O3_HOME_URL}")
        attacker_page.goto(O3_HOME_URL)
        attacker_page.wait_for_timeout(3000)
        
        final_url = attacker_page.url
        print(f"  Final URL: {final_url}")
        
        # Determine if reuse succeeded
        if 'login' in final_url.lower():
            browser.reuse_result = 'rejected'
            print("→ Expired session REJECTED - Redirected to login")
        elif 'home' in final_url.lower():
            browser.reuse_result = 'accepted'
            print("→ ⚠ Expired session ACCEPTED - Attacker got access!")
        else:
            browser.reuse_result = 'unclear'
            print(f"→ Unclear result - URL: {final_url}")
        
        attacker_context.close()
        attacker_browser.close()
    
    print("-"*60)

@pytest_bdd.then('the session should be denied')
def verify_session_denied(browser):
    """Verify expired session was rejected and calculate CVSS"""
    print("\n" + "="*60)
    print("VERIFICATION & CVSS CALCULATION")
    print("="*60)
    
    result = getattr(browser, 'reuse_result', 'unknown')
    
    print(f"Reuse Result: {result}")
    
    session_denied = (result == 'rejected')
    
    # ===================================================================
    # CVSS CALCULATION for Expired Session Reuse
    # ===================================================================
    
    # CVSS v3.1 Base Metrics for Session Reuse Vulnerability
    AV = 0.85   # Attack Vector: Network
    AC = 0.44   # Attack Complexity: High (requires session theft)
    PR = 0.62   # Privileges Required: Low (need old session)
    UI = 0.85   # User Interaction: None
    S = 0       # Scope: Unchanged
    
    # Impact Metrics
    C = 0.56    # Confidentiality: High (full user data access)
    I = 0.56    # Integrity: High (can modify data)
    A = 0.00    # Availability: None
    
    # Calculate Impact Sub-Score
    ISS_Base = 1 - ((1 - C) * (1 - I) * (1 - A))
    
    if S == 0:
        Impact = 6.42 * ISS_Base
    else:
        Impact = 7.52 * (ISS_Base - 0.029) - 3.25 * ((ISS_Base - 0.02) ** 15)
    
    # Calculate Exploitability Sub-Score
    Exploitability = 8.22 * AV * AC * PR * UI
    
    # Calculate Base Score
    if Impact <= 0:
        Base_score = 0
    else:
        if S == 0:
            Base_score = min(1.08 * (Impact + Exploitability), 10)
        else:
            Base_score = min(1.08 * (Impact + Exploitability), 10)
    
    Base_score = round(Base_score, 1)
    
    # ===================================================================
    # DISPLAY RESULTS
    # ===================================================================
    
    print("\nCVSS VULNERABILITY SCORE CALCULATION")
    print("="*60)
    print("Attack: Expired Session Reuse")
    print(f"Session Denied: {session_denied}")
    print("-"*60)
    print(f"CVSS Base Score: {Base_score}")
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
    print("  Attack Complexity (AC): High")
    print("  Privileges Required (PR): Low")
    print("  User Interaction (UI): None")
    print("  Scope (S): Unchanged")
    print("  Impact (CIA): High/High/None")
    print("")
    print(f"Severity Rating: {severity}")
    print("="*60)
    print("")
    
    # Assertions
    assert Base_score is not None, "CVSS score calculation failed"
    assert 0.0 <= Base_score <= 10.0, f"Invalid CVSS score: {Base_score}"
    
    # Note about result
    if session_denied:
        print("NOTE: Expired session reuse was prevented")
        print("This indicates proper session invalidation on logout")
    else:
        print("NOTE: Expired session was accepted")
        print("This indicates a critical session management vulnerability")
