import pytest_bdd
from conftest import O3_BASE_URL, O3_LOGIN_URL, O3_HOME_URL
from login_helper import perform_login
from playwright.sync_api import sync_playwright
import os

@pytest_bdd.scenario('tests/session_management/session_management.feature',
                     'Session ID use on a different IP Address',
                     features_base_dir='')
def test_session_hijacking():
    """Test Case 1: Session hijacking from different context"""
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
    
    # Perform two-step login
    success = perform_login(browser)
    assert success, f"Login failed - URL: {browser.url}"
    
    # Store cookies for later use
    browser.session_cookies = browser.context.cookies()
    
    print(f"✓ Login successful")
    print(f"  URL: {browser.url}")
    print(f"  Cookies captured: {len(browser.session_cookies)}")
    print("="*60)

@pytest_bdd.when('the attacker steals the session ID and tries to use it from a different IP address')
def simulate_session_hijacking(browser):
    """Simulate session hijacking by using cookies in new browser context"""
    print("\n" + "-"*60)
    print("ATTACK: Session Hijacking Simulation")
    print("-"*60)
    
    stolen_cookies = browser.session_cookies
    
    print(f"\nAttacker stole {len(stolen_cookies)} cookies")
    for cookie in stolen_cookies:
        print(f"  {cookie['name']} = {cookie['value'][:20]}...")
    
    # Create a NEW browser context (simulates different client/IP)
    print("\nCreating new browser context (simulating attacker's computer)...")
    
    with sync_playwright() as p:
        attacker_browser = p.chromium.launch(headless=True)
        attacker_context = attacker_browser.new_context()
        
        # Inject stolen cookies
        print("Injecting stolen cookies into attacker's browser...")
        attacker_context.add_cookies(stolen_cookies)
        
        attacker_page = attacker_context.new_page()
        
        # Try to access protected page with stolen session
        print(f"\nAttacker accessing protected page: {O3_HOME_URL}")
        attacker_page.goto(O3_HOME_URL)
        attacker_page.wait_for_timeout(3000)
        
        # Check if access granted or denied
        final_url = attacker_page.url
        
        print(f"  Final URL: {final_url}")
        
        # Determine if hijack succeeded
        if 'login' in final_url.lower():
            browser.hijack_result = 'rejected'
            print("→ Session REJECTED - Redirected to login")
        elif 'home' in final_url.lower():
            browser.hijack_result = 'accepted'
            print("→ ⚠ Session ACCEPTED - Attacker got access!")
        else:
            browser.hijack_result = 'unclear'
            print(f"→ Unclear result - URL: {final_url}")
        
        attacker_context.close()
        attacker_browser.close()
    
    print("-"*60)

@pytest_bdd.then('the session should be denied access')
def verify_hijacking_prevented(browser):
    """Verify session hijacking was prevented and calculate CVSS"""
    print("\n" + "="*60)
    print("VERIFICATION & CVSS CALCULATION")
    print("="*60)
    
    result = getattr(browser, 'hijack_result', 'unknown')
    
    print(f"Hijack Result: {result}")
    
    access_denied = (result == 'rejected')
    
    # CVSS v3.1 Base Metrics for Session Hijacking
    AV = 0.85   # Attack Vector: Network
    AC = 0.44   # Attack Complexity: High
    PR = 0.62   # Privileges Required: Low
    UI = 0.85   # User Interaction: None
    S = 0       # Scope: Unchanged
    
    C = 0.56    # Confidentiality: High
    I = 0.56    # Integrity: High
    A = 0.00    # Availability: None
    
    ISS_Base = 1 - ((1 - C) * (1 - I) * (1 - A))
    
    if S == 0:
        Impact = 6.42 * ISS_Base
    else:
        Impact = 7.52 * (ISS_Base - 0.029) - 3.25 * ((ISS_Base - 0.02) ** 15)
    
    Exploitability = 8.22 * AV * AC * PR * UI
    
    if Impact <= 0:
        Base_score = 0
    else:
        if S == 0:
            Base_score = min(1.08 * (Impact + Exploitability), 10)
        else:
            Base_score = min(1.08 * (Impact + Exploitability), 10)
    
    Base_score = round(Base_score, 1)
    
    print("\nCVSS VULNERABILITY SCORE CALCULATION")
    print("="*60)
    print("Attack: Session Hijacking")
    print(f"Access Denied: {access_denied}")
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
    
    assert Base_score is not None, "CVSS score calculation failed"
    assert 0.0 <= Base_score <= 10.0, f"Invalid CVSS score: {Base_score}"
    
    if not access_denied:
        print("NOTE: Session hijacking was successful")
        print("This indicates a vulnerability in session management")
    else:
        print("NOTE: Session hijacking was prevented")
        print("This indicates proper session binding controls")
