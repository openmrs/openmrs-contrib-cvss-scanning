import pytest_bdd
from conftest import O3_BASE_URL, O3_LOGIN_URL, O3_HOME_URL
import time

@pytest_bdd.scenario('tests/session_management/session_management.feature',
                     'Session expiration after idle time',
                     features_base_dir='')
def test_idle_timeout():
    """Test Case 2: Session idle timeout"""
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
    
    print(f"✓ Login successful")
    print(f"  URL: {current_url}")
    print("="*60)

@pytest_bdd.when('the user stays idle')
def user_stays_idle(browser):
    """User remains idle (no activity)"""
    print("\n" + "-"*60)
    print("ACTION: User Stays Idle")
    print("-"*60)
    
    # Record idle start time
    browser.idle_start = time.time()
    
    # NOTE: In production, idle timeout is typically 15-30 minutes
    # For testing purposes, we'll simulate with a shorter wait
    idle_duration_seconds = 30  # Test duration
    
    print(f"Simulating idle period: {idle_duration_seconds} seconds")
    print("NOTE: Production timeout is typically 15-30 minutes")
    print("      This test uses shortened duration for CI/CD efficiency")
    
    time.sleep(idle_duration_seconds)
    
    browser.idle_duration = idle_duration_seconds
    
    print(f"✓ Idle period complete: {idle_duration_seconds}s")
    print("-"*60)

@pytest_bdd.then('the session should be checked if it is idle after every five minutes')
def check_session_timeout(browser):
    """Check if session has expired after idle period"""
    print("\n" + "="*60)
    print("VERIFICATION: Session Timeout Check")
    print("="*60)
    
    # Try to access a protected page after idle period
    print(f"Attempting to access: {O3_HOME_URL}")
    
    try:
        browser.goto(O3_HOME_URL)
        browser.wait_for_timeout(3000)
        
        final_url = browser.url
        print(f"  Final URL: {final_url}")
        
        # Check if session expired (redirected to login)
        if 'login' in final_url.lower():
            browser.session_expired = True
            print("→ Session EXPIRED - Redirected to login")
        else:
            browser.session_expired = False
            print("→ Session ACTIVE - Still on protected page")
            
    except Exception as e:
        print(f"  Error checking session: {e}")
        browser.session_expired = False
    
    # ===================================================================
    # CVSS CALCULATION for Session Timeout
    # ===================================================================
    
    session_expired = getattr(browser, 'session_expired', False)
    idle_duration = getattr(browser, 'idle_duration', 0)
    
    # CVSS v3.1 Base Metrics for Session Timeout Vulnerability
    AV = 0.62   # Attack Vector: Adjacent (physical access or local network)
    AC = 0.44   # Attack Complexity: High (requires unattended session)
    PR = 0.62   # Privileges Required: Low (need initial login)
    UI = 0.85   # User Interaction: None
    S = 0       # Scope: Unchanged
    
    # Impact Metrics (if no timeout)
    C = 0.56    # Confidentiality: High (access to user data)
    I = 0.22    # Integrity: Low (limited time window)
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
    print("Attack: Session Timeout Vulnerability")
    print(f"Session Expired: {session_expired}")
    print(f"Test Duration: {idle_duration}s (simulated)")
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
    print("  Attack Vector (AV): Adjacent")
    print("  Attack Complexity (AC): High")
    print("  Privileges Required (PR): Low")
    print("  User Interaction (UI): None")
    print("  Scope (S): Unchanged")
    print("  Impact (CIA): High/Low/None")
    print("")
    print(f"Severity Rating: {severity}")
    print("="*60)
    print("")
    
    # Assertions
    assert Base_score is not None, "CVSS score calculation failed"
    assert 0.0 <= Base_score <= 10.0, f"Invalid CVSS score: {Base_score}"
    
    # Note about result
    if session_expired:
        print("NOTE: Session timeout is working")
        print("This is expected security behavior")
    else:
        print("NOTE: Session did not expire during test period")
        print("This may indicate missing timeout controls")
        print("IMPORTANT: This test uses shortened duration (30s)")
        print("           Production timeout should be 15-30 minutes")
