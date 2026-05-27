"""
Shared login helper for session management tests.
Handles OpenMRS O3's two-step login process.
"""

from tests.utils import DEFAULT_WAIT_TIME

def perform_login(browser, username='admin', password='Admin123'):
    """
    Perform two-step login for OpenMRS O3
    
    Returns: True if successful, False otherwise
    """
    try:
        # Step 1: Enter username
        browser.fill('input[id="username"]', username)
        browser.wait_for_timeout(DEFAULT_WAIT_TIME)
        
        # Step 1: Click Continue
        browser.click('button[type="submit"]')
        browser.wait_for_timeout(DEFAULT_WAIT_TIME * 2)
        
        # Step 2: Enter password (now visible)
        browser.fill('input[type="password"]', password)
        browser.wait_for_timeout(DEFAULT_WAIT_TIME / 2)
        
        # Step 2: Click Login
        browser.click('button[type="submit"]')
        browser.wait_for_timeout(DEFAULT_WAIT_TIME * 3)
        
        # Verify login success
        current_url = browser.url
        return 'home' in current_url.lower()
        
    except Exception as e:
        print(f"Login error: {e}")
        return False
