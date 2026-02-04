"""
Shared login helper for session management tests.
Handles OpenMRS O3's two-step login process with rate limit recovery.
"""
import time

def perform_login(browser, username='admin', password='Admin123', max_retries=4, initial_wait=45):
    """
    Perform two-step login for OpenMRS O3 with aggressive rate limit handling
    
    Args:
        browser: Playwright page object
        username: Login username
        password: Login password
        max_retries: Number of retry attempts if rate limited
        initial_wait: Seconds to wait before first attempt (for rate limit cooldown)
    
    Returns: True if successful, False otherwise
    """
    
    # Initial cooldown - wait for rate limit to clear from previous tests
    if initial_wait > 0:
        print(f"  Waiting {initial_wait}s for rate limit cooldown...")
        time.sleep(initial_wait)
    
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                # Progressive backoff: 45s, 60s, 90s
                wait_time = 45 + (attempt * 15)
                print(f"  Retry {attempt}/{max_retries - 1} - Waiting {wait_time}s for rate limit recovery...")
                time.sleep(wait_time)
            
            # Refresh page
            print(f"  Attempt {attempt + 1}: Starting login sequence...")
            browser.goto(browser.url)
            browser.wait_for_timeout(2000)
            
            # Step 1: Enter username
            browser.fill('input[id="username"]', username, timeout=15000)
            browser.wait_for_timeout(1000)
            
            # Step 1: Click Continue
            browser.click('button[type="submit"]', timeout=15000)
            browser.wait_for_timeout(3000)
            
            # Step 2: Enter password (now visible)
            try:
                browser.fill('input[type="password"]', password, timeout=15000)
                browser.wait_for_timeout(1000)
            except Exception as e:
                print(f"  → Password field not accessible: {str(e)[:80]}")
                if attempt < max_retries - 1:
                    print(f"  → Will retry after cooldown...")
                    continue
                raise
            
            # Step 2: Click Login
            browser.click('button[type="submit"]', timeout=15000)
            browser.wait_for_timeout(5000)
            
            # Verify login success
            current_url = browser.url
            if 'home' in current_url.lower():
                print(f"  ✓ Login successful on attempt {attempt + 1}")
                return True
            
            # Still on login page - rate limited
            if 'login' in current_url.lower():
                print(f"  → Login blocked on attempt {attempt + 1} (rate limited)")
                if attempt < max_retries - 1:
                    continue
            
            return False
            
        except Exception as e:
            print(f"  → Error on attempt {attempt + 1}: {str(e)[:100]}")
            if attempt < max_retries - 1:
                continue
            return False
    
    print(f"  ✗ Login failed after {max_retries} attempts (likely rate limited)")
    return False
