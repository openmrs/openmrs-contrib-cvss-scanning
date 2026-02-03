import pytest
from playwright.sync_api import sync_playwright
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# URL configuration
O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')

@pytest.fixture(scope="function")
def browser():
    """Setup Playwright browser for testing"""
    with sync_playwright() as p:
        # Launch browser
        browser = p.chromium.launch(
            headless=True,  # Headless in CI, visible locally
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
            ] if os.getenv('CI') else []
        )
        
        # Create context and page
        context = browser.new_context()
        page = context.new_page()
        
        # Set default timeout (equivalent to implicit wait)
        page.set_default_timeout(30000)  # 30 seconds
        
        # Add helper attribute for test data storage
        page.attack_type = None
        page.invalid_credential = None
        page.valid_credential = None
        
        yield page
        
        # Cleanup
        context.close()
        browser.close()
