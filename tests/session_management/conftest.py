import pytest
from playwright.sync_api import sync_playwright
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# URL configuration
O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')
O3_LOGIN_URL = f'{O3_BASE_URL}/login'
O3_HOME_URL = f'{O3_BASE_URL}/home'

@pytest.fixture(scope="function")
def browser():
    """Setup Playwright browser for testing"""
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
            ] if os.getenv('CI') else []
        )
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(30000)
        
        yield page
        
        context.close()
        browser.close()
