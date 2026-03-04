import pytest
from playwright.sync_api import sync_playwright
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# URL configuration
O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')