import pytest
import pytest_bdd

from playwright.sync_api import sync_playwright
from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_BASE_URL

import os
from dotenv import load_dotenv

DEFAULT_LOAD_TIME = 1000

# URL configuration
O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')
O3_LOGIN_URL = f'{O3_BASE_URL}/login'
O3_HOME_URL = f'{O3_BASE_URL}/home'



