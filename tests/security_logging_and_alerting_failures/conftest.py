import pytest
import pytest_bdd

from playwright.sync_api import Page
from tests.utils import login, O3_ROOT_URL, DEFAULT_WAIT_TIME
from datetime import datetime, timezone

@pytest_bdd.when('an admin logs in on the login page')
def when_an_admin_logs_in_on_the_login_page(page:Page):
    
    login(page, "admin", "Admin123")

@pytest_bdd.when('visits the server logs page')
def when_visits_the_server_logs_page(page:Page):
    
    page.goto(O3_ROOT_URL + "admin/maintenance/serverLog.form")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

@pytest_bdd.given('the current time is saved')
def given_the_current_time_is_saved(date_time_data):
    
    date_time_data["saved_timestamp"] = datetime.now(timezone.utc)

@pytest.fixture(scope="function")
def date_time_data():
    return {}