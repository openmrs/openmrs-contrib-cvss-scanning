import re
import pytest
from pytest_bdd import scenarios, given, when, then, parsers
from playwright.sync_api import Page, expect


O3_LOGIN_URL = 'http://0.0.0.0:80/openmrs/spa/login'
O3_WELCOME_URL = 'http://0.0.0.0:80/openmrs/spa/login/location'
O3_HOMEPAGE_URL = 'http://0.0.0.0:80/openmrs/spa/home/service-queues#'
DEFAULT_WAIT_TIME = 1000

def navigate_to_login(browser):
    """Navigate to O3 login page"""
    browser.goto(O3_LOGIN_URL)
    browser.wait_for_timeout(DEFAULT_WAIT_TIME)

def login(page:Page):
    page.goto(O3_LOGIN_URL)
    page.locator('#username').fill("admin")
    page.get_by_text("Continue").click()
    page.locator('#password').fill("Admin123")
    page.get_by_text("Log in").click()

    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    if(page.url==O3_WELCOME_URL):
        page.get_by_text("Outpatient Clinic").click()
        page.get_by_text("Remember my location").click()
        page.get_by_text("Confirm").click()

def createTestPatient(page:Page):
    page.goto(O3_HOMEPAGE_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Add patient').click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator('#givenName').fill("Test")
    page.locator('#familyName').fill("Patient")
    page.get_by_text("Other").click()

    #date of birth -> no, estimated age
    page.locator('[class="cds--content-switcher cds--layout-constraint--size__default-md cds--layout-constraint--size__min-sm cds--layout-constraint--size__max-lg"]').get_by_text('No').click()
    page.locator('#yearsEstimated').fill("26")
    page.locator('#monthsEstimated').fill("0")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Register patient").click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

def verifyTestPatientExists(page:Page):
    page.goto(O3_HOMEPAGE_URL)
    #page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #page.get_by_label('Search patient',exact=True).click()
    #page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #if(page.get_by_text("Other").count()>=1):
        #page.wait_for_timeout(DEFAULT_WAIT_TIME)
    #else:
        #createTestPatient(page)
        #page.wait_for_timeout(DEFAULT_WAIT_TIME)


def navigateToTestPatient(page:Page):
    page.goto(O3_HOMEPAGE_URL)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_label('Search patient',exact=True).click()
    page.get_by_placeholder('Search for a patient by name or identifier number').fill("Test Patient")
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

    child = page.get_by_text("01-Jan-2000")
    child.click()
    #parent = page.locator(".a").filter(has=child)
    #parent.click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME*2)
    #find and click actions button
    child = page.get_by_text("Actions")
    child.click()
    #parent = page.location("button").filter(has=child)
    #parent.click()
    #find and click actions button
    page.wait_for_timeout(DEFAULT_WAIT_TIME/5)
    child = page.get_by_text("Edit patient details")
    child.click()
    #parent = page.location("button").filter(has=child)
    #parent.click()
    page.wait_for_timeout(DEFAULT_WAIT_TIME)

def calculateCVSSScore():
    return 0.0