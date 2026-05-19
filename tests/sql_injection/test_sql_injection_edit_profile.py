import pytest
import pytest_bdd
from pytest_bdd import parsers, scenario
from playwright.sync_api import Page
from tests.utils import DEFAULT_WAIT_TIME, O3_HOME_URL

from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor



loggedIn = False
testLocation = None

sqlTestStrings=[
    "hello;CREATE TABLE testingTable (testfield datetime PRIMARY KEY);"
]

sqlEditProfileNameLocations = {
    "first name":    "#givenName",
    "middle name":   "#middleName",
    "family name":   "#familyName",
}
sqlEditProfileAddressLocations = {
    "address 1":     "#address1",
    "address 2":     "#address2",
    "city":          "#cityVillage",
    "state":         "#stateProvince",
    "country":       "#country",
    "postal code":   "#postalCode",
}

@pytest.mark.parametrize("testString",sqlTestStrings)
@scenario('sql_injection.feature', 'SQL injection on <personNameSQLString> field of edit patient page')
@pytest_bdd.when(parsers.parse('the attacker tries to edit a patient {personNameSQLString} using a set of potential SQL strings'))
def test_sql_injection_on_edit_profile_page_parameterized(page:Page,testString,request,url_data):
    #run the test
    #fill in field and update patient
    page.goto(url_data["edit_url"])
    global testLocation
    scenarioString = request.getfixturevalue('_pytest_bdd_example')['personNameSQLString']
    testLocation=scenarioString
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator(sqlEditProfileNameLocations[scenarioString]).fill(testString)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Update patient").click()

@pytest.fixture(scope="function",autouse=True)
def cleanupTestPatient(page,url_data):
    yield
    if url_data["edit_url"]!=None:
        page.goto(url_data["edit_url"])
        page.wait_for_timeout(DEFAULT_WAIT_TIME)

        page.locator("#givenName").fill("Test")
        page.locator("#middleName").fill("Ing")
        page.locator("#familyName").fill("Patient")
        page.locator("#address1").fill("10000 Avenue Road")
        page.locator("#address2").fill("243")
        page.locator("#cityVillage").fill("Village Town")
        page.locator("#stateProvince").fill("St.Mrs Province")
        page.locator("#country").fill("USA")
        page.locator("#postalCode").fill("00000")
        page.locator("#phone").fill("XXX-555-XXXX")
        page.get_by_text("Update patient").click()
        #waits for page to load then ends
        child = page.get_by_text("Vitals and biometrics")
        child.wait_for()

#Reset database by removing a potential testingTable table
@pytest.fixture(scope="function",autouse=True)
def cleanupDatabase(cursor:MySQLCursor, connection:MySQLConnection):
    yield
    select_lockout_query = """
    DROP TABLE IF EXISTS testingTable;
    """
    
    cursor.execute(select_lockout_query)
    connection.commit()


    








