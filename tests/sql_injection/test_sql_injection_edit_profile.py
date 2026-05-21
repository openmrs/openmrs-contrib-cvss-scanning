import pytest
import pytest_bdd
from pytest_bdd import parsers, scenario
from playwright.sync_api import Page
from tests.utils import DEFAULT_WAIT_TIME, calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics
from tests.conftest import save_cvss_result

from mysql.connector import MySQLConnection
from mysql.connector.cursor import MySQLCursor

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

@pytest_bdd.given('a CVSS score is calculated and printed')
def given_cvss_score_is_calculted_and_printed(request):


    # For an indepth reference to CVSS 4.0
    # https://www.first.org/cvss/v4.0/specification-document


    # To determine the CVSS score, the following metrics will need
    # to be decided. Here is each metric, and the possible values.
    # These are basic descriptions of the metrics. For further clarification
    # inspect the specification document linked above.


    # Attack Vector (AV) / BaseMetrics.AttackVector
    # This metric relfects the context for which vulnerability exploitation is possible.
    #   Network     The vulnerable system is bound to the network stack
    #
    #   Adjacent    The vulnerable system is bound to a protocol stack, but the attack is limited at the protocol level
    #
    #   Local       The attacker exploits the vulnerability by accessing the target system locally or through terminal emulation (e.g., SSH); or the attacker relies 
    #               on User Interaction by another person to perform actions required to exploit the vulnerability
    #
    #   Physical    The attack requires the attacker to physically touch or manipulate the vulnerable system.


    AV = BaseMetrics.AttackVector.NETWORK


    # Attack Complexity (AC) / BaseMetrics.AttackComplexity
    # This metric caputres the actions taken by an attacker to evade existing built-in security
    #   Low         The attacker must take no measurable action to exploit 
    #               the vulnerability.
    #
    #   High        The attacker must have additional methods available to 
    #               bypass security measures in place or the attacker must 
    #               gather some target-specific secret before the attack 
    #               can be successful.


    AC = BaseMetrics.AttackComplexity.LOW


    # Attack Requirements (AT) / BaseMetrics.AttackRequirements
    # This metric captures the prerequisites or conditions to access the vulnerability.
    #   None        The attacker can expect to be able to reach the
    #               vulnerability and execute the exploit under all or
    #               most instances of the vulnerability.
    #
    #   Present     The successful attack depends on the presence of
    #               specific deployment and execution conditions. A 
    #               race condition must be won to successfully exploit 
    #               the vulnerability or The attacker must inject 
    #               themselves into the logical network path between 
    #               the target and the resource requested by the victim.


    AT = BaseMetrics.AttackRequirements.NONE


    # Privileges Required (PR) / BaseMetrics.PriviledgesRequired
    # This metric describes the level of priviledges an attacker must possess prior to exploiting a vulnerability.
    #   None        The attacker is unauthenticated prior to attack, 
    #               and therefore does not require any access
    #
    #   Low         The attacker requires privileges that provide basic 
    #               capabilities that are typically limited to settings 
    #               and resources owned by a single low-privileged user.
    #
    #   High        The attacker requires privileges that provide 
    #               significant (e.g., administrative) control over the 
    #               vulnerable system allowing full access


    PR = BaseMetrics.PriviledgesRequired.LOW


    # User Interaction (UI) / BaseMetrics.UserInteraction
    # This metric captures the requirement of a non-attacker human user to access the vulnerability
    #   None        The vulnerable system can be exploited without 
    #               interaction from any human user, other than the 
    #               attacker
    #
    #   Passive     Successful exploitation of this vulnerability 
    #               requires limited interaction by the targeted user   
    #               with the vulnerable system and the attacker’s 
    #               payload
    #
    #   Active      Successful exploitation of this vulnerability 
    #               requires a targeted user to perform specific, 
    #               conscious interactions with the vulnerable system 
    #               and the attacker’s payload


    UI = BaseMetrics.UserInteraction.NONE


    # Impact Metrics
    # The Impact metrics capture the effects of a successfully 
    # exploited vulnerability. Analysts should constrain impacts to a 
    # reasonable, final outcome which they are confident an attacker is 
    # able to achieve.
    # 
    # For each impact metric, the metric is measured on a
    # Vulnerable System (V) and a Subsequent System (S).
    # The vulnerable system is the specfic area of software that 
    # contains the vulnerability. The subsequent system is everything 
    # outside of that area.


    # Confidentiality (VC/SC) BaseMetrics.Confidentiality
    # This measures the impact to the confidentiality of the information
    # if the vulnerability is exploited. Confidentiality refers to 
    # limiting information access and disclosure to only authorized 
    # users, as well as preventing access by, or disclosure to, 
    # unauthorized ones.
    # 
    # Impact to the Vulnerable System (VC) / .VulnerableSystem
    #   High        There is a total loss of confidentiality, resulting 
    #               in all information within the Vulnerable System 
    #               being divulged to the attacker.
    #
    #   Low         There is some loss of confidentiality. Access to 
    #               some restricted information is obtained, but the 
    #               attacker does not have control over what 
    #               information is obtained, or the amount or kind of 
    #               loss is limited.
    #
    #   None        There is no loss of confidentiality.
    
    VC = BaseMetrics.Confidentiality.VulnerableSystem.HIGH


    # Impact to the Subsequent System (SC) / .SubsequentSystem
    #   High        There is a total loss of confidentiality, resulting 
    #               in all resources within the Subsequent System being 
    #               divulged to the attacker.
    #
    #   Low         There is some loss of confidentiality. Access to 
    #               some restricted information is obtained, but the 
    #               attacker does not have control over what 
    #               information is obtained, or the amount or kind of 
    #               loss is limited.
    #
    #   None        There is no loss of confidentiality.


    SC = BaseMetrics.Confidentiality.SubsequentSystem.HIGH


    # Integrity (VI/SI) / BaseMetrics.Integrity
    # This metric measures the impact to integrity of a successfully 
    # exploited vulnerability. Integrity refers to the trustworthiness 
    # and veracity of information.
    # 
    # Impact to the Vulnerable System (VI) / .VulnerableSystem
    #   High        There is a total loss of integrity, or a complete 
    #               loss of protection.
    #
    #   Low         Modification of data is possible, but the attacker 
    #               does not have control over the consequence of a 
    #               modification, or the amount of modification is 
    #               limited.
    #
    #   None        There is no loss of integrity.
    
    VI = BaseMetrics.Integrity.VulnerableSystem.HIGH


    # Impact to the Subsequent System (SI) / .SubsequentSystem
    #   High        There is a total loss of integrity, or a complete 
    #               loss of protection.
    #
    #   Low         Modification of data is possible, but the attacker 
    #               does not have control over the consequence of a 
    #               modification, or the amount of modification is 
    #               limited.
    #
    #   None        There is no loss of integrity.


    SI = BaseMetrics.Integrity.SubsequentSystem.NONE


    # Availability (VA/SA) BaseMetrics.Availability
    # This metric measures the impact to the availability of the 
    # impacted system resulting from a successfully exploited 
    # vulnerability. While the Confidentiality and Integrity impact 
    # metrics apply to the loss of confidentiality or integrity of data 
    # (e.g., information, files) used by the system, this metric refers 
    # to the loss of availability of the impacted system itself, such 
    # as a networked service (e.g., web, database, email).
    #
    #  Impact to the Vulnerable System (VA) / .VulnerableSystem
    #   High        There is a total loss of availability, resulting in 
    #               the attacker being able to fully deny access to 
    #               resources
    #
    #   Low         Performance is reduced or there are interruptions 
    #               in resource availability. Even if repeated 
    #               exploitation of the vulnerability is possible, the 
    #               attacker does not have the ability to completely 
    #               deny service to legitimate users.
    #
    #   None        There is no impact to availability.
    
    VA = BaseMetrics.Availability.VulnerableSystem.NONE


    # Impact to the Subsequent System (SA) / .SubsequentSystem
    #   High        There is a total loss of availability, resulting in 
    #               the attacker being able to fully deny access to 
    #               resources
    #
    #   Low         Performance is reduced or there are interruptions   
    #               in resource availability. Even if repeated 
    #               exploitation of the vulnerability is possible, the 
    #               attacker does not have the ability to completely 
    #               deny service to legitimate users.
    #
    #   None        There is no impact to availability.


    SA = BaseMetrics.Availability.SubsequentSystem.NONE


    # Calculate CVSS 4.0 score
    cvss_score = calculate_cvss_v4_score(
        AV = AV, AC = AC, AT = AT, PR = PR, UI = UI, VC = VC, VI = VI, VA = VA, SC = SC, SI = SI, SA = SA
        )


    # This is calculated automatically
    # It has possible values of Low, Medium, High, Critical
    severity = get_cvss_severity(cvss_score)


    display_results(cvss_score=cvss_score, severity=severity)
    
    # This is required to be able to add the CVSS and Severity to the dashboard.
    save_cvss_result(request, cvss_score, severity)


@pytest.mark.parametrize("testString",sqlTestStrings)
@scenario('sql_injection.feature', 'SQL injection on <personNameSQLString> field of edit patient page')
@pytest_bdd.when(parsers.parse('the attacker tries to edit a patient {personNameSQLString} using a set of potential SQL strings'))
def test_sql_injection_on_edit_profile_page_parameterized(page:Page,testString,request,url_data,cleanupTestPatient,cleanupDatabase):
    #fill in field and update patient
    page.goto(url_data["edit_url"])
    scenarioString = request.getfixturevalue('_pytest_bdd_example')['personNameSQLString']
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.locator(sqlEditProfileNameLocations[scenarioString]).fill(testString)
    page.wait_for_timeout(DEFAULT_WAIT_TIME)
    page.get_by_text("Update patient").click()

@pytest.fixture(scope="function")
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
@pytest.fixture(scope="function")
def cleanupDatabase(cursor:MySQLCursor, connection:MySQLConnection):
    yield
    select_lockout_query = """
    DROP TABLE IF EXISTS testingTable;
    """
    
    cursor.execute(select_lockout_query)
    connection.commit()

@pytest_bdd.then('the database should not have a testing table made in it')
def the_database_should_not_have_a_testing_table_made_in_it(cursor:MySQLCursor, connection:MySQLConnection):
    
    select_lockout_query = """
    SHOW TABLES where Tables_in_openmrs = 'testingTable';
    """
    
    cursor.execute(select_lockout_query)
    queryResult = None
    try:
        queryResult = cursor.fetchone()['Tables_in_openmrs']
    except TypeError:
        pass

    if queryResult == "testingTable":
        assert False
    








