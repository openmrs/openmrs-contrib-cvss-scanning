import pytest_bdd

from tests.utils import calculate_cvss_v4_score, get_cvss_severity, display_results, BaseMetrics, O3_BASE_URL
from tests.conftest import save_cvss_result
from tests.authentication.conftest import random_password, login

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


    PR = BaseMetrics.PriviledgesRequired.NONE


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


    SC = BaseMetrics.Confidentiality.SubsequentSystem.NONE


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
    
    VA = BaseMetrics.Availability.VulnerableSystem.HIGH


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

@pytest_bdd.scenario('authentication.feature', 'Brute force password attack with known admin username')
def test_brute_force_password_attack_with_known_admin_username():
 pass

@pytest_bdd.when('the attacker tries to login with known username admin and random passwords')
def when_the_attacker_tries_to_login_with_known_username_admin_and_random_passwords(new_page):
    # This function represents what will happen during the When step of the scenario.
    
    # OpenMRS password requirements
    # Minimum 8 characters
    # Must contain upper and lower case letters
    # Must contain at least 1 number

    passwords = []

    for _ in range(0,7):
        passwords.append(random_password())
        
    for password in passwords:
        print("Trying...", password)
                
        # try passwords
        login(new_page, "admin", password)
        new_page.wait_for_timeout(1000)
            
        # if on page /login/location
        if (new_page.url != (O3_BASE_URL + '/login')):
            # password worked
            break

@pytest_bdd.then('the login page should be displayed')
def then_the_login_page_should_be_displayed(new_page):
    assert new_page.url == O3_BASE_URL + '/login'

#cleanup step