Feature: O3 XSS Security Testing  
  As a security auditor
  I want to test OpenMRS 3 against various XSS injection attacks
  So that I can assess injection vulnerabilities and blocking mechanisms
  
  Background:
    Given A CVSS is calculated and logged
    Given logged into OpenMRS O3
    Given a test patient has been created
    Given the OpenMRS 3 edit patient page is displayed
    
  Scenario: XSS injection edit profile parameterized
    When the attacker tries to edit a patient middle name using a set of potential XSS strings
    Then see if XSS injection was successful
    Then cleanup the test patient and potentially report failure
