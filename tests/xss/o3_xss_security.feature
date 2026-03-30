Feature: XSS
  As a security auditor
  I want to test OpenMRS 3 against various XSS injection attacks
  So that I can assess injection vulnerabilities and blocking mechanisms
  
  Background:
    Given a CVSS score is calculated and printed
    Given logged into OpenMRS O3
    Given a test patient has been created
    Given the OpenMRS 3 edit patient page is displayed
    
  Scenario: XSS injection on edit profile page, parameterized
    A parameterized test to try several potential XSS injection strings on each field of the edit profile page.
    When the attacker tries to edit a patient middle name using a set of potential XSS strings
    Then see if XSS injection was successful
    Then cleanup the test patient and potentially report failure