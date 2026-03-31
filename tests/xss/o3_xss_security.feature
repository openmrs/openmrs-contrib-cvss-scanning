Feature: XSS
  As a security auditor
  I want to test OpenMRS 3 against various XSS injection attacks
  So that I can assess injection vulnerabilities and blocking mechanisms
  
  Background:
    Given a CVSS score is calculated and printed
    Given logged into OpenMRS O3
    Given a test patient has been created
    Given the OpenMRS 3 edit patient page is displayed

  Scenario Outline: XSS injection on <scenarioString> field of edit patient page, parameterized
    A parameterized test to try several potential XSS injection strings on the <scenarioString> field of the edit patient page.
      When the attacker tries to edit a patient <scenarioString> using a set of potential XSS strings
      Then see if XSS injection was successful
      
  Examples:
    | scenarioString |
    | first name     |
    | middle name    |
    | family name    |
    | address 1      |
    | address 2      |
    | city           |
    | state          |
    | country        |
    | postal code    |
    | phone number   |