Feature: O3 XSS Security Testing  
  As a security auditor
  I want to test OpenMRS 3 against various XSS injection attacks
  So that I can assess injection vulnerabilities and blocking mechanisms
  
  Background:
    Given the OpenMRS 3 edit patient page is displayed

  Scenario: XSS injection on patient edit page
    When the attacker tries to edit a patient middle name to make an alert when perform XSS
    Then check if an alert was made, if so, calculate CVSS score. 
    
