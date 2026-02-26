Feature: O3 XSS Security Testing  
  As a security auditor
  I want to test OpenMRS 3 against various XSS injection attacks
  So that I can assess injection vulnerabilities and blocking mechanisms
  
  Background:
    Given logged into OpenMRS O3
    Given a test patient has been created
    Given the OpenMRS 3 edit patient page is displayed

  Scenario: XSS injection edit profile parameterized
    When the attacker tries to edit a patient middle name using a set of potential XSS strings and an alert was found after any string
    Then calculate CVSS score and report failure. 
  #Scenario: XSS injection on patient edit page, middle name field
    #When the attacker tries to edit a patient middle name using a set of potential XSS strings and an alert was found after any string
    #Then calculate CVSS score and report failure. 
  #Scenario: XSS injection on patient edit page, first name field
    #When the attacker tries to edit a patient first name using a set of potential XSS strings and an alert was found after any string
    #Then calculate CVSS score and report failure. 
  #Scenario: XSS injection on patient edit page, family name field
    #When the attacker tries to edit a patient family name using a set of potential XSS strings and an alert was found after any string
    #Then calculate CVSS score and report failure.  