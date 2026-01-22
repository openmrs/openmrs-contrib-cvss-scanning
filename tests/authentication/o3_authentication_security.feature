Feature: O3 Authentication Security Testing
  As a security auditor
  I want to test OpenMRS 3 against various brute force authentication attacks
  So that I can assess authentication vulnerabilities and blocking mechanisms
  
  Background:
    Given the OpenMRS 3 login page is displayed

  Scenario: Username enumeration with wrong usernames
    When the attacker tries to login with invalid "username" and valid password
    Then check after 10 incorrect attempts, the CVSS score for username enumeration attack should be calculated

  Scenario: Complete credential guessing with wrong username and password
    When the attacker tries to login with invalid "username" and invalid "password"
    Then check after 10 incorrect attempts, the CVSS score for credential guessing attack should be calculated

  Scenario: Password attack with 6 wrong password attempts
    When the attacker tries to login with valid username and invalid "password"
    Then check after 6 incorrect attempts, the CVSS score for password attack should be calculated

  Scenario: Password attack with 7 wrong password attempts
    When the attacker tries to login with valid username and invalid "password"
    Then check after 7 incorrect attempts, the CVSS score for password attack should be calculated

  Scenario: Password attack with 8 wrong password attempts
    When the attacker tries to login with valid username and invalid "password"
    Then check after 8 incorrect attempts, the CVSS score for password attack should be calculated
