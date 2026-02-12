Feature: O3 Authentication Security Testing
  As a security auditor
  I want to test OpenMRS 3 against various brute force authentication attacks
  So that I can assess authentication vulnerabilities and blocking mechanisms
  
  Background:
    Given the OpenMRS 3 login page is displayed

# Test Case 1: Brute Force Password Attack
# Attack: known username admin + randomly generated passwords
# Expected: Account lockout after 7 failed attempts, 5 mins cooldown before having access to attempt login again
# Testing: 
# 1. if brute force password attack vulnerability exist
# 2. if account lockout works
# 3. if 5 mins cooldown period works
  Scenario: Brute force password attack with known admin username
    When the attacker tries to login with known username "admin" and random passwords
    Then check after 7 incorrect attempts, the CVSS score for brute force password attack should be calculated
    And verify account lockout triggers after 7 failures
    And verify account becomes accessible after 5-minute cooldown period

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
