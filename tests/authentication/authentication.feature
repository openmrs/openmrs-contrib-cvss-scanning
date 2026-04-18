Feature: Authentication
  As a security auditor
  I want to test OpenMRS 3 against brute force authentication attacks on both frontend and API layers
  So that I can assess whether defenses are consistently applied across attack surfaces

  Background:
    Given a CVSS score is calculated and printed

  Scenario: Brute force password attack with known admin username
    Tests whether an attacker can login to the login page using a known username and random passwords.

    Given the OpenMRS 3 login page is displayed
    When the attacker tries to login with known username admin and random passwords
    Then the login page should be displayed

  Scenario: Brute force password attack via REST API with known admin username
    Tests whether an attacker can login accross the API using a known username and random passwords.

    When the attacker sends 7 API login requests with known username admin and random passwords
    Then the user should not be authenticated
  
  Scenario: Brute force attack on login page causes lockout
    Tests whether the system will lockout an attacker from a brute force attack.

    Given the OpenMRS 3 login page is displayed
    When an attacker fails 7 login attempts on the login page
    Then the login page should block the correct credentials

  Scenario: Brute force attack on REST API causes lockout
    Tests whether the system will lockout an attacker from a brute force attack.

    When an attacker fails 7 login attempts through the REST API
    Then the REST API should block the correct credentials

  Scenario: Lockout on login page is accessible after 5 minutes
    Tests whether an account is accessible after a 5 minute waiting period
    and if the attacker has locked out the user from using their account

    Given the OpenMRS 3 login page is displayed
    Given the login page is locked out from 7 failed login attempts
    When a user waits 5 minutes
    And a user logs in to the login page with the correct credentials
    Then the correct credentials should log into the login page

  Scenario: Lockout on REST API is accessible after 5 minutes
    Tests whether an account is accessible after a 5 minute waiting period
    and if the attacker has locked out the user from using their account

    Given the REST API is locked out from 7 failed login attempts
    When a user waits 5 minutes
    And a user logs in to the REST API with the correct credentials
    Then the correct credentials should log into the REST API