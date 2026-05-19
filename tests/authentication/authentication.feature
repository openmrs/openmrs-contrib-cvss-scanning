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

  Scenario: Lockout on login page is not accessible at 4 minutes and 50 seconds
    Tests whether an account is accessible after a 4 minute and 50 second waiting period

    Given the OpenMRS 3 login page is displayed
    And the login page is locked out from 7 failed login attempts
    When a user simulates waiting 4 minutes and 50 seconds for a lockout
    And a user logs in to the login page with the correct credentials
    Then the login page should block the correct credentials

  Scenario: Lockout on login page is accessible after 5 minutes
    Tests whether an account is accessible after a 5 minute waiting period

    Given the OpenMRS 3 login page is displayed
    And the login page is locked out from 7 failed login attempts
    When a user simulates waiting 5 minutes for a lockout
    And a user logs in to the login page with the correct credentials
    Then the location selection or home page should be shown

  Scenario: Lockout on REST API is not accessible at 4 minutes and 50 seconds
    Tests whether an account is accessible after a 4 minute and 50 second waiting period

    Given the REST API is locked out from 7 failed login attempts
    When a user simulates waiting 4 minutes and 50 seconds for a lockout
    And a user logs in to the REST API with the correct credentials
    Then the user should not be authenticated

  Scenario: Lockout on REST API is accessible after 5 minutes
    Tests whether an account is accessible after a 5 minute waiting period

    Given the REST API is locked out from 7 failed login attempts
    When a user simulates waiting 5 minutes for a lockout
    And a user logs in to the REST API with the correct credentials
    Then the user should be authenticated