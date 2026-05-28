Feature: Security Logging & Alerting Failures

  Background:
    Given a CVSS score is calculated and printed

  Scenario: Server logs should show failed login attempts
    A failed login attempt with an incorrect username or password should be shown in the logs

    Given the current time is saved
    When a user attempts to login with the wrong username or password
    And an admin logs in on the login page
    And visits the server logs page
    Then a failed login attempt log should exist after the saved timestamp