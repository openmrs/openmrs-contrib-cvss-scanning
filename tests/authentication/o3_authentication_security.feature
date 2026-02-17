Feature: O3 Authentication Security Testing
  As a security auditor
  I want to test OpenMRS 3 against brute force authentication attacks on both frontend and API layers
  So that I can assess whether defenses are consistently applied across attack surfaces

  Background:
    Given the OpenMRS 3 login page is displayed

  # Test Case 1: Brute Force Password Attack (Frontend)
  # Attack: Known username "admin" + randomly generated passwords via login UI
  # Expected: Account lockout after 7 failed attempts, 5-minute cooldown
  # Testing:
  # 1. Whether brute force password vulnerability exists at the UI layer
  # 2. Whether account lockout works at the UI layer
  # 3. Whether 5-minute cooldown period works
  Scenario: Brute force password attack with known admin username
    When the attacker tries to login with known username "admin" and random passwords
    Then check after 7 incorrect attempts, the CVSS score for brute force password attack should be calculated
    And verify account lockout triggers after 7 failures
    And verify account becomes accessible after 5-minute cooldown period

  # Test Case 2: Brute Force Password Attack (API)
  # Attack: Known username "admin" + randomly generated passwords via REST API
  # Expected: Same lockout defenses should apply at the API layer
  # Testing:
  # 1. Whether brute force password vulnerability exists at the API layer
  # 2. Whether account lockout works at the API layer
  # 3. Whether API-layer defenses are consistent with UI-layer defenses
  Scenario: Brute force password attack via REST API with known admin username
    When the attacker sends 7 API login requests with known username "admin" and random passwords
    Then the CVSS score for brute force API password attack should be calculated
    And verify API account lockout triggers after 7 failures
    And verify API account becomes accessible after 5-minute cooldown period
