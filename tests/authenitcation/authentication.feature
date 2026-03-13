# The Feature describes a vulnerability or test category
# that a user is testing. For example, XSS, SQL Injection, etc.
# In this way, it groups related scenarios, or related tests.
# Add the title of the feature next to the Feature tag,

# To run all scenarios in this feature file, use this command
# pytest tests/<folder>/ -v -s

# such as, "Feature: SQL Injection"
Feature: Authentication
  As a security auditor
  I want to test OpenMRS 3 against brute force authentication attacks on both frontend and API layers
  So that I can assess whether defenses are consistently applied across attack surfaces

  # Background holds any amount of Given steps to run before
  # each scenario. These should be used to consolidate shared behavior
  Background:
    # Given steps are used to describe the initial context of the
    # system. This will run before the test and sets up the system
    # to be in a known state. Such as, "Given I am logged in"
    # When written in the background, the Given will run before
    # each scenario.

    # Each scenario should calculate and print a CVSS score.
    # Becuase it is a static value, it can be done before anything else
    Given a CVSS score is calculated and printed
    Given the OpenMRS 3 login page is displayed

  # A scenario is a specfic method to test against the vulnerability
  # Each scenario will be converted into its own test file in python
  Scenario: Brute force password attack with known admin username
    Tests account lockout and cooldown after 7 failed login attempts with known username "admin". Uses CVSS 4.0 with dynamic scoring based on observed security mechanisms.
    # ^^^ Put the description of the scenario above. This will become
    # the description on the dashboard

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When the attacker tries to login with known username admin and random passwords

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then check after 7 incorrect attempts
    And verify account lockout triggers after 7 failures
    And verify account becomes accessible after 5-minute cooldown period

  Scenario: Brute force password attack via REST API with known admin username
    Tests account lockout and cooldown after 7 failed API login attempts with known
    username "admin". Uses CVSS 4.0 with dynamic scoring based on observed API-layer
    security mechanisms. Compares defense consistency with frontend brute force test.
    # ^^^ Put the description of the scenario above. This will become
    # the description on the dashboard

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When the attacker sends 7 API login requests with known username admin and random passwords

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then check after 7 incorrect attempts
    And verify API account lockout triggers after 7 failures
    And verify API account becomes accessible after 5-minute cooldown period

# For further explanation of Gherkin and Feature files,
# reference https://cucumber.io/docs/gherkin/reference/
# Keep in mind that some of the definitions in the
# comments have been modified to reflect testing purposes.