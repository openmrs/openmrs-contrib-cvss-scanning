# The Feature describes a vulnerability or test category
# that a user is testing. For example, XSS, SQL Injection, etc.
# In this way, it groups related scenarios, or related tests.
# Add the title of the feature next to the Feature tag,
# such as, "Feature: SQL Injection"
Feature: Session Management
  As a security auditor
  I want to test OpenMRS 3 against various session management attacks
  # Text can be add here for a description of the feature

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
    Given the OpenMRS 3 home page is show after login

  # A scenario is a specfic method to test against the vulnerability
  # Each scenario will be converted into its own test file in python
  Scenario: Cookies have Secure attribute
    Test whether cookies have the secure attribute enabled.

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When Cookies are accessed from the browser

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then the cookies attribute secure should be True
  
  Scenario: Cookies have HTTPOnly attribute
    Test whether cookies have the HTTPOnly attribute enabled.

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When Cookies are accessed from the browser

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then the cookies attribute httpOnly should be True

  Scenario: Cookies have SameSite attribute
    Test whether cookies have the SameSite attribute to Strict or Lax.

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When Cookies are accessed from the browser

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then the cookies attribute sameSite should be Strict or Lax

  Scenario: Session cookie should change when logging out
    After a user logs out of a system, the cookie holding information
    about the login should expire and a new one should be created

    Given cookie information is saved
    And the user logs out of their account

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When the url is directed at /spa

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then the cookies expire and new cookies with different IDs are generated
    And the login page should be shown

  Scenario: Session cookie hijacked
    After a user logs out of a system, the cookie holding information
    about the login is used to try and regain access

    Given cookie information is saved
    And the user logs out of their account

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When an attacker injects an old cookie
    And the url is directed at /spa

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then the login page should be shown

# For further explanation of Gherkin and Feature files,
# reference https://cucumber.io/docs/gherkin/reference/
# Keep in mind that some of the definitions in the
# comments have been modified to reflect testing purposes.