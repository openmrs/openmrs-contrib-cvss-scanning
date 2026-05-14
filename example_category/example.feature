# The Feature describes a vulnerability or test category
# that a user is testing. For example, XSS, SQL Injection, etc.
# In this way, it groups related scenarios, or related tests.
# Add the title of the feature next to the Feature tag,

# To run all scenarios in this feature file, use this command
# pytest tests/<folder>/ -v -s

# such as, "Feature: SQL Injection"
Feature:

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

  # A scenario is a specfic method to test against the vulnerability
  # Each scenario will be converted into its own test file in python
  Scenario:

    # ^^^ Put the description of the scenario above. This will become
    # the description on the dashboard

    # Given steps are used to describe the initial context of the
    # system. This will run before the test and sets up the system
    # to be in a known state. Such as, "Given I am logged in" 
    Given 

    # And and But steps are to specify multiple Given statements for
    # one Scenario statement. They can be used to make the statements
    # more readable. In the test file, they will be converted back
    # into Given statements.
    #And 
    #But 

    # When steps describe an event or action, likely done by an attacker
    # Such as, "When the attacker tries to ..."
    When 

    # Then steps should describe the expected
    # outcome or result of the above When statement.
    Then 

    # And and But steps are to specify multiple Then statements for
    # one When statement. They can be used to make the statements
    # more readable. In the test file, they will be converted back
    # into Then statements.
    #And 
    #But

    # For any shared given/when/then, use see the conftest.py example
    # to see how to utilize shared code.

  # More scenarios can be added. Each represents one method to test.
  #Scenario:

# For further explanation of Gherkin and Feature files,
# reference https://cucumber.io/docs/gherkin/reference/
# Keep in mind that some of the definitions in the
# comments have been modified to reflect testing purposes.