Feature: SQL Injection
  As a security auditor
  I want to test OpenMRS 3 against various SQL injection attacks
  So that I can assess injection vulnerabilities and blocking mechanisms

  Scenario Outline: SQL injection on <personNameSQLString> field of edit patient page
    A parameterized test to try several potential SQL injection strings that target the person_name table of the OpenMRS O3 data model.
      Given a CVSS score is calculated and printed
      Given logged into OpenMRS O3
      Given a test patient has been created
      Given the OpenMRS 3 edit patient page is displayed
      When the attacker tries to edit a patient <personNameSQLString> using a set of potential SQL strings
      Then the database should not have a testing table made in it
      #If the potential injection string isn't present, then that would indicate the input successfully injected SQL somehow
      
  Examples:
    | personNameSQLString |
    | first name     |
    | middle name    |
    | family name    |
