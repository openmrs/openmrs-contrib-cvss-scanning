Feature: Security Misconfiguration
  As a security auditor
  I want to check that the system does not have any misconfigured security features

  Background:
    Given a CVSS score is calculated and printed

  Scenario: Security header x-content-type-options is set to nosniff on login page
    Files are run using the content type because nosniff is set for the header x-content-type-options
    
    Given the login page response is returned
    When the security headers are checked
    Then the x-content-type-options should be present
    And the value of x-content-type-options is set to nosniff