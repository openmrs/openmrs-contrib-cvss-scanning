Feature: Security Misconfiguration
  As a security auditor
  I want to check that the system does not have any misconfigured security features

  Background:
    Given a CVSS score is calculated and printed
    Given the login page response is returned
    When the security headers are checked

  Scenario: Security header x-content-type-options is set to nosniff on login page
    Files are run using the content type because nosniff is set for the header x-content-type-options
    
    Then the x-content-type-options should be present
    And the value of x-content-type-options is set to nosniff
  
  Scenario Outline: Security header attribute <attribute> should not be used for default-src directive on login page
    The content-security-policy header should not have unsafe- attributes for the default-src directive

    Then the content-security-policy should be present
    And <attribute> should not be present in default-src

    Examples:
      | attribute       |
      | 'unsafe-eval'   |
      | 'unsafe-inline' |
      | 'unsafe-hash'   |
  
  Scenario Outline: Security header directive <directive> should be set to 'none' or 'self' on login page
    Directives should be set to 'none' or 'self' on login page if it exists and does not fall back to default-src

    Then the content-security-policy should be present
    And <directive> should be set to 'none' or 'self' if it exists or <fallback> to default-src

    Examples:
      | directive       | fallback |
      | default-src     | True     |
      | script-src      | True     |
      | style-src       | True     |
      | connect-src     | True     |
      | media-src       | True     |
      | object-src      | True     |
      | frame-src       | True     |
      | worker-src      | True     |
      | manifest-src    | True     |
      | child-src       | True     |
      | font-src        | True     |
      | frame-ancestors | False    |
      | form-action     | False    |
      | base-uri        | False    |

  Scenario Outline: Security header directive <directive> should not be set to * or http: on login page
      Directives should not be set to * or http: on login page if it exists and falls back to default-src

      Then the content-security-policy should be present
      And <directive> should not be set to * or http: if it exists and <fallback> to default-src
    
        Examples:
          | directive       | fallback |
          | default-src     | True     |
          | script-src      | True     |
          | style-src       | True     |
          | connect-src     | True     |
          | media-src       | True     |
          | object-src      | True     |
          | frame-src       | True     |
          | worker-src      | True     |
          | manifest-src    | True     |
          | child-src       | True     |
          | font-src        | True     |
          | frame-ancestors | False    |
          | form-action     | False    |
          | base-uri        | False    |

Scenario: Content Security Policy should not allow unsafe-eval
    Given a CVSS score is calculated and printed
    Given the login page response is returned
    When the security headers are checked
    Then the Content-Security-Policy header should not contain unsafe-eval

  Scenario: Content Security Policy should not allow unsafe-inline scripts
    Given a CVSS score is calculated and printed
    Given the login page response is returned
    When the security headers are checked
    Then the Content-Security-Policy header should not contain unsafe-inline for scripts

  Scenario: Content Security Policy should have form-action directive
    Given a CVSS score is calculated and printed
    Given the login page response is returned
    When the security headers are checked
    Then the Content-Security-Policy header should contain a form-action directive