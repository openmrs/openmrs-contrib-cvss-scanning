Feature: Cryptographic Failures

  Background:
    Given a CVSS score is calculated and printed

  Scenario: The OpenMRS application should not use the default encryption key
    The current encrpytion key should not match the default key for the system.

    Given the default encrpytion key
    When the runtime properties are accessed
    And the encryption key is found
    Then the encryption key should not equal to the default key
  
  # Scenario: The OpenMRS application should not use the default encryption vector
  #   The current encrpytion vector should not match the default vector for the system.

  #   Given the default encrpytion vector is 9wyBUNglFCRVSUhMfsTa3Q==
  #   When the runtime properties are accessed
  #   And the encryption vector is found
  #   Then the encryption vector should not equal to the default vector