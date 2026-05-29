Feature: Memory Management Failures

  Background:
    Given a CVSS score is calculated and printed

  Scenario: Integer overflow of quantity on billing page
    On the quantity field of the billing page, a large integer should not cause an integer overflow or wraparound

    Given the login page is shown
    And the admin logs in
    And a new patient is created
    And the billings history page is shown
    And a bill is created
    When a quantity is inputted
    Then the quantity should not overflow or wraparound