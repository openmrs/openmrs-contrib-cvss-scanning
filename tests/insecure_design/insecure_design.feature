Feature: Insecure Design

  Background:
    Given a CVSS score is calculated and printed

  Scenario: Appointments should be blocked after reaching max load
    An appointment service should not allow a new appointment after going past the max number

    Given 3 test patients are created
    And the max appoitment limit for General Medicine services is set to 2
    When 3 appointment requests are made over the api
    Then 2 out of 3 appointments should be successful