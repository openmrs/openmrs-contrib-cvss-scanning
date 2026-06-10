Feature: Insecure Design

  Background:
    Given a CVSS score is calculated and printed

  Scenario Outline: Appointments should be blocked after reaching max load
    An appointment service should not allow a new appointment after going past the max number

    Given <numberOfPatients> test patients are created
    And the max appointment limit for services is set to <maxAppointments>
    When <numberOfPatients> appointment requests are made over the api
    Then <maxAppointments> out of <numberOfPatients> appointments should be successful

  Examples:
    | numberOfPatients | maxAppointments |
    | 3                | 2               |
    | 2                | 2               |