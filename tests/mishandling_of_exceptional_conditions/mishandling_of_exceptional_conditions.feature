Feature: Mishandling of Exceptional Conditions

  Background:
    Given a CVSS score is calculated and printed

  Scenario: Web server version name and number should not be shown on 404 page
    Apache Tomcat version number should not be shown when the default HTTP 404 Error page is shown

    Given the attacker visits the page /openmrs/doesnotexist
    And the HTTP status 404 error page is shown
    When the attacker looks for the version number
    Then the version number will not be shown