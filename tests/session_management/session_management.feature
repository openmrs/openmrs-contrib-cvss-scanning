Feature: Session Management
  As a security auditor
  I want to test OpenMRS 3 against various session management attacks

  Background:
    Given a CVSS score is calculated and printed
    Given the OpenMRS 3 home page is show after login

  Scenario: Cookies have Secure attribute
    Test whether cookies have the secure attribute enabled.

    When Cookies are accessed from the browser
    Then the cookies attribute secure should be True
  
  Scenario: Cookies have HTTPOnly attribute
    Test whether cookies have the HTTPOnly attribute enabled.

    When Cookies are accessed from the browser
    Then the cookies attribute httpOnly should be True

  Scenario: Cookies have SameSite attribute
    Test whether cookies have the SameSite attribute to Strict or Lax.

    When Cookies are accessed from the browser
    Then the cookies attribute sameSite should be Strict or Lax

  Scenario: Session cookie should change when logging out
    After a user logs out of a system, the cookie holding information
    about the login should expire and a new one should be created

    Given cookie information is saved
    And the user logs out of their account
    When the url is directed at /spa
    Then the cookies expire and new cookies with different IDs are generated
    And the login page should be shown

  Scenario: Session cookie hijacked
    After a user logs out of a system, the cookie holding information
    about the login is used to try and regain access

    Given cookie information is saved
    And the user logs out of their account
    When an attacker injects an old cookie
    And the url is directed at /spa
    Then the login page should be shown
  
  Scenario: Session cookie can be used by a valid user
    After leaving the page and coming back without logging out the cookie information grants access to the users account
    
    Given cookie information is saved
    And the user navigates to a different page
    When a valid cookie is injected
    And the url is directed at /spa
    Then the home page should be shown
