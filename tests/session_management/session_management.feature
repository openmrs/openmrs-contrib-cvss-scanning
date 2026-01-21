Feature: Session Management Testing
    As a security auditor
    I want to test OpenMRS 3 against various session management attacks

    Background:
    Given the OpenMRS 3 home page is show after login

    Scenario: Session ID use on a different IP Address
        When the attacker steals the session ID and tries to use it from a different IP address
        Then the session should be denied access
    
    Scenario: Session expiration on time
        When the user stays idle
        Then the session should be checked if it is idle after every five minutes
    
    Scenario: Cannot resuse expired session
        When a user's session had expired and is resused
        Then the session should be denied